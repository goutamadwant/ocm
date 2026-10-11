use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::SupervisorChildSpec;
#[cfg(test)]
use crate::infra::shell::OPENCLAW_NATIVE_SERVICE_IDENTITY_KEYS;
use crate::infra::shell::{
    apply_external_supervision_protocol_v1, apply_legacy_supervision, quote_posix,
};

const PROTOCOL: &str = "openclaw.gateway.restart-handoff";
const PROTOCOL_VERSION: u8 = 1;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RestartHandoffSupport {
    ProtocolV1,
    Unsupported(String),
}

impl RestartHandoffSupport {
    pub(super) fn status_label(&self) -> &'static str {
        match self {
            Self::ProtocolV1 => "protocol-v1",
            Self::Unsupported(_) => "legacy",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RestartHandoffConsumeResult {
    Accepted,
    NotAccepted(String),
    Unsupported(String),
    Failed(String),
    NotChecked,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesResponse {
    ok: bool,
    protocol: String,
    protocol_version: u8,
    operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsumeResponse {
    ok: bool,
    protocol: String,
    protocol_version: u8,
    status: String,
    reason: Option<String>,
    handoff: Option<ConsumedHandoff>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsumedHandoff {
    pid: u64,
    supervisor_mode: String,
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

enum ChildCompletion {
    #[cfg(unix)]
    ExitedUnreaped,
    #[cfg(not(unix))]
    Reaped(ExitStatus),
}

struct CommandProcessGuard {
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

pub(super) fn probe_restart_handoff_support(spec: &SupervisorChildSpec) -> RestartHandoffSupport {
    if !spec.restart_handoff_pid_bound {
        return RestartHandoffSupport::Unsupported(
            "resolved command does not preserve the supervised gateway PID".to_string(),
        );
    }
    let probe_spec = prepare_supervisor_child_spec(
        spec,
        &RestartHandoffSupport::Unsupported("capability probe pending".to_string()),
    );
    let output = match run_openclaw_machine_command(
        &probe_spec,
        &["gateway", "restart-handoff", "capabilities", "--json"],
    ) {
        Ok(output) => output,
        Err(error) => return RestartHandoffSupport::Unsupported(error),
    };
    if !output.status.success() {
        return RestartHandoffSupport::Unsupported(command_failure_detail(output.status));
    }
    let response = match serde_json::from_slice::<CapabilitiesResponse>(&output.stdout) {
        Ok(response) => response,
        Err(error) => {
            return RestartHandoffSupport::Unsupported(format!(
                "invalid capability response: {error}"
            ));
        }
    };
    if response.ok
        && response.protocol == PROTOCOL
        && response.protocol_version == PROTOCOL_VERSION
        && response
            .operations
            .iter()
            .any(|operation| operation == "consume")
    {
        RestartHandoffSupport::ProtocolV1
    } else {
        RestartHandoffSupport::Unsupported(
            "runtime does not advertise restart-handoff protocol version 1 consume".to_string(),
        )
    }
}

pub(super) fn prepare_supervisor_child_spec(
    spec: &SupervisorChildSpec,
    support: &RestartHandoffSupport,
) -> SupervisorChildSpec {
    let mut prepared = spec.clone();
    match support {
        RestartHandoffSupport::ProtocolV1 => {
            apply_external_supervision_protocol_v1(&mut prepared.process_env);
        }
        RestartHandoffSupport::Unsupported(_) => {
            apply_legacy_supervision(&mut prepared.process_env);
        }
    }
    prepared
}

pub(super) fn consume_restart_handoff(
    spec: &SupervisorChildSpec,
    support: &RestartHandoffSupport,
    expected_pid: u32,
) -> RestartHandoffConsumeResult {
    if let RestartHandoffSupport::Unsupported(reason) = support {
        return RestartHandoffConsumeResult::Unsupported(reason.clone());
    }
    let prepared = prepare_supervisor_child_spec(spec, support);
    let expected_pid_arg = expected_pid.to_string();
    let output = match run_openclaw_machine_command(
        &prepared,
        &[
            "gateway",
            "restart-handoff",
            "consume",
            "--expected-pid",
            &expected_pid_arg,
            "--json",
        ],
    ) {
        Ok(output) => output,
        Err(error) => return RestartHandoffConsumeResult::Failed(error),
    };
    if !output.status.success() {
        return RestartHandoffConsumeResult::Failed(command_failure_detail(output.status));
    }
    let response = match serde_json::from_slice::<ConsumeResponse>(&output.stdout) {
        Ok(response) => response,
        Err(error) => {
            return RestartHandoffConsumeResult::Failed(format!(
                "invalid consume response: {error}"
            ));
        }
    };
    if !response.ok
        || response.protocol != PROTOCOL
        || response.protocol_version != PROTOCOL_VERSION
    {
        return RestartHandoffConsumeResult::Failed(
            "consume response does not match restart-handoff protocol version 1".to_string(),
        );
    }
    match response.status.as_str() {
        "accepted" => match response.handoff {
            Some(handoff)
                if handoff.pid == u64::from(expected_pid)
                    && handoff.supervisor_mode == "external" =>
            {
                RestartHandoffConsumeResult::Accepted
            }
            _ => RestartHandoffConsumeResult::Failed(
                "accepted consume response does not match the exited external gateway".to_string(),
            ),
        },
        "none" | "rejected" => RestartHandoffConsumeResult::NotAccepted(
            response
                .reason
                .unwrap_or_else(|| response.status.to_string()),
        ),
        status => RestartHandoffConsumeResult::Failed(format!(
            "unknown consume response status \"{status}\""
        )),
    }
}

fn run_openclaw_machine_command(
    spec: &SupervisorChildSpec,
    openclaw_args: &[&str],
) -> Result<CommandOutput, String> {
    run_openclaw_machine_command_with_timeout(spec, openclaw_args, COMMAND_TIMEOUT)
}

fn run_openclaw_machine_command_with_timeout(
    spec: &SupervisorChildSpec,
    openclaw_args: &[&str],
    timeout: Duration,
) -> Result<CommandOutput, String> {
    let started_at = Instant::now();
    let deadline = started_at + timeout;
    let program_arguments = openclaw_program_arguments(spec, openclaw_args)?;
    let program = program_arguments
        .first()
        .ok_or_else(|| "restart-handoff command is missing a program".to_string())?;
    let mut command = Command::new(program);
    command
        .args(program_arguments.iter().skip(1))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(&spec.process_env)
        .current_dir(Path::new(&spec.run_dir));
    let process_guard = CommandProcessGuard::new()?;
    process_guard.configure_command(&mut command);
    let mut child = command.spawn().map_err(|error| {
        format!(
            "failed running restart-handoff command for env \"{}\": {error}",
            spec.env_name
        )
    })?;
    if let Err(error) = process_guard.assign_and_start(&mut child) {
        let _ = process_guard.terminate(&mut child);
        return Err(error);
    }
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(error_with_cleanup(
                "restart-handoff command stdout was not captured".to_string(),
                process_guard.terminate(&mut child),
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return Err(error_with_cleanup(
                "restart-handoff command stderr was not captured".to_string(),
                process_guard.terminate(&mut child),
            ));
        }
    };
    #[cfg(unix)]
    if let Err(error) = set_nonblocking(&stdout).and_then(|_| set_nonblocking(&stderr)) {
        return Err(error_with_cleanup(
            format!("failed configuring restart-handoff output capture: {error}"),
            process_guard.terminate(&mut child),
        ));
    }
    let stdout_reader = spawn_output_reader(stdout, deadline);
    let stderr_reader = spawn_output_reader(stderr, deadline);

    let completion = match wait_for_child(&mut child, deadline, timeout) {
        Ok(completion) => completion,
        Err(error) => {
            return Err(command_error_after_cleanup(
                error,
                &process_guard,
                &mut child,
                &stdout_reader,
                &stderr_reader,
                false,
            ));
        }
    };
    let stdout = match receive_output(&stdout_reader, deadline, "stdout") {
        Ok(stdout) => stdout,
        Err(error) => {
            return Err(command_error_after_cleanup(
                error,
                &process_guard,
                &mut child,
                &stdout_reader,
                &stderr_reader,
                false,
            ));
        }
    };
    if let Err(error) = receive_output(&stderr_reader, deadline, "stderr") {
        return Err(command_error_after_cleanup(
            error,
            &process_guard,
            &mut child,
            &stdout_reader,
            &stderr_reader,
            true,
        ));
    }
    let status = finish_child_wait(&mut child, completion)?;
    Ok(CommandOutput { status, stdout })
}

impl CommandProcessGuard {
    fn new() -> Result<Self, String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };

            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(format!(
                    "failed creating restart-handoff process job: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&info).cast(),
                    std::mem::size_of_val(&info) as u32,
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(job);
                }
                return Err(format!(
                    "failed configuring restart-handoff process job: {error}"
                ));
            }
            Ok(Self { job })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }

    fn configure_command(&self, command: &mut Command) {
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(windows)]
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
        #[cfg(not(any(unix, windows)))]
        let _ = command;
    }

    fn assign_and_start(&self, child: &mut Child) -> Result<(), String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

            if unsafe {
                AssignProcessToJobObject(
                    self.job,
                    child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                let _ = child.kill();
                let _ = reap_child_until(child, Instant::now() + CLEANUP_TIMEOUT);
                return Err(format!(
                    "failed assigning restart-handoff command to process job: {error}"
                ));
            }
            resume_windows_process(child.id())?;
        }
        #[cfg(not(windows))]
        let _ = child;
        Ok(())
    }

    fn terminate(&self, child: &mut Child) -> Result<(), String> {
        #[cfg(unix)]
        {
            let process_group = child.id() as libc::pid_t;
            let mut failures = Vec::new();
            if let Err(error) = signal_process_group(process_group, libc::SIGTERM) {
                failures.push(error);
            }
            thread::sleep(CLEANUP_TIMEOUT / 2);
            if let Err(error) = signal_process_group(process_group, libc::SIGKILL) {
                failures.push(error);
            }
            let _ = child.kill();
            match reap_child_until(child, Instant::now() + CLEANUP_TIMEOUT / 2) {
                Ok(true) => {}
                Ok(false) => failures.push(
                    "restart-handoff command cleanup did not settle before its deadline"
                        .to_string(),
                ),
                Err(error) => failures.push(error),
            }
            match wait_for_process_group_exit(process_group, CLEANUP_TIMEOUT / 2) {
                Ok(true) => {}
                Ok(false) => failures
                    .push("restart-handoff descendant cleanup could not be verified".to_string()),
                Err(error) => failures.push(error),
            }
            return if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            };
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::TerminateJobObject;

            if unsafe { TerminateJobObject(self.job, 1) } == 0 {
                let error = std::io::Error::last_os_error();
                let _ = child.kill();
                let _ = reap_child_until(child, Instant::now() + CLEANUP_TIMEOUT);
                return Err(format!(
                    "restart-handoff descendant cleanup could not be verified: {error}"
                ));
            }
            return match reap_child_until(child, Instant::now() + CLEANUP_TIMEOUT) {
                Ok(true) => Ok(()),
                Ok(false) => Err(
                    "restart-handoff command cleanup did not settle before its deadline"
                        .to_string(),
                ),
                Err(error) => Err(error),
            };
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child.kill();
            let _ = reap_child_until(child, Instant::now() + CLEANUP_TIMEOUT);
            Err("restart-handoff descendant cleanup could not be verified".to_string())
        }
    }
}

#[cfg(windows)]
impl Drop for CommandProcessGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

fn spawn_output_reader<R: Read + Send + 'static>(
    reader: R,
    deadline: Instant,
) -> Receiver<std::io::Result<Vec<u8>>> {
    #[cfg(not(unix))]
    let _ = deadline;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        #[cfg(unix)]
        let result = read_bounded_until(reader, deadline);
        #[cfg(not(unix))]
        let result = read_bounded(reader);
        let _ = sender.send(result);
    });
    receiver
}

#[cfg(unix)]
fn set_nonblocking(reader: &impl AsRawFd) -> std::io::Result<()> {
    let descriptor = reader.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn receive_output(
    reader: &Receiver<std::io::Result<Vec<u8>>>,
    deadline: Instant,
    stream: &str,
) -> Result<Vec<u8>, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match reader.recv_timeout(remaining) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(format!("failed reading restart-handoff {stream}: {error}")),
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "restart-handoff command output did not settle before its operation deadline ({stream} still open)"
        )),
        Err(RecvTimeoutError::Disconnected) => Err(format!(
            "restart-handoff {stream} reader stopped unexpectedly"
        )),
    }
}

fn command_error_after_cleanup(
    error: String,
    process_guard: &CommandProcessGuard,
    child: &mut Child,
    stdout_reader: &Receiver<std::io::Result<Vec<u8>>>,
    stderr_reader: &Receiver<std::io::Result<Vec<u8>>>,
    stdout_already_settled: bool,
) -> String {
    let cleanup = process_guard.terminate(child);
    let settle_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let stdout_settled =
        stdout_already_settled || receive_output(stdout_reader, settle_deadline, "stdout").is_ok();
    let stderr_settled = receive_output(stderr_reader, settle_deadline, "stderr").is_ok();
    match (cleanup, stdout_settled && stderr_settled) {
        (Ok(()), true) => format!("{error}; owned process cleanup completed"),
        (Ok(()), false) => {
            format!(
                "{error}; owned process cleanup completed but detached output ownership remained unresolved"
            )
        }
        (Err(cleanup_error), _) => format!("{error}; {cleanup_error}"),
    }
}

fn error_with_cleanup(error: String, cleanup: Result<(), String>) -> String {
    match cleanup {
        Ok(()) => format!("{error}; owned process cleanup completed"),
        Err(cleanup_error) => format!("{error}; {cleanup_error}"),
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) -> Result<(), String> {
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(format!(
        "failed signaling restart-handoff process group {process_group}: {error}"
    ))
}

#[cfg(unix)]
fn process_group_exists(process_group: libc::pid_t) -> Result<bool, String> {
    if unsafe { libc::kill(-process_group, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(format!(
        "failed checking restart-handoff process group {process_group}: {error}"
    ))
}

#[cfg(unix)]
fn wait_for_process_group_exit(
    process_group: libc::pid_t,
    timeout: Duration,
) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_exists(process_group)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(windows)]
fn resume_windows_process(pid: u32) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return Err(format!(
            "failed listing suspended restart-handoff threads: {error}"
        ));
    }
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut found = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    let mut resume_result = None;
    while found {
        if entry.th32OwnerProcessID == pid {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                resume_result = Some(Err(format!(
                    "failed opening suspended restart-handoff thread: {}",
                    std::io::Error::last_os_error()
                )));
            } else {
                let previous_count = unsafe { ResumeThread(thread) };
                let resume_error = (previous_count == u32::MAX).then(std::io::Error::last_os_error);
                unsafe {
                    CloseHandle(thread);
                }
                resume_result = Some(match (previous_count, resume_error) {
                    (1, _) => Ok(()),
                    (u32::MAX, Some(error)) => Err(format!(
                        "failed resuming suspended restart-handoff process {pid}: {error}"
                    )),
                    (count, _) => Err(format!(
                        "restart-handoff process {pid} remained suspended after resume (previous count {count})"
                    )),
                });
            }
            break;
        }
        found = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    resume_result.unwrap_or_else(|| {
        Err(format!(
            "failed finding suspended restart-handoff process thread for {pid}"
        ))
    })
}

fn openclaw_program_arguments(
    spec: &SupervisorChildSpec,
    openclaw_args: &[&str],
) -> Result<Vec<String>, String> {
    let gateway_args = [
        "gateway".to_string(),
        "run".to_string(),
        "--port".to_string(),
        spec.child_port.to_string(),
    ];
    if let Some(binary_path) = spec.binary_path.as_ref() {
        let prefix_len = spec
            .args
            .len()
            .checked_sub(gateway_args.len())
            .ok_or_else(|| {
                format!(
                    "service child env \"{}\" has incomplete gateway arguments",
                    spec.env_name
                )
            })?;
        if spec.args[prefix_len..] != gateway_args {
            return Err(format!(
                "service child env \"{}\" gateway arguments do not match its port",
                spec.env_name
            ));
        }
        let mut program_arguments = vec![binary_path.clone()];
        program_arguments.extend(spec.args[..prefix_len].iter().cloned());
        program_arguments.extend(openclaw_args.iter().map(|arg| (*arg).to_string()));
        return Ok(program_arguments);
    }

    let command = spec.command.as_deref().ok_or_else(|| {
        format!(
            "service child env \"{}\" is missing a launcher command",
            spec.env_name
        )
    })?;
    let suffix = format!(
        " {}",
        gateway_args
            .iter()
            .map(|arg| quote_posix(arg))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let base_command = command.strip_suffix(&suffix).ok_or_else(|| {
        format!(
            "service child env \"{}\" launcher command does not end with its gateway arguments",
            spec.env_name
        )
    })?;
    let machine_args = openclaw_args
        .iter()
        .map(|arg| quote_posix(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let machine_command = format!("{base_command} {machine_args}");
    if cfg!(windows) {
        Ok(vec!["cmd".to_string(), "/C".to_string(), machine_command])
    } else {
        Ok(vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            machine_command,
        ])
    }
}

#[cfg(not(unix))]
fn read_bounded<R: Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(remaining)]);
    }
    Ok(kept)
}

#[cfg(unix)]
fn read_bounded_until<R: Read>(mut reader: R, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "output did not settle before its operation deadline",
            ));
        }
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(kept),
            Ok(read) => {
                let remaining = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..read.min(remaining)]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "output did not settle before its operation deadline",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    timeout: Duration,
) -> Result<ChildCompletion, String> {
    loop {
        #[cfg(unix)]
        let wait_result = child_exited_unreaped(child).map(|exited| exited.then_some(()));
        #[cfg(not(unix))]
        let wait_result = child.try_wait();
        match wait_result {
            #[cfg(unix)]
            Ok(Some(())) => return Ok(ChildCompletion::ExitedUnreaped),
            #[cfg(not(unix))]
            Ok(Some(status)) => return Ok(ChildCompletion::Reaped(status)),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                return Err(format!(
                    "restart-handoff command timed out after {} seconds",
                    timeout.as_secs()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "failed waiting for restart-handoff command: {error}"
                ));
            }
        }
    }
}

#[cfg(unix)]
fn child_exited_unreaped(child: &Child) -> Result<bool, String> {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { info.si_pid() } != 0)
}

fn finish_child_wait(child: &mut Child, completion: ChildCompletion) -> Result<ExitStatus, String> {
    #[cfg(not(unix))]
    let _ = child;
    match completion {
        #[cfg(unix)]
        ChildCompletion::ExitedUnreaped => child
            .try_wait()
            .map_err(|error| format!("failed reaping restart-handoff command: {error}"))?
            .ok_or_else(|| "restart-handoff command exit was not ready to reap".to_string()),
        #[cfg(not(unix))]
        ChildCompletion::Reaped(status) => Ok(status),
    }
}

fn reap_child_until(child: &mut Child, deadline: Instant) -> Result<bool, String> {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(true),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => return Ok(false),
            Err(error) => {
                return Err(format!("failed reaping restart-handoff command: {error}"));
            }
        }
    }
}

fn command_failure_detail(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("command exited {code}"),
        None => "command terminated without an exit code".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn direct_spec() -> SupervisorChildSpec {
        SupervisorChildSpec {
            env_name: "demo".to_string(),
            binding_kind: "runtime".to_string(),
            binding_name: "local".to_string(),
            restart_handoff_pid_bound: true,
            command: None,
            binary_path: Some("/runtime/node_modules/openclaw/openclaw.mjs".to_string()),
            runtime_source_kind: Some("installed".to_string()),
            runtime_release_version: None,
            runtime_release_channel: None,
            args: vec![
                "--profile".to_string(),
                "demo".to_string(),
                "gateway".to_string(),
                "run".to_string(),
                "--port".to_string(),
                "19001".to_string(),
            ],
            run_dir: "/tmp/demo".to_string(),
            child_port: 19001,
            stdout_path: "/tmp/demo.stdout.log".to_string(),
            stderr_path: "/tmp/demo.stderr.log".to_string(),
            process_env: BTreeMap::from([
                (
                    "OPENCLAW_LAUNCHD_LABEL".to_string(),
                    "ai.openclaw.ocm".to_string(),
                ),
                (
                    "OPENCLAW_SYSTEMD_UNIT".to_string(),
                    "ai.openclaw.ocm.service".to_string(),
                ),
                (
                    "OPENCLAW_WINDOWS_TASK_NAME".to_string(),
                    "OCM Supervisor".to_string(),
                ),
                (
                    "OPENCLAW_SERVICE_MARKER".to_string(),
                    "openclaw".to_string(),
                ),
                ("OPENCLAW_SERVICE_KIND".to_string(), "gateway".to_string()),
            ]),
        }
    }

    #[test]
    fn direct_binding_replaces_only_gateway_arguments() {
        let args = openclaw_program_arguments(
            &direct_spec(),
            &[
                "gateway",
                "restart-handoff",
                "consume",
                "--expected-pid",
                "42",
                "--json",
            ],
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                "/runtime/node_modules/openclaw/openclaw.mjs",
                "--profile",
                "demo",
                "gateway",
                "restart-handoff",
                "consume",
                "--expected-pid",
                "42",
                "--json",
            ]
        );
    }

    #[test]
    fn wrapper_binding_skips_restart_handoff_capability_probe() {
        let mut spec = direct_spec();
        spec.restart_handoff_pid_bound = false;
        spec.binary_path = Some("/missing/pnpm".to_string());

        assert_eq!(
            probe_restart_handoff_support(&spec),
            RestartHandoffSupport::Unsupported(
                "resolved command does not preserve the supervised gateway PID".to_string()
            )
        );
    }

    #[test]
    fn supported_child_uses_external_supervision_without_native_identity() {
        let prepared =
            prepare_supervisor_child_spec(&direct_spec(), &RestartHandoffSupport::ProtocolV1);
        assert_eq!(
            prepared
                .process_env
                .get("OPENCLAW_SUPERVISOR_MODE")
                .map(String::as_str),
            Some("external")
        );
        assert_eq!(
            prepared
                .process_env
                .get("OPENCLAW_SERVICE_KIND")
                .map(String::as_str),
            Some("gateway")
        );
        assert!(!prepared.process_env.contains_key("OPENCLAW_NO_RESPAWN"));
        for key in OPENCLAW_NATIVE_SERVICE_IDENTITY_KEYS {
            assert!(!prepared.process_env.contains_key(key));
        }
    }

    #[test]
    fn unsupported_child_blocks_detached_respawn_and_native_identity_inference() {
        let prepared = prepare_supervisor_child_spec(
            &direct_spec(),
            &RestartHandoffSupport::Unsupported("missing".to_string()),
        );
        assert_eq!(
            prepared
                .process_env
                .get("OPENCLAW_SERVICE_MARKER")
                .map(String::as_str),
            Some("openclaw")
        );
        assert!(!prepared.process_env.contains_key("OPENCLAW_SERVICE_KIND"));
        assert!(
            !prepared
                .process_env
                .contains_key("OPENCLAW_SUPERVISOR_MODE")
        );
        assert_eq!(
            prepared
                .process_env
                .get("OPENCLAW_NO_RESPAWN")
                .map(String::as_str),
            Some("1")
        );
        for key in OPENCLAW_NATIVE_SERVICE_IDENTITY_KEYS {
            assert!(!prepared.process_env.contains_key(key));
        }
    }

    #[cfg(unix)]
    #[test]
    fn machine_command_bounds_output_settlement_and_cleans_pipe_holders() {
        let temp = tempfile::tempdir().unwrap();
        let descendant_pid = temp.path().join("descendant.pid");
        let launcher = temp.path().join("openclaw.mjs");
        fs::write(
            &launcher,
            "#!/bin/sh\n( trap '' TERM HUP; for _ in 1 2 3 4 5; do sleep 1; done ) &\nprintf '%s\\n' \"$!\" > \"$OCM_TEST_DESCENDANT_PID\"\nprintf '%s\\n' '{\"ok\":true}'\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();

        let mut spec = direct_spec();
        spec.binary_path = Some(launcher.to_string_lossy().into_owned());
        spec.run_dir = temp.path().to_string_lossy().into_owned();
        spec.process_env.insert(
            "OCM_TEST_DESCENDANT_PID".to_string(),
            descendant_pid.to_string_lossy().into_owned(),
        );
        let started_at = Instant::now();
        let error = match run_openclaw_machine_command_with_timeout(
            &spec,
            &["gateway", "restart-handoff", "capabilities", "--json"],
            Duration::from_millis(250),
        ) {
            Ok(_) => panic!("command unexpectedly settled inherited output"),
            Err(error) => error,
        };
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "output settlement exceeded the bounded operation deadline"
        );
        assert!(error.contains("output did not settle"), "{error}");

        let descendant_pid = fs::read_to_string(descendant_pid).unwrap();
        for _ in 0..100 {
            let alive = Command::new("kill")
                .args(["-0", descendant_pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !alive {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("output-holding descendant survived command cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn machine_command_bounds_output_from_detached_pipe_holders() {
        let temp = tempfile::tempdir().unwrap();
        let descendant_pid = temp.path().join("detached-descendant.pid");
        let launcher = temp.path().join("openclaw.mjs");
        fs::write(
            &launcher,
            "#!/bin/sh\n\"$OCM_TEST_HELPER_BIN\" --exact supervisor::openclaw_handoff::tests::detached_output_holder_helper --nocapture &\nfor _ in $(seq 1 200); do\n  [ -f \"$OCM_TEST_DESCENDANT_PID\" ] && break\n  sleep 0.01\ndone\nprintf '%s\\n' '{\"ok\":true}'\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();

        let mut spec = direct_spec();
        spec.binary_path = Some(launcher.to_string_lossy().into_owned());
        spec.run_dir = temp.path().to_string_lossy().into_owned();
        spec.process_env.insert(
            "OCM_TEST_HELPER_BIN".to_string(),
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        spec.process_env.insert(
            "OCM_TEST_DESCENDANT_PID".to_string(),
            descendant_pid.to_string_lossy().into_owned(),
        );
        spec.process_env
            .insert("OCM_TEST_CONTINUOUS_OUTPUT".to_string(), "1".to_string());

        let started_at = Instant::now();
        let error = match run_openclaw_machine_command_with_timeout(
            &spec,
            &["gateway", "restart-handoff", "capabilities", "--json"],
            Duration::from_millis(250),
        ) {
            Ok(_) => panic!("detached inherited output unexpectedly settled"),
            Err(error) => error,
        };
        assert!(
            started_at.elapsed() < Duration::from_secs(3),
            "detached output holder exceeded the bounded operation deadline"
        );
        assert!(error.contains("output did not settle"), "{error}");
        assert!(
            error.contains("detached output ownership remained unresolved")
                || error.contains("failed signaling restart-handoff process group"),
            "{error}"
        );

        let descendant_pid = fs::read_to_string(descendant_pid).unwrap();
        let descendant_pid = descendant_pid.trim().parse::<libc::pid_t>().unwrap();
        assert_eq!(unsafe { libc::kill(descendant_pid, 0) }, 0);
        assert_eq!(unsafe { libc::kill(descendant_pid, libc::SIGKILL) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn detached_output_holder_helper() {
        let Some(pid_path) = std::env::var_os("OCM_TEST_DESCENDANT_PID") else {
            return;
        };
        assert_ne!(unsafe { libc::setsid() }, -1);
        fs::write(pid_path, std::process::id().to_string()).unwrap();
        if std::env::var_os("OCM_TEST_CONTINUOUS_OUTPUT").is_some() {
            let mut stdout = std::io::stdout().lock();
            let output = [b'x'; 8192];
            loop {
                let _ = stdout.write_all(&output);
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}
