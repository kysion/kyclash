#[cfg(unix)]
mod unix {
    use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    };
    use std::time::{Duration, Instant};

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use ring::hmac;
    #[cfg(feature = "networking-dev")]
    use serde::Deserialize;
    use serde::Serialize;

    use super::super::{
        IpcRequest, IpcRequestPayload, IpcResponse, IpcResponsePayload, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode,
        SidecarHandshake, SidecarLaunchContext, SidecarProcessStatus, SidecarRuntime, SidecarTrustManifest,
        verify_macos_sidecar,
    };

    const MAX_RECORD_SIZE: usize = 64 * 1_024;
    const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(10);
    const DEFAULT_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
    const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(2);
    const CHILD_REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);

    #[derive(Serialize)]
    struct BootstrapRecord<'a> {
        protocol_version: u8,
        instance_id: &'a str,
        auth_token: String,
        private_key: String,
    }

    #[cfg(feature = "networking-dev")]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LabSidecarHandshake {
        pub protocol_version: u8,
        pub instance_id: String,
        pub auth_proof: String,
        pub lab_profile: super::super::NetworkProfile,
        pub cancel_endpoint: String,
    }

    /// The process-control seam owned by the stdio runtime.
    ///
    /// A broker implementation may provide the same typed stdio handles while
    /// keeping the actual child in a privileged service.  The runtime never
    /// accepts a path, argv, environment, or shell from this trait; those
    /// launch-policy decisions stay with the launcher implementation.
    pub trait SidecarProcessControl: Send {
        /// The monotonically increasing generation assigned by the launcher.
        /// A handle from an older generation must never be used to terminate a
        /// newer child.
        fn generation(&self) -> u64;

        /// Probe and reap only this exact process handle when it has exited.
        /// `None` means that this exact child is still running; `Some` carries
        /// the child's exit-success bit after wait/reap confirmation.
        fn try_wait_status(&mut self) -> std::io::Result<Option<bool>>;

        /// Request termination of this exact process handle.
        fn kill_owned(&mut self) -> std::io::Result<()>;

        /// Transfer the one owned stdin/stdout descriptor to the protocol
        /// runtime.  Returning boxed stdio keeps the broker bridge independent
        /// of `std::process::Child` while preserving EOF-based cleanup.
        fn take_stdin(&mut self) -> Option<Box<dyn io::Write + Send>>;
        fn take_stdout(&mut self) -> Option<Box<dyn io::Read + Send>>;
    }

    impl<T: SidecarProcessControl + ?Sized> SidecarProcessControl for Box<T> {
        fn generation(&self) -> u64 {
            (**self).generation()
        }

        fn try_wait_status(&mut self) -> std::io::Result<Option<bool>> {
            (**self).try_wait_status()
        }

        fn kill_owned(&mut self) -> std::io::Result<()> {
            (**self).kill_owned()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn io::Write + Send>> {
            (**self).take_stdin()
        }

        fn take_stdout(&mut self) -> Option<Box<dyn io::Read + Send>> {
            (**self).take_stdout()
        }
    }

    /// Creates one fixed-policy sidecar process and returns its exact process
    /// control.  Implementations must not broaden this API with arbitrary
    /// command, argument, environment, route, or secret fields.
    pub trait StdioSidecarLauncher: Send {
        fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode>;
    }

    /// Local process implementation used by the existing userspace and
    /// development paths.  The future macOS broker client will implement the
    /// same launcher seam without changing protocol-v2 framing.
    #[derive(Debug, Clone, Default)]
    pub struct LocalProcessLauncher {
        executable: PathBuf,
    }

    impl LocalProcessLauncher {
        #[must_use]
        pub const fn new(executable: PathBuf) -> Self {
            Self { executable }
        }
    }

    struct LocalProcessControl {
        generation: u64,
        child: Child,
    }

    pub struct StdioSidecarRuntime<L: StdioSidecarLauncher = LocalProcessLauncher> {
        executable: PathBuf,
        launcher: L,
        child: Option<Box<dyn SidecarProcessControl>>,
        generation: Option<u64>,
        next_generation: u64,
        stdin: Option<Box<dyn io::Write + Send>>,
        records: Option<Receiver<Result<Vec<u8>, NetworkErrorCode>>>,
        response_timeout: Duration,
        cancel_drain_timeout: Duration,
        next_cancel_sequence: u64,
        trust: Option<SidecarTrustManifest>,
    }

    impl SidecarProcessControl for LocalProcessControl {
        fn generation(&self) -> u64 {
            self.generation
        }

        fn try_wait_status(&mut self) -> std::io::Result<Option<bool>> {
            self.child.try_wait().map(|status| status.map(|value| value.success()))
        }

        fn kill_owned(&mut self) -> std::io::Result<()> {
            self.child.kill()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn io::Write + Send>> {
            self.child
                .stdin
                .take()
                .map(|stdin: ChildStdin| Box::new(stdin) as Box<dyn io::Write + Send>)
        }

        fn take_stdout(&mut self) -> Option<Box<dyn io::Read + Send>> {
            self.child
                .stdout
                .take()
                .map(|stdout: ChildStdout| Box::new(stdout) as Box<dyn io::Read + Send>)
        }
    }

    impl StdioSidecarLauncher for LocalProcessLauncher {
        fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode> {
            let child = Command::new(&self.executable)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            Ok(Box::new(LocalProcessControl { generation, child }))
        }
    }

    fn terminate_child_handle<C: SidecarProcessControl>(child: &mut Option<C>) -> Result<(), NetworkErrorCode> {
        terminate_child_handle_with_timeout(child, CHILD_REAP_TIMEOUT, CHILD_REAP_POLL_INTERVAL)
    }

    fn terminate_child_handle_with_timeout<C: SidecarProcessControl>(
        child: &mut Option<C>,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<(), NetworkErrorCode> {
        let Some(process) = child.as_mut() else {
            return Ok(());
        };
        if matches!(process.try_wait_status(), Ok(Some(_))) {
            child.take();
            return Ok(());
        }

        // The child may exit between try_wait and kill. A failed kill is not
        // authoritative, so continue polling the exact owned handle. Never
        // call blocking wait here: AsyncStdioSidecarRuntime executes this code
        // inside block_in_place, where an outer Tokio timeout cannot pre-empt a
        // stuck wait. On timeout the handle remains quarantined for a later
        // stop/reap retry.
        let _ = process.kill_owned();
        let deadline = Instant::now() + timeout;
        loop {
            if matches!(process.try_wait_status(), Ok(Some(_))) {
                child.take();
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            std::thread::sleep(remaining.min(poll_interval.max(Duration::from_millis(1))));
        }
    }

    impl StdioSidecarRuntime<LocalProcessLauncher> {
        pub fn new(executable: PathBuf) -> Self {
            Self::with_launcher(executable.clone(), LocalProcessLauncher::new(executable))
        }

        pub fn new_trusted(executable: PathBuf, trust: SidecarTrustManifest) -> Self {
            Self {
                launcher: LocalProcessLauncher::new(executable.clone()),
                executable,
                child: None,
                generation: None,
                next_generation: 0,
                stdin: None,
                records: None,
                response_timeout: Duration::from_secs(2),
                cancel_drain_timeout: DEFAULT_CANCEL_DRAIN_TIMEOUT,
                next_cancel_sequence: 1,
                trust: Some(trust),
            }
        }
    }

    impl<L: StdioSidecarLauncher> StdioSidecarRuntime<L> {
        pub const fn with_launcher(executable: PathBuf, launcher: L) -> Self {
            Self {
                executable,
                launcher,
                child: None,
                generation: None,
                next_generation: 0,
                stdin: None,
                records: None,
                response_timeout: Duration::from_secs(2),
                cancel_drain_timeout: DEFAULT_CANCEL_DRAIN_TIMEOUT,
                next_cancel_sequence: 1,
                trust: None,
            }
        }

        pub const fn with_response_timeout(mut self, timeout: Duration) -> Self {
            self.response_timeout = timeout;
            self
        }

        pub const fn with_cancel_drain_timeout(mut self, timeout: Duration) -> Self {
            self.cancel_drain_timeout = timeout;
            self
        }

        pub fn request(&mut self, request: &IpcRequest) -> Result<IpcResponse, NetworkErrorCode> {
            let cancel = AtomicBool::new(false);
            self.request_cancellable(request, &cancel)
        }

        /// Protocol v2 remains single-flight except for one exact Cancel control
        /// request targeting an active connect or health request. Both
        /// correlated responses are validated and drained before stream reuse.
        pub fn request_cancellable(
            &mut self,
            request: &IpcRequest,
            cancel: &AtomicBool,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            request.validate_protocol()?;
            let cancellable = matches!(
                request.payload,
                IpcRequestPayload::ConnectTransport { .. } | IpcRequestPayload::SampleHealth
            );
            if cancellable && cancel.load(Ordering::Acquire) {
                return Err(NetworkErrorCode::OperationCancelled);
            }
            if let Err(error) = self.send_request(request) {
                let _ = self.terminate_child();
                return Err(error);
            }

            let primary_deadline = Instant::now() + self.response_timeout;
            let mut cancel_request = None;
            let mut cancel_deadline = None;
            let mut primary_response = None;
            let mut cancel_response = None;

            loop {
                let now = Instant::now();
                if cancel_request.is_none() && now >= primary_deadline {
                    let _ = self.terminate_child();
                    return Err(NetworkErrorCode::OperationTimedOut);
                }
                if cancel_request.is_none() && cancellable && cancel.load(Ordering::Acquire) {
                    let control = match self.cancellation_request(&request.request_id) {
                        Ok(control) => control,
                        Err(error) => {
                            let _ = self.terminate_child();
                            return Err(error);
                        }
                    };
                    if self.send_request(&control).is_err() {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    }
                    cancel_deadline = Some(Instant::now() + self.cancel_drain_timeout);
                    cancel_request = Some(control);
                }

                let deadline = cancel_deadline.unwrap_or(primary_deadline);
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    let _ = self.terminate_child();
                    return Err(if cancel_request.is_some() {
                        NetworkErrorCode::SidecarUnavailable
                    } else {
                        NetworkErrorCode::OperationTimedOut
                    });
                }

                let record = match self.receive_record_for(remaining.min(CANCELLATION_POLL_INTERVAL)) {
                    Ok(Some(record)) => record,
                    Ok(None) => continue,
                    Err(_) => {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    }
                };
                let response: IpcResponse = match serde_json::from_slice(&record) {
                    Ok(response) => response,
                    Err(_) => {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    }
                };
                if response.request_id == request.request_id {
                    if response.validate_protocol(request).is_err() || primary_response.replace(response).is_some() {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    }
                } else if let Some(cancel_request) = cancel_request.as_ref()
                    && response.request_id == cancel_request.request_id
                {
                    if response.validate_protocol(cancel_request).is_err()
                        || cancel_response.replace(response).is_some()
                    {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    }
                } else {
                    let _ = self.terminate_child();
                    return Err(NetworkErrorCode::SidecarUnavailable);
                }

                if cancel_request.is_none() {
                    if let Some(response) = primary_response.take() {
                        if matches!(
                            &response.result,
                            Err(error) if error.code == NetworkErrorCode::OperationCancelled
                        ) {
                            let _ = self.terminate_child();
                            return Err(NetworkErrorCode::SidecarUnavailable);
                        }
                        return Ok(response);
                    }
                } else if primary_response.is_some() && cancel_response.is_some() {
                    let Some(primary) = primary_response.take() else {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    };
                    let Some(control) = cancel_response.take() else {
                        let _ = self.terminate_child();
                        return Err(NetworkErrorCode::SidecarUnavailable);
                    };
                    return self.finish_cancel_pair(request, primary, control);
                }
            }
        }

        fn cancellation_request(&mut self, target_request_id: &str) -> Result<IpcRequest, NetworkErrorCode> {
            let sequence = self.next_cancel_sequence;
            self.next_cancel_sequence = sequence.checked_add(1).ok_or(NetworkErrorCode::InvalidConfiguration)?;
            let request_id = format!("cancel.{sequence:016}");
            if request_id == target_request_id {
                return self.cancellation_request(target_request_id);
            }
            let request = IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id,
                payload: IpcRequestPayload::Cancel {
                    target_request_id: target_request_id.into(),
                },
            };
            request.validate_protocol()?;
            Ok(request)
        }

        fn finish_cancel_pair(
            &mut self,
            request: &IpcRequest,
            primary: IpcResponse,
            control: IpcResponse,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            let accepted = matches!(
                &control.result,
                Ok(IpcResponsePayload::CancelAccepted { target_request_id })
                    if target_request_id == &request.request_id
            );
            let primary_cancelled = matches!(
                &primary.result,
                Err(error)
                    if error.code == NetworkErrorCode::OperationCancelled && !error.retryable
            );
            if accepted {
                if primary_cancelled {
                    return Err(NetworkErrorCode::OperationCancelled);
                }
            } else if matches!(
                &control.result,
                Err(error)
                    if error.code == NetworkErrorCode::InvalidStateTransition
                        && !error.retryable
                        && !matches!(
                            &primary.result,
                            Err(primary_error)
                                if primary_error.code == NetworkErrorCode::OperationCancelled
                        )
            ) {
                return Ok(primary);
            }
            let _ = self.terminate_child();
            Err(NetworkErrorCode::SidecarUnavailable)
        }

        #[cfg(feature = "networking-dev")]
        pub fn start_lab(&mut self, context: &SidecarLaunchContext) -> Result<LabSidecarHandshake, NetworkErrorCode> {
            let record = self.start_record(context)?;
            let handshake: LabSidecarHandshake = serde_json::from_slice(&record).map_err(|_| {
                let _ = self.terminate_child();
                NetworkErrorCode::AuthenticationFailed
            })?;
            if handshake.protocol_version != NETWORK_IPC_PROTOCOL_VERSION {
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::UnsupportedProtocolVersion);
            }
            Ok(handshake)
        }

        fn start_record(&mut self, context: &SidecarLaunchContext) -> Result<Vec<u8>, NetworkErrorCode> {
            if self.child.is_some() || context.private_key().len() != 32 {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            if let Some(trust) = &self.trust {
                verify_macos_sidecar(&self.executable, trust)?;
            }
            let generation = self
                .next_generation
                .checked_add(1)
                .ok_or(NetworkErrorCode::InvalidStateTransition)?;
            self.next_generation = generation;
            let process = self.launcher.launch(generation)?;
            let process_generation = process.generation();
            self.generation = Some(process_generation);
            self.child = Some(process);
            if process_generation != generation {
                // A launcher must never hand an older generation back to the
                // runtime.  Reap only the exact returned handle, then refuse
                // the session; do not guess by PID or process name.
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            let Some(mut stdin) = self.child.as_mut().and_then(|process| process.take_stdin()) else {
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::SidecarUnavailable);
            };
            let Some(stdout) = self.child.as_mut().and_then(|process| process.take_stdout()) else {
                drop(stdin);
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::SidecarUnavailable);
            };
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || read_records(stdout, sender));
            let bootstrap = BootstrapRecord {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: &context.instance_id,
                auth_token: BASE64.encode(context.auth_token()),
                private_key: BASE64.encode(context.private_key()),
            };
            let encoded = match serde_json::to_vec(&bootstrap) {
                Ok(encoded) => encoded,
                Err(_) => {
                    drop(stdin);
                    let _ = self.terminate_child();
                    return Err(NetworkErrorCode::InvalidConfiguration);
                }
            };
            if encoded.len() >= MAX_RECORD_SIZE {
                drop(stdin);
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            if stdin
                .write_all(&encoded)
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .is_err()
            {
                drop(stdin);
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            self.stdin = Some(stdin);
            self.records = Some(receiver);
            match self.receive_record() {
                Ok(record) => Ok(record),
                Err(error) => {
                    let _ = self.terminate_child();
                    Err(error)
                }
            }
        }

        fn receive_record(&self) -> Result<Vec<u8>, NetworkErrorCode> {
            self.receive_record_for(self.response_timeout)?
                .ok_or(NetworkErrorCode::OperationTimedOut)
        }

        fn receive_record_for(&self, timeout: Duration) -> Result<Option<Vec<u8>>, NetworkErrorCode> {
            match self
                .records
                .as_ref()
                .ok_or(NetworkErrorCode::SidecarUnavailable)?
                .recv_timeout(timeout)
            {
                Ok(record) => record.map(Some),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(NetworkErrorCode::SidecarUnavailable),
            }
        }

        fn send_request(&mut self, request: &IpcRequest) -> Result<(), NetworkErrorCode> {
            request.validate_protocol()?;
            let encoded = serde_json::to_vec(request).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            if encoded.len() >= MAX_RECORD_SIZE {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            let stdin = self.stdin.as_mut().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            stdin
                .write_all(&encoded)
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)
        }

        fn terminate_child(&mut self) -> Result<(), NetworkErrorCode> {
            self.stdin.take();
            self.records.take();
            let Some(expected_generation) = self.generation else {
                return terminate_child_handle(&mut self.child);
            };
            let Some(process) = self.child.as_ref() else {
                self.generation = None;
                return Ok(());
            };
            if process.generation() != expected_generation {
                // Never terminate a process whose generation does not match
                // this runtime slot.  Keep the handle quarantined for a
                // caller that still owns that exact generation.
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            let result = terminate_child_handle(&mut self.child);
            if result.is_ok() {
                self.generation = None;
            }
            result
        }
    }

    impl<L: StdioSidecarLauncher> SidecarRuntime for StdioSidecarRuntime<L> {
        fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            let result = self
                .start_record(context)
                .and_then(|record| serde_json::from_slice(&record).map_err(|_| NetworkErrorCode::AuthenticationFailed));
            if result.is_err() {
                let _ = self.terminate_child();
            }
            result
        }

        fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            let child = self.child.as_mut().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            let expected_generation = self.generation.ok_or(NetworkErrorCode::SidecarUnavailable)?;
            if child.generation() != expected_generation {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            match child
                .try_wait_status()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
            {
                None => Ok(SidecarProcessStatus::Running),
                Some(success) => {
                    self.child.take();
                    self.generation = None;
                    self.stdin.take();
                    self.records.take();
                    Ok(SidecarProcessStatus::Exited { success })
                }
            }
        }

        fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            if self.child.is_none() {
                return Ok(());
            }
            let request = IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "request.shutdown".into(),
                payload: IpcRequestPayload::Disconnect,
            };
            let graceful = self.request(&request).is_ok();
            if graceful {
                let deadline = Instant::now() + self.response_timeout;
                while Instant::now() < deadline {
                    if self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait_status().ok().flatten())
                        .is_some()
                    {
                        self.child.take();
                        self.generation = None;
                        self.stdin.take();
                        self.records.take();
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            self.terminate_child()
        }
    }

    impl<L: StdioSidecarLauncher> Drop for StdioSidecarRuntime<L> {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    pub fn sidecar_auth_proof(auth_token: &[u8], instance_id: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, auth_token);
        let mut message = b"kyclash-sidecar-bootstrap-v2\0".to_vec();
        message.extend_from_slice(instance_id.as_bytes());
        hex(hmac::sign(&key, &message).as_ref())
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(DIGITS[usize::from(byte >> 4)] as char);
            encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
        }
        encoded
    }

    fn read_records(stdout: Box<dyn io::Read + Send>, sender: mpsc::Sender<Result<Vec<u8>, NetworkErrorCode>>) {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut record = Vec::new();
            let result = reader
                .by_ref()
                .take((MAX_RECORD_SIZE + 1) as u64)
                .read_until(b'\n', &mut record);
            match result {
                Ok(0) => return,
                Ok(_) if record.len() > MAX_RECORD_SIZE || !record.ends_with(b"\n") => {
                    let _ = sender.send(Err(NetworkErrorCode::SidecarUnavailable));
                    return;
                }
                Ok(_) => {
                    record.pop();
                    if sender.send(Ok(record)).is_err() {
                        return;
                    }
                }
                Err(_) => {
                    let _ = sender.send(Err(NetworkErrorCode::SidecarUnavailable));
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            collections::VecDeque,
            fs,
            io::{Read, Write},
            os::unix::fs::PermissionsExt as _,
            sync::{Arc, Mutex, atomic::AtomicUsize},
            thread,
        };

        use super::*;
        #[cfg(feature = "networking-dev")]
        use crate::networking::TransportKind;
        use crate::networking::{
            IpcResponsePayload, NetworkState, NetworkStatus, RestartPolicy, SidecarController, SidecarLifecycleState,
        };

        // Hosted macOS runners can have a substantially slower first process
        // start than a developer machine. Keep production's two-second
        // runtime default unchanged; only the process-level integration tests
        // use this bounded, test-scoped budget.
        const ACTUAL_CHILD_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

        fn actual_child_runtime(executable: PathBuf) -> StdioSidecarRuntime {
            StdioSidecarRuntime::new(executable).with_response_timeout(ACTUAL_CHILD_RESPONSE_TIMEOUT)
        }

        fn scripted_runtime(
            body: &str,
        ) -> Result<(tempfile::TempDir, SidecarLaunchContext, StdioSidecarRuntime), NetworkErrorCode> {
            let directory = tempfile::tempdir().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let executable = directory.path().join("scripted-sidecar");
            let auth_token = vec![0x41; 32];
            let instance_id = "scripted.sidecar";
            let handshake = serde_json::to_string(&SidecarHandshake {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: instance_id.into(),
                auth_proof: sidecar_auth_proof(&auth_token, instance_id),
            })
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            let script =
                format!("#!/bin/sh\nIFS= read -r bootstrap || exit 10\nprintf '%s\\n' '{handshake}'\n{body}\n");
            fs::write(&executable, script).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let mut permissions = fs::metadata(&executable)
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&executable, permissions).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let context = SidecarLaunchContext::new(instance_id.into(), auth_token).with_private_key(vec![0x42; 32]);
            let runtime = StdioSidecarRuntime::new(executable)
                .with_response_timeout(Duration::from_secs(5))
                .with_cancel_drain_timeout(Duration::from_millis(500));
            Ok((directory, context, runtime))
        }

        fn scenario_records(fixture: &str) -> Result<(String, String), NetworkErrorCode> {
            let scenario: serde_json::Value =
                serde_json::from_str(fixture).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            Ok((
                serde_json::to_string(&scenario["primary_response"])
                    .map_err(|_| NetworkErrorCode::InvalidConfiguration)?,
                serde_json::to_string(&scenario["cancel_response"])
                    .map_err(|_| NetworkErrorCode::InvalidConfiguration)?,
            ))
        }

        fn status_record() -> Result<String, NetworkErrorCode> {
            serde_json::to_string(
                &serde_json::from_str::<serde_json::Value>(include_str!(
                    "../../../schemas/fixtures/network-ipc-v2.status.json"
                ))
                .map_err(|_| NetworkErrorCode::InvalidConfiguration)?,
            )
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)
        }

        fn request_cancel<L: StdioSidecarLauncher>(
            runtime: &mut StdioSidecarRuntime<L>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            let cancel = Arc::new(AtomicBool::new(false));
            let signal = Arc::clone(&cancel);
            let canceller = thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                signal.store(true, Ordering::Release);
            });
            let result = runtime.request_cancellable(
                &IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.health.123".into(),
                    payload: IpcRequestPayload::SampleHealth,
                },
                cancel.as_ref(),
            );
            if canceller.join().is_err() {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            result
        }

        struct InjectedTerminationChild {
            kill_fails: bool,
            polls_before_exit: Option<usize>,
            kill_calls: Arc<AtomicUsize>,
            poll_calls: Arc<AtomicUsize>,
        }

        impl SidecarProcessControl for InjectedTerminationChild {
            fn generation(&self) -> u64 {
                1
            }

            fn try_wait_status(&mut self) -> std::io::Result<Option<bool>> {
                self.poll_calls.fetch_add(1, Ordering::AcqRel);
                match self.polls_before_exit.as_mut() {
                    Some(remaining) if *remaining == 0 => Ok(Some(true)),
                    Some(remaining) => {
                        *remaining -= 1;
                        Ok(None)
                    }
                    None => Ok(None),
                }
            }

            fn kill_owned(&mut self) -> std::io::Result<()> {
                self.kill_calls.fetch_add(1, Ordering::AcqRel);
                if self.kill_fails {
                    Err(std::io::Error::other("injected exit-before-kill race"))
                } else {
                    Ok(())
                }
            }

            fn take_stdin(&mut self) -> Option<Box<dyn io::Write + Send>> {
                None
            }

            fn take_stdout(&mut self) -> Option<Box<dyn io::Read + Send>> {
                None
            }
        }

        #[derive(Clone)]
        struct FakeCancellationSchedule {
            cancel_after_records: usize,
            release_after_records: usize,
            cancel: Arc<AtomicBool>,
            release: Arc<AtomicBool>,
        }

        #[derive(Clone, Default)]
        struct FakePipeMetrics {
            stdin_drops: Arc<AtomicUsize>,
            stdout_drops: Arc<AtomicUsize>,
            writes: Arc<Mutex<Vec<u8>>>,
            cancellation_schedule: Option<FakeCancellationSchedule>,
            kill_calls: Arc<AtomicUsize>,
            poll_calls: Arc<AtomicUsize>,
            reaped: Arc<AtomicUsize>,
        }

        struct FakeWriter {
            writes: Arc<Mutex<Vec<u8>>>,
            drops: Arc<AtomicUsize>,
            cancellation_schedule: Option<FakeCancellationSchedule>,
        }

        impl Write for FakeWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let record_count = {
                    let mut writes = self
                        .writes
                        .lock()
                        .map_err(|_| std::io::Error::other("fake writer lock poisoned"))?;
                    writes.extend_from_slice(bytes);
                    writes.iter().filter(|byte| **byte == b'\n').count()
                };
                if let Some(schedule) = &self.cancellation_schedule {
                    if record_count >= schedule.cancel_after_records {
                        schedule.cancel.store(true, Ordering::Release);
                    }
                    if record_count >= schedule.release_after_records {
                        schedule.release.store(true, Ordering::Release);
                    }
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl Drop for FakeWriter {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::AcqRel);
            }
        }

        struct FakeReader {
            lines: VecDeque<Vec<u8>>,
            pending: Vec<u8>,
            delay_after_first: Option<Duration>,
            release_after_first: Option<Arc<AtomicBool>>,
            reads: usize,
            drops: Arc<AtomicUsize>,
        }

        impl Read for FakeReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.reads > 0 {
                    if let Some(release) = self.release_after_first.take() {
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !release.load(Ordering::Acquire) {
                            if Instant::now() >= deadline {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "fake reader release timed out",
                                ));
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                    if let Some(delay) = self.delay_after_first.take() {
                        thread::sleep(delay);
                    }
                }
                self.reads = self.reads.saturating_add(1);
                if self.pending.is_empty() {
                    let Some(mut line) = self.lines.pop_front() else {
                        return Ok(0);
                    };
                    line.push(b'\n');
                    self.pending = line;
                }
                let count = buffer.len().min(self.pending.len());
                buffer[..count].copy_from_slice(&self.pending[..count]);
                self.pending.drain(..count);
                Ok(count)
            }
        }

        impl Drop for FakeReader {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::AcqRel);
            }
        }

        struct FakeProcessControl {
            generation: u64,
            polls_before_exit: Option<usize>,
            kill_fails: bool,
            exit_success: bool,
            stdin: Option<FakeWriter>,
            stdout: Option<FakeReader>,
            metrics: FakePipeMetrics,
        }

        impl SidecarProcessControl for FakeProcessControl {
            fn generation(&self) -> u64 {
                self.generation
            }

            fn try_wait_status(&mut self) -> std::io::Result<Option<bool>> {
                self.metrics.poll_calls.fetch_add(1, Ordering::AcqRel);
                match self.polls_before_exit.as_mut() {
                    Some(remaining) if *remaining == 0 => {
                        self.metrics.reaped.fetch_add(1, Ordering::AcqRel);
                        Ok(Some(self.exit_success))
                    }
                    Some(remaining) => {
                        *remaining -= 1;
                        Ok(None)
                    }
                    None => Ok(None),
                }
            }

            fn kill_owned(&mut self) -> std::io::Result<()> {
                self.metrics.kill_calls.fetch_add(1, Ordering::AcqRel);
                if self.kill_fails {
                    return Err(std::io::Error::other("fake kill race"));
                }
                self.polls_before_exit = Some(0);
                Ok(())
            }

            fn take_stdin(&mut self) -> Option<Box<dyn io::Write + Send>> {
                self.stdin
                    .take()
                    .map(|writer| Box::new(writer) as Box<dyn io::Write + Send>)
            }

            fn take_stdout(&mut self) -> Option<Box<dyn io::Read + Send>> {
                self.stdout
                    .take()
                    .map(|reader| Box::new(reader) as Box<dyn io::Read + Send>)
            }
        }

        struct FakeLaunchSpec {
            generation: Option<u64>,
            records: Vec<Vec<u8>>,
            delay_after_first: Option<Duration>,
            polls_before_exit: Option<usize>,
            kill_fails: bool,
            metrics: FakePipeMetrics,
        }

        struct FakeLauncher {
            specs: VecDeque<FakeLaunchSpec>,
        }

        impl FakeLauncher {
            fn one(spec: FakeLaunchSpec) -> Self {
                Self {
                    specs: VecDeque::from([spec]),
                }
            }
        }

        impl StdioSidecarLauncher for FakeLauncher {
            fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode> {
                let spec = self.specs.pop_front().ok_or(NetworkErrorCode::SidecarUnavailable)?;
                let actual_generation = spec.generation.unwrap_or(generation);
                let lines = spec.records.into_iter().collect();
                Ok(Box::new(FakeProcessControl {
                    generation: actual_generation,
                    polls_before_exit: spec.polls_before_exit,
                    kill_fails: spec.kill_fails,
                    exit_success: true,
                    stdin: Some(FakeWriter {
                        writes: Arc::clone(&spec.metrics.writes),
                        drops: Arc::clone(&spec.metrics.stdin_drops),
                        cancellation_schedule: spec.metrics.cancellation_schedule.clone(),
                    }),
                    stdout: Some(FakeReader {
                        lines,
                        pending: Vec::new(),
                        delay_after_first: spec.delay_after_first,
                        release_after_first: spec
                            .metrics
                            .cancellation_schedule
                            .as_ref()
                            .map(|schedule| Arc::clone(&schedule.release)),
                        reads: 0,
                        drops: Arc::clone(&spec.metrics.stdout_drops),
                    }),
                    metrics: spec.metrics,
                }))
            }
        }

        fn fake_metrics() -> FakePipeMetrics {
            FakePipeMetrics::default()
        }

        fn fake_handshake_record(context: &SidecarLaunchContext) -> Vec<u8> {
            serde_json::to_vec(&SidecarHandshake {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: context.instance_id.clone(),
                auth_proof: sidecar_auth_proof(context.auth_token(), &context.instance_id),
            })
            .unwrap_or_default()
        }

        fn fake_runtime_with_spec(
            context: &SidecarLaunchContext,
            mut records: Vec<Vec<u8>>,
            metrics: FakePipeMetrics,
            delay_after_first: Option<Duration>,
            generation: Option<u64>,
        ) -> StdioSidecarRuntime<FakeLauncher> {
            let handshake = fake_handshake_record(context);
            records.insert(0, handshake);
            let launcher = FakeLauncher::one(FakeLaunchSpec {
                generation,
                records,
                delay_after_first,
                polls_before_exit: None,
                kill_fails: false,
                metrics,
            });
            StdioSidecarRuntime::with_launcher(PathBuf::from("fixed-sidecar"), launcher)
                .with_response_timeout(Duration::from_millis(100))
                .with_cancel_drain_timeout(Duration::from_millis(200))
        }

        fn fake_runtime(
            context: &SidecarLaunchContext,
            records: Vec<Vec<u8>>,
            metrics: FakePipeMetrics,
        ) -> StdioSidecarRuntime<FakeLauncher> {
            fake_runtime_with_spec(context, records, metrics, None, None)
        }

        fn wait_for_drop(count: &Arc<AtomicUsize>) {
            let deadline = Instant::now() + Duration::from_secs(1);
            while count.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
        }

        #[test]
        fn fake_launcher_preserves_handshake_request_and_descriptor_cleanup() -> Result<(), NetworkErrorCode> {
            let context =
                SidecarLaunchContext::new("fake.handshake".into(), vec![0x31; 32]).with_private_key(vec![0x32; 32]);
            let metrics = fake_metrics();
            let mut runtime = fake_runtime(&context, vec![status_record()?.into_bytes()], metrics.clone());
            let handshake = runtime.start(&context)?;
            assert_eq!(handshake.instance_id, context.instance_id);
            let response = runtime.request(&IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "request.status".into(),
                payload: IpcRequestPayload::GetStatus,
            })?;
            assert!(matches!(response.result, Ok(IpcResponsePayload::Status(_))));
            let _ = runtime.stop();

            let writes = String::from_utf8(
                metrics
                    .writes
                    .lock()
                    .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                    .clone(),
            )
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            assert!(writes.contains("\"protocol_version\":2"));
            assert!(writes.contains("\"request_id\":\"request.status\""));
            wait_for_drop(&metrics.stdin_drops);
            wait_for_drop(&metrics.stdout_drops);
            assert_eq!(metrics.stdin_drops.load(Ordering::Acquire), 1);
            assert_eq!(metrics.stdout_drops.load(Ordering::Acquire), 1);
            Ok(())
        }

        #[test]
        fn fake_launcher_cancel_drains_correlated_pair_before_exact_reap() -> Result<(), NetworkErrorCode> {
            let context =
                SidecarLaunchContext::new("fake.cancel".into(), vec![0x33; 32]).with_private_key(vec![0x34; 32]);
            let (primary, control) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
            ))?;
            let cancel = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let metrics = FakePipeMetrics {
                cancellation_schedule: Some(FakeCancellationSchedule {
                    cancel_after_records: 2,
                    release_after_records: 3,
                    cancel: Arc::clone(&cancel),
                    release,
                }),
                ..fake_metrics()
            };
            let mut runtime = fake_runtime_with_spec(
                &context,
                vec![primary.into_bytes(), control.into_bytes()],
                metrics.clone(),
                None,
                None,
            );
            runtime.start(&context)?;
            let result = runtime.request_cancellable(
                &IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.health.123".into(),
                    payload: IpcRequestPayload::SampleHealth,
                },
                cancel.as_ref(),
            );
            assert_eq!(result, Err(NetworkErrorCode::OperationCancelled));
            let writes = metrics
                .writes
                .lock()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .clone();
            assert!(writes.ends_with(b"\n"));
            let records = writes[..writes.len() - 1]
                .split(|byte| *byte == b'\n')
                .collect::<Vec<_>>();
            assert_eq!(records.len(), 3);
            assert!(records.iter().all(|record| !record.is_empty()));
            let primary_request: IpcRequest =
                serde_json::from_slice(records[1]).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            assert_eq!(primary_request.request_id, "request.health.123");
            assert!(matches!(primary_request.payload, IpcRequestPayload::SampleHealth));
            let cancel_request: IpcRequest =
                serde_json::from_slice(records[2]).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            assert_eq!(cancel_request.request_id, "cancel.0000000000000001");
            assert!(matches!(
                cancel_request.payload,
                IpcRequestPayload::Cancel { target_request_id }
                    if target_request_id == primary_request.request_id
            ));
            runtime.terminate_child()?;
            assert_eq!(metrics.kill_calls.load(Ordering::Acquire), 1);
            assert!(metrics.reaped.load(Ordering::Acquire) >= 1);
            Ok(())
        }

        #[test]
        fn fake_launcher_timeout_forces_exact_reap_and_closes_pipes() -> Result<(), NetworkErrorCode> {
            let context =
                SidecarLaunchContext::new("fake.timeout".into(), vec![0x35; 32]).with_private_key(vec![0x36; 32]);
            let metrics = fake_metrics();
            let mut runtime = fake_runtime_with_spec(
                &context,
                Vec::new(),
                metrics.clone(),
                Some(Duration::from_millis(100)),
                None,
            )
            .with_response_timeout(Duration::from_millis(20));
            runtime.start(&context)?;
            assert_eq!(
                runtime.request(&IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.timeout.fake".into(),
                    payload: IpcRequestPayload::GetStatus,
                }),
                Err(NetworkErrorCode::OperationTimedOut)
            );
            assert_eq!(metrics.kill_calls.load(Ordering::Acquire), 1);
            assert!(metrics.reaped.load(Ordering::Acquire) >= 1);
            wait_for_drop(&metrics.stdin_drops);
            wait_for_drop(&metrics.stdout_drops);
            Ok(())
        }

        #[test]
        fn fake_launcher_rejects_stale_generation_without_reusing_process_handle() {
            let context =
                SidecarLaunchContext::new("fake.stale".into(), vec![0x37; 32]).with_private_key(vec![0x38; 32]);
            let metrics = fake_metrics();
            let mut runtime = fake_runtime_with_spec(&context, Vec::new(), metrics.clone(), None, Some(99));
            assert_eq!(runtime.start(&context), Err(NetworkErrorCode::InvalidStateTransition));
            assert_eq!(metrics.kill_calls.load(Ordering::Acquire), 1);
            assert!(metrics.reaped.load(Ordering::Acquire) >= 1);
            assert_eq!(runtime.status(), Err(NetworkErrorCode::SidecarUnavailable));
        }

        #[test]
        fn fake_process_exact_reap_does_not_release_unconfirmed_handle() -> Result<(), NetworkErrorCode> {
            let metrics = fake_metrics();
            let mut process = Some(FakeProcessControl {
                generation: 7,
                polls_before_exit: None,
                kill_fails: true,
                exit_success: true,
                stdin: None,
                stdout: None,
                metrics: metrics.clone(),
            });
            assert_eq!(
                terminate_child_handle_with_timeout(&mut process, Duration::ZERO, Duration::ZERO),
                Err(NetworkErrorCode::SidecarUnavailable)
            );
            assert!(process.is_some());
            let Some(process_ref) = process.as_mut() else {
                return Err(NetworkErrorCode::SidecarUnavailable);
            };
            process_ref.polls_before_exit = Some(1);
            process_ref.kill_fails = false;
            terminate_child_handle(&mut process)?;
            assert!(process.is_none());
            assert_eq!(metrics.kill_calls.load(Ordering::Acquire), 2);
            assert!(metrics.reaped.load(Ordering::Acquire) >= 1);
            Ok(())
        }

        #[test]
        fn bootstrap_encoding_matches_shared_fixture() -> Result<(), serde_json::Error> {
            const PRODUCTION_SHAPED_INSTANCE_ID: &str = "kyclash.0123456789abcdef0123456789abcdef";
            let bootstrap = BootstrapRecord {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: PRODUCTION_SHAPED_INSTANCE_ID,
                auth_token: BASE64.encode([0x41; 32]),
                private_key: BASE64.encode([0x42; 32]),
            };
            let fixture = include_bytes!("../../../schemas/fixtures/network-sidecar-bootstrap-v2.json");
            let expected: serde_json::Value = serde_json::from_slice(fixture)?;
            assert_eq!(serde_json::to_value(bootstrap)?, expected);
            let handshake: SidecarHandshake = serde_json::from_slice(include_bytes!(
                "../../../schemas/fixtures/network-sidecar-handshake-v2.json"
            ))?;
            assert_eq!(handshake.protocol_version, NETWORK_IPC_PROTOCOL_VERSION);
            assert_eq!(handshake.instance_id, PRODUCTION_SHAPED_INSTANCE_ID);
            assert_eq!(
                handshake.auth_proof,
                sidecar_auth_proof(&[0x41; 32], PRODUCTION_SHAPED_INSTANCE_ID)
            );
            Ok(())
        }

        #[test]
        fn cancellation_wins_in_both_response_orders_and_stream_remains_usable() -> Result<(), NetworkErrorCode> {
            let (primary, control) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
            ))?;
            for (first, second) in [(&primary, &control), (&control, &primary)] {
                let body = format!(
                    "IFS= read -r primary || exit 11\nIFS= read -r control || exit 12\nprintf '%s\\n' '{first}'\nprintf '%s\\n' '{second}'\nIFS= read -r status || exit 13\nprintf '%s\\n' '{}'\n/bin/sleep 2",
                    status_record()?
                );
                let (_directory, context, mut runtime) = scripted_runtime(&body)?;
                runtime.start(&context)?;
                assert_eq!(request_cancel(&mut runtime), Err(NetworkErrorCode::OperationCancelled));
                let status = runtime.request(&IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.status".into(),
                    payload: IpcRequestPayload::GetStatus,
                })?;
                assert!(matches!(status.result, Ok(IpcResponsePayload::Status(_))));
                runtime.terminate_child()?;
            }
            Ok(())
        }

        #[test]
        fn completion_wins_in_both_response_orders_and_primary_is_authoritative() -> Result<(), NetworkErrorCode> {
            let (primary, control) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.completion-wins.json"
            ))?;
            for (first, second) in [(&primary, &control), (&control, &primary)] {
                let body = format!(
                    "IFS= read -r primary || exit 11\nIFS= read -r control || exit 12\nprintf '%s\\n' '{first}'\nprintf '%s\\n' '{second}'\nIFS= read -r status || exit 13\nprintf '%s\\n' '{}'\n/bin/sleep 2",
                    status_record()?
                );
                let (_directory, context, mut runtime) = scripted_runtime(&body)?;
                runtime.start(&context)?;
                let response = request_cancel(&mut runtime)?;
                assert!(matches!(response.result, Ok(IpcResponsePayload::Health(_))));
                assert!(
                    runtime
                        .request(&IpcRequest {
                            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                            request_id: "request.status".into(),
                            payload: IpcRequestPayload::GetStatus,
                        })
                        .is_ok()
                );
                runtime.terminate_child()?;
            }
            Ok(())
        }

        #[test]
        fn standalone_operation_cancelled_before_control_is_fatal_and_reaped() -> Result<(), NetworkErrorCode> {
            let (cancelled_primary, _) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
            ))?;
            let body = format!("IFS= read -r primary || exit 11\nprintf '%s\\n' '{cancelled_primary}'\n/bin/sleep 2");
            let (_directory, context, mut runtime) = scripted_runtime(&body)?;
            runtime.start(&context)?;
            assert_eq!(
                runtime.request(&IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.health.123".into(),
                    payload: IpcRequestPayload::SampleHealth,
                }),
                Err(NetworkErrorCode::SidecarUnavailable)
            );
            assert_eq!(runtime.status(), Err(NetworkErrorCode::SidecarUnavailable));
            Ok(())
        }

        #[test]
        fn too_late_cancel_and_cancelled_primary_are_contradictory_in_both_orders() -> Result<(), NetworkErrorCode> {
            let (cancelled_primary, _) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
            ))?;
            let (_, too_late_control) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.completion-wins.json"
            ))?;
            for (first, second) in [
                (&cancelled_primary, &too_late_control),
                (&too_late_control, &cancelled_primary),
            ] {
                let body = format!(
                    "IFS= read -r primary || exit 11\nIFS= read -r control || exit 12\nprintf '%s\\n' '{first}'\nprintf '%s\\n' '{second}'\n/bin/sleep 2"
                );
                let (_directory, context, mut runtime) = scripted_runtime(&body)?;
                runtime.start(&context)?;
                assert_eq!(request_cancel(&mut runtime), Err(NetworkErrorCode::SidecarUnavailable));
                assert_eq!(runtime.status(), Err(NetworkErrorCode::SidecarUnavailable));
            }
            Ok(())
        }

        #[test]
        fn accepted_cancel_requires_nonretryable_primary_and_strict_nested_fields() -> Result<(), NetworkErrorCode> {
            let (cancelled_primary, accepted_control) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
            ))?;
            let mut retryable_primary: serde_json::Value =
                serde_json::from_str(&cancelled_primary).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            retryable_primary["result"]["Err"]["retryable"] = serde_json::Value::Bool(true);
            let retryable_primary =
                serde_json::to_string(&retryable_primary).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;

            let mut extra_control: serde_json::Value =
                serde_json::from_str(&accepted_control).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            let data = extra_control["result"]["Ok"]["data"]
                .as_object_mut()
                .ok_or(NetworkErrorCode::InvalidConfiguration)?;
            data.insert("unknown".into(), serde_json::Value::Bool(true));
            let extra_control =
                serde_json::to_string(&extra_control).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;

            for (primary, control) in [
                (&retryable_primary, &accepted_control),
                (&cancelled_primary, &extra_control),
            ] {
                let body = format!(
                    "IFS= read -r primary || exit 11\nIFS= read -r control || exit 12\nprintf '%s\\n' '{primary}'\nprintf '%s\\n' '{control}'\n/bin/sleep 2"
                );
                let (_directory, context, mut runtime) = scripted_runtime(&body)?;
                runtime.start(&context)?;
                assert_eq!(request_cancel(&mut runtime), Err(NetworkErrorCode::SidecarUnavailable));
                assert_eq!(runtime.status(), Err(NetworkErrorCode::SidecarUnavailable));
            }
            Ok(())
        }

        #[test]
        fn termination_waits_after_kill_race_and_quarantines_unconfirmed_handle() -> Result<(), NetworkErrorCode> {
            let race_kills = Arc::new(AtomicUsize::new(0));
            let race_polls = Arc::new(AtomicUsize::new(0));
            let mut raced_child = Some(InjectedTerminationChild {
                kill_fails: true,
                polls_before_exit: Some(1),
                kill_calls: Arc::clone(&race_kills),
                poll_calls: Arc::clone(&race_polls),
            });
            terminate_child_handle(&mut raced_child)?;
            assert!(raced_child.is_none());
            assert_eq!(race_kills.load(Ordering::Acquire), 1);
            assert_eq!(race_polls.load(Ordering::Acquire), 2);

            let retry_kills = Arc::new(AtomicUsize::new(0));
            let retry_polls = Arc::new(AtomicUsize::new(0));
            let mut quarantined_child = Some(InjectedTerminationChild {
                kill_fails: false,
                polls_before_exit: None,
                kill_calls: Arc::clone(&retry_kills),
                poll_calls: Arc::clone(&retry_polls),
            });
            assert_eq!(
                terminate_child_handle_with_timeout(&mut quarantined_child, Duration::ZERO, Duration::ZERO),
                Err(NetworkErrorCode::SidecarUnavailable)
            );
            assert!(quarantined_child.is_some());
            quarantined_child
                .as_mut()
                .ok_or(NetworkErrorCode::SidecarUnavailable)?
                .polls_before_exit = Some(1);
            terminate_child_handle(&mut quarantined_child)?;
            assert!(quarantined_child.is_none());
            assert_eq!(retry_kills.load(Ordering::Acquire), 2);
            assert_eq!(retry_polls.load(Ordering::Acquire), 4);
            Ok(())
        }

        #[test]
        fn incomplete_or_contradictory_cancel_pairs_are_fatal_and_reaped() -> Result<(), NetworkErrorCode> {
            let (cancelled_primary, accepted_control) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
            ))?;
            let (successful_primary, _) = scenario_records(include_str!(
                "../../../schemas/fixtures/network-ipc-v2.completion-wins.json"
            ))?;
            for records in [
                format!("printf '%s\\n' '{accepted_control}'"),
                format!("printf '%s\\n' '{cancelled_primary}'"),
                format!("printf '%s\\n' '{accepted_control}'\nprintf '%s\\n' '{successful_primary}'"),
            ] {
                let body = format!(
                    "IFS= read -r primary || exit 11\nIFS= read -r control || exit 12\n{records}\n/bin/sleep 2"
                );
                let (_directory, context, mut runtime) = scripted_runtime(&body)?;
                runtime.start(&context)?;
                assert_eq!(request_cancel(&mut runtime), Err(NetworkErrorCode::SidecarUnavailable));
                assert_eq!(runtime.status(), Err(NetworkErrorCode::SidecarUnavailable));
            }
            Ok(())
        }

        #[test]
        fn cancellation_token_never_cancels_or_kills_a_noncancellable_request() -> Result<(), NetworkErrorCode> {
            let body = format!(
                "IFS= read -r primary || exit 11\nprintf '%s\\n' '{}'\n/bin/sleep 2",
                status_record()?
            );
            let (_directory, context, mut runtime) = scripted_runtime(&body)?;
            runtime.start(&context)?;
            let cancel = AtomicBool::new(true);
            let response = runtime.request_cancellable(
                &IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.status".into(),
                    payload: IpcRequestPayload::GetStatus,
                },
                &cancel,
            )?;
            assert!(matches!(response.result, Ok(IpcResponsePayload::Status(_))));
            assert_eq!(runtime.status(), Ok(SidecarProcessStatus::Running));
            runtime.terminate_child()?;
            Ok(())
        }

        #[test]
        fn launches_real_go_child_and_round_trips_status_and_shutdown() -> Result<(), NetworkErrorCode> {
            let Ok(executable) = std::env::var("KYCLASH_NETWORK_SIDECAR_BIN") else {
                return Ok(());
            };
            let auth_token = vec![0x41; 32];
            let instance_id = "kyclash.fedcba98765432100123456789abcdef";
            let context =
                SidecarLaunchContext::new(instance_id.into(), auth_token.clone()).with_private_key(vec![0x42; 32]);
            let mut runtime = actual_child_runtime(executable.into());
            let handshake = runtime.start(&context)?;
            assert_eq!(handshake.protocol_version, NETWORK_IPC_PROTOCOL_VERSION);
            assert_eq!(handshake.instance_id, instance_id);
            assert_eq!(handshake.auth_proof, sidecar_auth_proof(&auth_token, instance_id));

            let response = runtime.request(&IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "request.status".into(),
                payload: IpcRequestPayload::GetStatus,
            })?;
            assert_eq!(
                response.result,
                Ok(IpcResponsePayload::Status(NetworkStatus {
                    state: NetworkState::Disconnected,
                    active_profile_id: None,
                    active_transport: None,
                    last_error: None,
                }))
            );
            runtime.stop()?;
            Ok(())
        }

        #[test]
        fn actual_child_prepares_and_stops_userspace_tunnel() -> Result<(), NetworkErrorCode> {
            let Ok(executable) = std::env::var("KYCLASH_NETWORK_SIDECAR_BIN") else {
                return Ok(());
            };
            let profile = serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))
                .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            let context = SidecarLaunchContext::new("stateful_child_test".into(), vec![0x43; 32])
                .with_private_key(vec![0x44; 32]);
            let mut runtime = actual_child_runtime(executable.into());
            runtime.start(&context)?;

            for (request_id, payload) in [
                ("request.profile", IpcRequestPayload::ApplyProfile(Box::new(profile))),
                ("request.prepare", IpcRequestPayload::PrepareTunnel),
            ] {
                let response = runtime.request(&IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: request_id.into(),
                    payload,
                })?;
                assert!(response.result.is_ok());
            }
            let response = runtime.request(&IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "request.stop_tunnel".into(),
                payload: IpcRequestPayload::StopTunnel,
            })?;
            assert!(response.result.is_ok());
            runtime.stop()?;
            Ok(())
        }

        #[cfg(feature = "networking-dev")]
        #[test]
        fn actual_lab_child_carries_health_traffic_across_all_carriers() -> Result<(), NetworkErrorCode> {
            let Ok(executable) = std::env::var("KYCLASH_NETWORK_LAB_SIDECAR_BIN") else {
                return Ok(());
            };
            let auth_token = vec![0x51; 32];
            let instance_id = "actual_lab_child";
            let context =
                SidecarLaunchContext::new(instance_id.into(), auth_token.clone()).with_private_key(vec![0x52; 32]);
            let mut runtime = actual_child_runtime(executable.clone().into());
            let handshake = runtime.start_lab(&context)?;
            assert_eq!(handshake.instance_id, instance_id);
            assert_eq!(handshake.auth_proof, sidecar_auth_proof(&auth_token, instance_id));
            handshake.lab_profile.validate()?;
            {
                let mut request_sequence = 0_u64;
                let mut request = |payload| {
                    request_sequence += 1;
                    runtime.request(&IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: format!("request.lab.{request_sequence}"),
                        payload,
                    })
                };
                assert!(
                    request(IpcRequestPayload::ApplyProfile(Box::new(handshake.lab_profile)))?
                        .result
                        .is_ok()
                );
                assert!(request(IpcRequestPayload::PrepareTunnel)?.result.is_ok());
                for transport in [TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp] {
                    assert!(
                        request(IpcRequestPayload::ConnectTransport { transport })?
                            .result
                            .is_ok()
                    );
                    let health = request(IpcRequestPayload::SampleHealth)?;
                    assert!(
                        matches!(health.result, Ok(IpcResponsePayload::Health(ref value)) if value.reachable),
                        "health probe failed: {:?}",
                        health.result
                    );
                    assert!(request(IpcRequestPayload::DisconnectTransport)?.result.is_ok());
                }
                assert!(request(IpcRequestPayload::StopTunnel)?.result.is_ok());
            }
            runtime.stop()?;

            let cancel_token = vec![0x61; 32];
            let cancel_instance = "actual_lab_cancel";
            let cancel_context = SidecarLaunchContext::new(cancel_instance.into(), cancel_token.clone())
                .with_private_key(vec![0x62; 32]);
            let mut runtime = actual_child_runtime(executable.into());
            let cancel_handshake = runtime.start_lab(&cancel_context)?;
            assert_eq!(
                cancel_handshake.auth_proof,
                sidecar_auth_proof(&cancel_token, cancel_instance)
            );
            let mut cancel_profile = cancel_handshake.lab_profile;
            let quic_endpoint = cancel_profile
                .transports
                .endpoints
                .iter_mut()
                .find(|endpoint| endpoint.transport == TransportKind::Quic)
                .ok_or(NetworkErrorCode::InvalidConfiguration)?;
            quic_endpoint.url = cancel_handshake.cancel_endpoint;
            cancel_profile.validate()?;
            let apply_cancel_profile = IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "request.cancel.profile".into(),
                payload: IpcRequestPayload::ApplyProfile(Box::new(cancel_profile)),
            };
            assert!(runtime.request(&apply_cancel_profile)?.result.is_ok());
            assert!(
                runtime
                    .request(&IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: "request.cancel.prepare".into(),
                        payload: IpcRequestPayload::PrepareTunnel,
                    })?
                    .result
                    .is_ok()
            );
            let cancel = Arc::new(AtomicBool::new(false));
            let cancel_from_controller = Arc::clone(&cancel);
            let canceller = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                cancel_from_controller.store(true, Ordering::Release);
            });
            let cancel_started = Instant::now();
            let cancellation_result = runtime.request_cancellable(
                &IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.cancel.connect".into(),
                    payload: IpcRequestPayload::ConnectTransport {
                        transport: TransportKind::Quic,
                    },
                },
                cancel.as_ref(),
            );
            canceller.join().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            assert_eq!(cancellation_result, Err(NetworkErrorCode::OperationCancelled));
            assert!(
                cancel_started.elapsed() < Duration::from_secs(5),
                "actual-child cancellation exceeded the bounded deadline"
            );

            let after_cancel = runtime.request(&IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "request.cancel.status".into(),
                payload: IpcRequestPayload::GetStatus,
            })?;
            assert!(matches!(
                after_cancel.result,
                Ok(IpcResponsePayload::Status(NetworkStatus {
                    state: NetworkState::PreparingTunnel,
                    active_transport: None,
                    ..
                }))
            ));
            for (index, transport) in [TransportKind::Wss, TransportKind::Tcp].into_iter().enumerate() {
                assert!(
                    runtime
                        .request(&IpcRequest {
                            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                            request_id: format!("request.cancel.fallback.{index}"),
                            payload: IpcRequestPayload::ConnectTransport { transport },
                        })?
                        .result
                        .is_ok()
                );
                let health = runtime.request(&IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: format!("request.cancel.health.{index}"),
                    payload: IpcRequestPayload::SampleHealth,
                })?;
                assert!(matches!(health.result, Ok(IpcResponsePayload::Health(ref value)) if value.reachable));
                assert!(
                    runtime
                        .request(&IpcRequest {
                            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                            request_id: format!("request.cancel.disconnect.{index}"),
                            payload: IpcRequestPayload::DisconnectTransport,
                        })?
                        .result
                        .is_ok()
                );
            }
            assert!(
                runtime
                    .request(&IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: "request.cancel.stop".into(),
                        payload: IpcRequestPayload::StopTunnel,
                    })?
                    .result
                    .is_ok()
            );
            runtime.stop()?;
            Ok(())
        }

        #[cfg(feature = "networking-dev")]
        #[test]
        fn actual_lab_child_timeout_forces_bounded_process_cleanup() -> Result<(), NetworkErrorCode> {
            let Ok(executable) = std::env::var("KYCLASH_NETWORK_LAB_SIDECAR_BIN") else {
                return Ok(());
            };
            let context =
                SidecarLaunchContext::new("actual_lab_timeout".into(), vec![0x71; 32]).with_private_key(vec![0x72; 32]);
            let mut runtime = StdioSidecarRuntime::new(executable.into()).with_response_timeout(Duration::from_secs(3));
            let handshake = runtime.start_lab(&context)?;
            let mut network_profile = handshake.lab_profile;
            network_profile
                .transports
                .endpoints
                .iter_mut()
                .find(|endpoint| endpoint.transport == TransportKind::Quic)
                .ok_or(NetworkErrorCode::InvalidConfiguration)?
                .url = handshake.cancel_endpoint;
            assert!(
                runtime
                    .request(&IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: "request.timeout.profile".into(),
                        payload: IpcRequestPayload::ApplyProfile(Box::new(network_profile)),
                    })?
                    .result
                    .is_ok()
            );
            assert!(
                runtime
                    .request(&IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: "request.timeout.prepare".into(),
                        payload: IpcRequestPayload::PrepareTunnel,
                    })?
                    .result
                    .is_ok()
            );
            assert_eq!(
                runtime.request(&IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.timeout.connect".into(),
                    payload: IpcRequestPayload::ConnectTransport {
                        transport: TransportKind::Quic
                    },
                }),
                Err(NetworkErrorCode::OperationTimedOut)
            );
            assert_eq!(runtime.status(), Err(NetworkErrorCode::SidecarUnavailable));
            runtime.stop()?;
            Ok(())
        }

        #[test]
        fn actual_child_is_terminated_when_authentication_fails() {
            let Ok(executable) = std::env::var("KYCLASH_NETWORK_SIDECAR_BIN") else {
                return;
            };
            let context =
                SidecarLaunchContext::new("auth_failure_test".into(), vec![0x41; 32]).with_private_key(vec![0x42; 32]);
            let runtime = StdioSidecarRuntime::new(executable.into());
            let mut controller =
                SidecarController::new(runtime, RestartPolicy::default(), context, "wrong-proof".into());
            assert_eq!(controller.start(0), Err(NetworkErrorCode::AuthenticationFailed));
            assert_eq!(controller.state(), SidecarLifecycleState::Stopped);
        }
    }
}

#[cfg(all(unix, feature = "networking-dev"))]
pub use unix::LabSidecarHandshake;
#[cfg(unix)]
pub use unix::{
    LocalProcessLauncher, SidecarProcessControl, StdioSidecarLauncher, StdioSidecarRuntime, sidecar_auth_proof,
};
