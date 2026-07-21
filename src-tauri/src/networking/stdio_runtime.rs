#[cfg(unix)]
mod unix {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant};

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use ring::hmac;
    use serde::Serialize;

    use super::super::{
        IpcRequest, IpcRequestPayload, IpcResponse, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, SidecarHandshake,
        SidecarLaunchContext, SidecarProcessStatus, SidecarRuntime,
    };

    const MAX_RECORD_SIZE: usize = 64 * 1_024;

    #[derive(Serialize)]
    struct BootstrapRecord<'a> {
        protocol_version: u8,
        instance_id: &'a str,
        auth_token: String,
        private_key: String,
    }

    pub struct StdioSidecarRuntime {
        executable: PathBuf,
        child: Option<Child>,
        stdin: Option<ChildStdin>,
        records: Option<Receiver<Result<Vec<u8>, NetworkErrorCode>>>,
        response_timeout: Duration,
    }

    impl StdioSidecarRuntime {
        pub const fn new(executable: PathBuf) -> Self {
            Self {
                executable,
                child: None,
                stdin: None,
                records: None,
                response_timeout: Duration::from_secs(2),
            }
        }

        pub const fn with_response_timeout(mut self, timeout: Duration) -> Self {
            self.response_timeout = timeout;
            self
        }

        pub fn request(&mut self, request: &IpcRequest) -> Result<IpcResponse, NetworkErrorCode> {
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
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let record = match self.receive_record() {
                Ok(record) => record,
                Err(error) => {
                    let _ = self.terminate_child();
                    return Err(error);
                }
            };
            let response: IpcResponse = match serde_json::from_slice(&record) {
                Ok(response) => response,
                Err(_) => {
                    let _ = self.terminate_child();
                    return Err(NetworkErrorCode::SidecarUnavailable);
                }
            };
            if response.protocol_version != NETWORK_IPC_PROTOCOL_VERSION {
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::UnsupportedProtocolVersion);
            }
            if response.request_id != request.request_id {
                let _ = self.terminate_child();
                return Err(NetworkErrorCode::AuthenticationFailed);
            }
            Ok(response)
        }

        fn receive_record(&self) -> Result<Vec<u8>, NetworkErrorCode> {
            self.records
                .as_ref()
                .ok_or(NetworkErrorCode::SidecarUnavailable)?
                .recv_timeout(self.response_timeout)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => NetworkErrorCode::OperationTimedOut,
                    mpsc::RecvTimeoutError::Disconnected => NetworkErrorCode::SidecarUnavailable,
                })?
        }

        fn terminate_child(&mut self) -> Result<(), NetworkErrorCode> {
            self.stdin.take();
            self.records.take();
            let Some(mut child) = self.child.take() else {
                return Ok(());
            };
            if child
                .try_wait()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
                .is_none()
            {
                child.kill().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            }
            child.wait().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            Ok(())
        }
    }

    impl SidecarRuntime for StdioSidecarRuntime {
        fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            if self.child.is_some() || context.private_key().len() != 32 {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            let mut child = Command::new(&self.executable)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let mut stdin = child.stdin.take().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            let stdout = child.stdout.take().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || read_records(stdout, sender));

            let bootstrap = BootstrapRecord {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: &context.instance_id,
                auth_token: BASE64.encode(context.auth_token()),
                private_key: BASE64.encode(context.private_key()),
            };
            let encoded = serde_json::to_vec(&bootstrap).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            if encoded.len() >= MAX_RECORD_SIZE {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            if stdin
                .write_all(&encoded)
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .is_err()
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            self.child = Some(child);
            self.stdin = Some(stdin);
            self.records = Some(receiver);
            let result = self
                .receive_record()
                .and_then(|record| serde_json::from_slice(&record).map_err(|_| NetworkErrorCode::AuthenticationFailed));
            if result.is_err() {
                let _ = self.terminate_child();
            }
            result
        }

        fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            let child = self.child.as_mut().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            match child.try_wait().map_err(|_| NetworkErrorCode::SidecarUnavailable)? {
                None => Ok(SidecarProcessStatus::Running),
                Some(status) => {
                    self.child.take();
                    self.stdin.take();
                    self.records.take();
                    Ok(SidecarProcessStatus::Exited {
                        success: status.success(),
                    })
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
                        .and_then(|child| child.try_wait().ok())
                        .flatten()
                        .is_some()
                    {
                        self.child.take();
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

    impl Drop for StdioSidecarRuntime {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    pub fn sidecar_auth_proof(auth_token: &[u8], instance_id: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, auth_token);
        let mut message = b"kyclash-sidecar-bootstrap-v1\0".to_vec();
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

    fn read_records(stdout: std::process::ChildStdout, sender: mpsc::Sender<Result<Vec<u8>, NetworkErrorCode>>) {
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
        use super::*;
        use crate::networking::{
            IpcResponsePayload, NetworkState, NetworkStatus, RestartPolicy, SidecarController, SidecarLifecycleState,
        };

        #[test]
        fn bootstrap_encoding_matches_shared_fixture() -> Result<(), serde_json::Error> {
            let bootstrap = BootstrapRecord {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: "fixture_instance",
                auth_token: BASE64.encode([0x41; 32]),
                private_key: BASE64.encode([0x42; 32]),
            };
            let fixture = include_bytes!("../../../schemas/fixtures/network-sidecar-bootstrap-v1.json");
            let expected: serde_json::Value = serde_json::from_slice(fixture)?;
            assert_eq!(serde_json::to_value(bootstrap)?, expected);
            Ok(())
        }

        #[test]
        fn launches_real_go_child_and_round_trips_status_and_shutdown() -> Result<(), NetworkErrorCode> {
            let Ok(executable) = std::env::var("KYCLASH_NETWORK_SIDECAR_BIN") else {
                return Ok(());
            };
            let auth_token = vec![0x41; 32];
            let instance_id = "actual_child_test";
            let context =
                SidecarLaunchContext::new(instance_id.into(), auth_token.clone()).with_private_key(vec![0x42; 32]);
            let mut runtime = StdioSidecarRuntime::new(executable.into());
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
            let mut runtime = StdioSidecarRuntime::new(executable.into());
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

#[cfg(unix)]
pub use unix::{StdioSidecarRuntime, sidecar_auth_proof};
