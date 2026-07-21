#[cfg(unix)]
mod unix {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant};

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use ring::hmac;
    #[cfg(feature = "networking-dev")]
    use serde::Deserialize;
    use serde::Serialize;

    use super::super::{
        IpcRequest, IpcRequestPayload, IpcResponse, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, SidecarHandshake,
        SidecarLaunchContext, SidecarProcessStatus, SidecarRuntime, SidecarTrustManifest, verify_macos_sidecar,
    };

    const MAX_RECORD_SIZE: usize = 64 * 1_024;

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

    pub struct StdioSidecarRuntime {
        executable: PathBuf,
        child: Option<Child>,
        stdin: Option<ChildStdin>,
        records: Option<Receiver<Result<Vec<u8>, NetworkErrorCode>>>,
        response_timeout: Duration,
        trust: Option<SidecarTrustManifest>,
    }

    impl StdioSidecarRuntime {
        pub const fn new(executable: PathBuf) -> Self {
            Self {
                executable,
                child: None,
                stdin: None,
                records: None,
                response_timeout: Duration::from_secs(2),
                trust: None,
            }
        }

        pub const fn new_trusted(executable: PathBuf, trust: SidecarTrustManifest) -> Self {
            Self {
                executable,
                child: None,
                stdin: None,
                records: None,
                response_timeout: Duration::from_secs(2),
                trust: Some(trust),
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

        #[cfg(feature = "networking-dev")]
        pub fn request_with_cancel(
            &mut self,
            operation: &IpcRequest,
            cancel: &IpcRequest,
        ) -> Result<(IpcResponse, IpcResponse), NetworkErrorCode> {
            operation.validate_protocol()?;
            cancel.validate_protocol()?;
            let operation_record = serde_json::to_vec(operation).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            let cancel_record = serde_json::to_vec(cancel).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            if operation_record.len() >= MAX_RECORD_SIZE || cancel_record.len() >= MAX_RECORD_SIZE {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            let stdin = self.stdin.as_mut().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            for record in [&operation_record, &cancel_record] {
                stdin
                    .write_all(record)
                    .and_then(|()| stdin.write_all(b"\n"))
                    .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            }
            stdin.flush().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let first: IpcResponse =
                serde_json::from_slice(&self.receive_record()?).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let second: IpcResponse =
                serde_json::from_slice(&self.receive_record()?).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let find = |request_id: &str| {
                if first.request_id == request_id {
                    Some(first.clone())
                } else if second.request_id == request_id {
                    Some(second.clone())
                } else {
                    None
                }
            };
            let operation_response = find(&operation.request_id).ok_or(NetworkErrorCode::AuthenticationFailed)?;
            let cancel_response = find(&cancel.request_id).ok_or(NetworkErrorCode::AuthenticationFailed)?;
            Ok((operation_response, cancel_response))
        }

        fn start_record(&mut self, context: &SidecarLaunchContext) -> Result<Vec<u8>, NetworkErrorCode> {
            if self.child.is_some() || context.private_key().len() != 32 {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            if let Some(trust) = &self.trust {
                verify_macos_sidecar(&self.executable, trust)?;
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
            match self.receive_record() {
                Ok(record) => Ok(record),
                Err(error) => {
                    let _ = self.terminate_child();
                    Err(error)
                }
            }
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
            let (operation_response, cancel_response) = runtime.request_with_cancel(
                &IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.cancel.connect".into(),
                    payload: IpcRequestPayload::ConnectTransport {
                        transport: TransportKind::Quic,
                    },
                },
                &IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.cancel.operation".into(),
                    payload: IpcRequestPayload::Cancel {
                        operation_id: "operation.connect".into(),
                    },
                },
            )?;
            assert!(
                cancel_response.result.is_ok(),
                "cancel failed: {:?}",
                cancel_response.result
            );
            assert!(operation_response.result.is_err());
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
pub use unix::{StdioSidecarRuntime, sidecar_auth_proof};
