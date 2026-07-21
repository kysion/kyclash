use std::collections::{HashMap, VecDeque};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::{
    IpcRequest, IpcResponse, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, SidecarHandshake, SidecarLaunchContext,
    SidecarLifecycleState, SidecarProcessStatus,
};

const COMMAND_CAPACITY: usize = 32;
const DIAGNOSTIC_CAPACITY: usize = 128;

#[async_trait]
pub trait AsyncProductionRuntime: Send + 'static {
    async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode>;
    async fn request(&mut self, request: IpcRequest, cancel: Arc<AtomicBool>) -> Result<IpcResponse, NetworkErrorCode>;
    async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode>;
    async fn stop(&mut self) -> Result<(), NetworkErrorCode>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionEventKind {
    Started,
    RequestCompleted,
    Cancelled,
    TimedOut,
    Restarting,
    CrashLoop,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEvent {
    pub sequence: u64,
    pub operation_id: Option<String>,
    pub kind: ProductionEventKind,
    pub error: Option<NetworkErrorCode>,
}

enum Command {
    Start {
        response: oneshot::Sender<Result<(), NetworkErrorCode>>,
    },
    Request {
        operation_id: String,
        request: IpcRequest,
        timeout: Duration,
        response: oneshot::Sender<Result<IpcResponse, NetworkErrorCode>>,
    },
    Poll {
        response: oneshot::Sender<Result<SidecarLifecycleState, NetworkErrorCode>>,
    },
    Health {
        operation_id: String,
        request: IpcRequest,
        timeout: Duration,
        response: oneshot::Sender<Result<IpcResponse, NetworkErrorCode>>,
    },
    Diagnostics {
        response: oneshot::Sender<Vec<ProductionEvent>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), NetworkErrorCode>>,
    },
}

#[derive(Clone)]
pub struct ProductionControllerHandle {
    commands: mpsc::Sender<Command>,
    cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl ProductionControllerHandle {
    pub async fn start(&self) -> Result<(), NetworkErrorCode> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Start { response: send })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }

    pub async fn request(
        &self,
        operation_id: String,
        request: IpcRequest,
        timeout: Duration,
    ) -> Result<IpcResponse, NetworkErrorCode> {
        if operation_id.is_empty() || timeout.is_zero() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Request {
                operation_id,
                request,
                timeout,
                response: send,
            })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }

    pub fn cancel(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let token = self
            .cancellations
            .lock()
            .get(operation_id)
            .cloned()
            .ok_or(NetworkErrorCode::OperationCancelled)?;
        token.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn poll(&self) -> Result<SidecarLifecycleState, NetworkErrorCode> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Poll { response: send })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }

    pub async fn sample_health(
        &self,
        operation_id: String,
        request: IpcRequest,
        timeout: Duration,
    ) -> Result<IpcResponse, NetworkErrorCode> {
        if !matches!(request.payload, super::IpcRequestPayload::SampleHealth) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Health {
                operation_id,
                request,
                timeout,
                response: send,
            })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }

    pub async fn diagnostics(&self) -> Result<Vec<ProductionEvent>, NetworkErrorCode> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Diagnostics { response: send })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)
    }

    pub async fn shutdown(&self) -> Result<(), NetworkErrorCode> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Shutdown { response: send })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }
}

pub fn spawn_production_controller<R: AsyncProductionRuntime>(
    runtime: R,
    context: SidecarLaunchContext,
    expected_auth_proof: String,
) -> ProductionControllerHandle {
    let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
    let cancellations = Arc::new(Mutex::new(HashMap::new()));
    let actor = ProductionController {
        runtime,
        context,
        expected_auth_proof,
        state: SidecarLifecycleState::Stopped,
        receiver,
        cancellations: Arc::clone(&cancellations),
        events: VecDeque::new(),
        next_sequence: 1,
        crashes: 0,
        retry_at: None,
    };
    tokio::spawn(actor.run());
    ProductionControllerHandle {
        commands,
        cancellations,
    }
}

struct ProductionController<R> {
    runtime: R,
    context: SidecarLaunchContext,
    expected_auth_proof: String,
    state: SidecarLifecycleState,
    receiver: mpsc::Receiver<Command>,
    cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    events: VecDeque<ProductionEvent>,
    next_sequence: u64,
    crashes: u8,
    retry_at: Option<Instant>,
}

impl<R: AsyncProductionRuntime> ProductionController<R> {
    async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            match command {
                Command::Start { response } => {
                    let _ = response.send(self.start().await);
                }
                Command::Request {
                    operation_id,
                    request,
                    timeout,
                    response,
                } => {
                    let _ = response.send(self.execute(operation_id, request, timeout).await);
                }
                Command::Poll { response } => {
                    let result = self.poll().await;
                    let _ = response.send(result);
                }
                Command::Health {
                    operation_id,
                    request,
                    timeout,
                    response,
                } => {
                    let _ = response.send(self.execute(operation_id, request, timeout).await);
                }
                Command::Diagnostics { response } => {
                    let _ = response.send(self.events.iter().cloned().collect());
                }
                Command::Shutdown { response } => {
                    let result = self.shutdown().await;
                    let _ = response.send(result);
                    break;
                }
            }
        }
        if self.state != SidecarLifecycleState::Stopped {
            let _ = self.runtime.stop().await;
        }
        self.cancellations.lock().clear();
    }

    async fn start(&mut self) -> Result<(), NetworkErrorCode> {
        if self.state != SidecarLifecycleState::Stopped {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.state = SidecarLifecycleState::Starting;
        let handshake = self.runtime.start(&self.context).await.inspect_err(|error| {
            self.state = SidecarLifecycleState::Stopped;
            self.record(ProductionEventKind::Failed, None, Some(*error));
        })?;
        if handshake.protocol_version != NETWORK_IPC_PROTOCOL_VERSION
            || handshake.instance_id != self.context.instance_id
            || handshake.auth_proof != self.expected_auth_proof
        {
            let _ = self.runtime.stop().await;
            self.state = SidecarLifecycleState::Stopped;
            self.record(
                ProductionEventKind::Failed,
                None,
                Some(NetworkErrorCode::AuthenticationFailed),
            );
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        self.state = SidecarLifecycleState::Running;
        self.retry_at = None;
        self.record(ProductionEventKind::Started, None, None);
        Ok(())
    }

    async fn execute(
        &mut self,
        operation_id: String,
        request: IpcRequest,
        timeout: Duration,
    ) -> Result<IpcResponse, NetworkErrorCode> {
        if self.state != SidecarLifecycleState::Running
            || request.validate_protocol().is_err()
            || self.cancellations.lock().contains_key(&operation_id)
        {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancellations
            .lock()
            .insert(operation_id.clone(), Arc::clone(&cancel));
        let result = tokio::time::timeout(timeout, self.runtime.request(request.clone(), cancel)).await;
        self.cancellations.lock().remove(&operation_id);
        match result {
            Err(_) => {
                let _ = self.runtime.stop().await;
                self.state = SidecarLifecycleState::Stopped;
                self.record(
                    ProductionEventKind::TimedOut,
                    Some(operation_id),
                    Some(NetworkErrorCode::OperationTimedOut),
                );
                Err(NetworkErrorCode::OperationTimedOut)
            }
            Ok(Err(error)) => {
                let kind = if error == NetworkErrorCode::OperationCancelled {
                    ProductionEventKind::Cancelled
                } else {
                    ProductionEventKind::Failed
                };
                self.record(kind, Some(operation_id), Some(error));
                Err(error)
            }
            Ok(Ok(response)) if response.request_id != request.request_id => {
                let _ = self.runtime.stop().await;
                self.state = SidecarLifecycleState::Stopped;
                self.record(
                    ProductionEventKind::Failed,
                    Some(operation_id),
                    Some(NetworkErrorCode::AuthenticationFailed),
                );
                Err(NetworkErrorCode::AuthenticationFailed)
            }
            Ok(Ok(response)) => {
                self.record(ProductionEventKind::RequestCompleted, Some(operation_id), None);
                Ok(response)
            }
        }
    }

    async fn poll(&mut self) -> Result<SidecarLifecycleState, NetworkErrorCode> {
        if self.state == SidecarLifecycleState::Backoff {
            if self.retry_at.is_some_and(|deadline| Instant::now() >= deadline) {
                self.state = SidecarLifecycleState::Stopped;
                self.record(ProductionEventKind::Restarting, None, None);
                self.start().await?;
            }
            return Ok(self.state);
        }
        if self.state != SidecarLifecycleState::Running {
            return Ok(self.state);
        }
        if matches!(self.runtime.status().await?, SidecarProcessStatus::Exited { .. }) {
            self.crashes = self.crashes.saturating_add(1);
            if self.crashes > 3 {
                self.state = SidecarLifecycleState::CrashLoop;
                self.record(
                    ProductionEventKind::CrashLoop,
                    None,
                    Some(NetworkErrorCode::SidecarUnavailable),
                );
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            self.state = SidecarLifecycleState::Backoff;
            let exponent = u32::from(self.crashes.saturating_sub(1).min(7));
            let delay_ms = 100_u64.saturating_mul(1_u64 << exponent).min(10_000);
            self.retry_at = Some(Instant::now() + Duration::from_millis(delay_ms));
            self.record(
                ProductionEventKind::Restarting,
                None,
                Some(NetworkErrorCode::SidecarUnavailable),
            );
        }
        Ok(self.state)
    }

    async fn shutdown(&mut self) -> Result<(), NetworkErrorCode> {
        self.runtime.stop().await?;
        self.state = SidecarLifecycleState::Stopped;
        self.cancellations.lock().clear();
        self.record(ProductionEventKind::Stopped, None, None);
        Ok(())
    }

    fn record(&mut self, kind: ProductionEventKind, operation_id: Option<String>, error: Option<NetworkErrorCode>) {
        if self.events.len() == DIAGNOSTIC_CAPACITY {
            self.events.pop_front();
        }
        self.events.push_back(ProductionEvent {
            sequence: self.next_sequence,
            operation_id,
            kind,
            error,
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::networking::{IpcRequestPayload, IpcResponsePayload};

    #[derive(Clone, Copy)]
    enum RequestMode {
        Success,
        WaitForCancel,
        Never,
        Stale,
        Failure,
    }

    struct FakeRuntime {
        mode: RequestMode,
        stopped: Arc<AtomicUsize>,
        exited: bool,
    }

    #[async_trait]
    impl AsyncProductionRuntime for FakeRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            Ok(SidecarHandshake {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: context.instance_id.clone(),
                auth_proof: "proof.test".into(),
            })
        }

        async fn request(
            &mut self,
            request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            match self.mode {
                RequestMode::WaitForCancel => loop {
                    if cancel.load(Ordering::Acquire) {
                        return Err(NetworkErrorCode::OperationCancelled);
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                },
                RequestMode::Never => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    unreachable!()
                }
                RequestMode::Failure => return Err(NetworkErrorCode::SidecarUnavailable),
                RequestMode::Success | RequestMode::Stale => {}
            }
            Ok(IpcResponse {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: if matches!(self.mode, RequestMode::Stale) {
                    "request.stale".into()
                } else {
                    request.request_id
                },
                result: Ok(IpcResponsePayload::Acknowledged),
            })
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            Ok(if self.exited {
                SidecarProcessStatus::Exited { success: false }
            } else {
                SidecarProcessStatus::Running
            })
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.stopped.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn request(request_id: &str) -> IpcRequest {
        IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: request_id.into(),
            payload: IpcRequestPayload::GetStatus,
        }
    }

    fn controller(mode: RequestMode) -> (ProductionControllerHandle, Arc<AtomicUsize>) {
        controller_with_exit(mode, false)
    }

    fn controller_with_exit(mode: RequestMode, exited: bool) -> (ProductionControllerHandle, Arc<AtomicUsize>) {
        let stopped = Arc::new(AtomicUsize::new(0));
        let runtime = FakeRuntime {
            mode,
            stopped: Arc::clone(&stopped),
            exited,
        };
        let context = SidecarLaunchContext::new("production.test".into(), vec![1; 32]).with_private_key(vec![2; 32]);
        (
            spawn_production_controller(runtime, context, "proof.test".into()),
            stopped,
        )
    }

    #[tokio::test]
    async fn health_poll_is_typed_and_crashes_reach_bounded_crash_loop() -> Result<(), NetworkErrorCode> {
        let (healthy, _) = controller(RequestMode::Success);
        healthy.start().await?;
        assert_eq!(
            healthy
                .sample_health(
                    "operation.health".into(),
                    request("request.not-health"),
                    Duration::from_secs(1)
                )
                .await,
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        let health_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.health".into(),
            payload: IpcRequestPayload::SampleHealth,
        };
        assert!(
            healthy
                .sample_health("operation.health".into(), health_request, Duration::from_secs(1))
                .await
                .is_ok()
        );
        healthy.shutdown().await?;

        let (crashing, _) = controller_with_exit(RequestMode::Success, true);
        crashing.start().await?;
        for delay in [110_u64, 210, 410] {
            assert_eq!(crashing.poll().await?, SidecarLifecycleState::Backoff);
            tokio::time::sleep(Duration::from_millis(delay)).await;
            assert_eq!(crashing.poll().await?, SidecarLifecycleState::Running);
        }
        assert_eq!(crashing.poll().await, Err(NetworkErrorCode::SidecarUnavailable));
        assert_eq!(crashing.poll().await?, SidecarLifecycleState::CrashLoop);
        let _ = crashing.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn correlates_requests_and_retains_redacted_monotonic_events() -> Result<(), NetworkErrorCode> {
        let (handle, _) = controller(RequestMode::Success);
        handle.start().await?;
        let response = handle
            .request("operation.one".into(), request("request.one"), Duration::from_secs(1))
            .await?;
        assert_eq!(response.request_id, "request.one");
        for index in 0..140 {
            let operation_id = format!("operation.ring.{index}");
            let request_id = format!("request.ring.{index}");
            handle
                .request(operation_id, request(&request_id), Duration::from_secs(1))
                .await?;
        }
        let events = handle.diagnostics().await?;
        assert_eq!(events.len(), DIAGNOSTIC_CAPACITY);
        assert!(events.windows(2).all(|pair| pair[1].sequence == pair[0].sequence + 1));
        assert!(
            events
                .iter()
                .all(|event| event.operation_id.as_deref() != Some("private-key"))
        );
        handle.shutdown().await
    }

    #[tokio::test]
    async fn cancellation_reaches_the_only_inflight_operation() -> Result<(), NetworkErrorCode> {
        let (handle, _) = controller(RequestMode::WaitForCancel);
        handle.start().await?;
        let requester = handle.clone();
        let pending = tokio::spawn(async move {
            requester
                .request(
                    "operation.cancel".into(),
                    request("request.cancel"),
                    Duration::from_secs(2),
                )
                .await
        });
        for _ in 0..100 {
            if handle.cancel("operation.cancel").is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            pending.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?,
            Err(NetworkErrorCode::OperationCancelled)
        );
        handle.shutdown().await
    }

    #[tokio::test]
    async fn timeout_stale_response_and_runtime_failure_fail_closed() -> Result<(), NetworkErrorCode> {
        for (mode, expected) in [
            (RequestMode::Never, NetworkErrorCode::OperationTimedOut),
            (RequestMode::Stale, NetworkErrorCode::AuthenticationFailed),
            (RequestMode::Failure, NetworkErrorCode::SidecarUnavailable),
        ] {
            let (handle, stopped) = controller(mode);
            handle.start().await?;
            assert_eq!(
                handle
                    .request(
                        "operation.fail".into(),
                        request("request.expected"),
                        Duration::from_millis(10)
                    )
                    .await,
                Err(expected)
            );
            if matches!(mode, RequestMode::Never | RequestMode::Stale) {
                assert_eq!(stopped.load(Ordering::Acquire), 1);
            }
            let _ = handle.shutdown().await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn dropping_every_handle_stops_the_owned_runtime() -> Result<(), NetworkErrorCode> {
        let (handle, stopped) = controller(RequestMode::Success);
        handle.start().await?;
        drop(handle);
        for _ in 0..100 {
            if stopped.load(Ordering::Acquire) != 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Err(NetworkErrorCode::OperationTimedOut)
    }
}
