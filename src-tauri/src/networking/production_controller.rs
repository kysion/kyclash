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
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    IpcRequest, IpcResponse, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, SidecarHandshake, SidecarLaunchContext,
    SidecarLifecycleState, SidecarProcessStatus,
};
#[cfg(unix)]
use super::{LocalProcessLauncher, SidecarRuntime as _, StdioSidecarLauncher, StdioSidecarRuntime};

const COMMAND_CAPACITY: usize = 32;
const DIAGNOSTIC_CAPACITY: usize = 128;
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

#[async_trait]
pub trait AsyncProductionRuntime: Send + 'static {
    async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode>;
    async fn request(&mut self, request: IpcRequest, cancel: Arc<AtomicBool>) -> Result<IpcResponse, NetworkErrorCode>;
    async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode>;
    /// Owns graceful shutdown plus any required forced termination and child
    /// reaping. The controller bounds how long it awaits this contract but has
    /// no runtime-specific process handle with which to kill a child itself.
    async fn stop(&mut self) -> Result<(), NetworkErrorCode>;
}

/// AsyncProductionRuntime adapter for a synchronous stdio sidecar launcher.
///
/// The injected launcher owns the child/session generation, stdio descriptors,
/// and exact stop/reap behavior.  Keeping that launcher type here is required
/// for the macOS tunnel broker: collapsing back to `LocalProcessLauncher`
/// would make the privileged broker seam unreachable from the production
/// controller.  This adapter only bridges the blocking protocol boundary into
/// Tokio and does not alter protocol-v2 framing.
#[cfg(unix)]
pub struct AsyncStdioSidecarRuntime<L: StdioSidecarLauncher = LocalProcessLauncher> {
    inner: StdioSidecarRuntime<L>,
}

#[cfg(unix)]
impl<L: StdioSidecarLauncher> AsyncStdioSidecarRuntime<L> {
    #[must_use]
    pub const fn new(inner: StdioSidecarRuntime<L>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn into_inner(self) -> StdioSidecarRuntime<L> {
        self.inner
    }
}

#[cfg(unix)]
#[async_trait]
impl<L> AsyncProductionRuntime for AsyncStdioSidecarRuntime<L>
where
    L: StdioSidecarLauncher + 'static,
{
    async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
        tokio::task::block_in_place(|| self.inner.start(context))
    }

    async fn request(&mut self, request: IpcRequest, cancel: Arc<AtomicBool>) -> Result<IpcResponse, NetworkErrorCode> {
        tokio::task::block_in_place(|| self.inner.request_cancellable(&request, cancel.as_ref()))
    }

    async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
        tokio::task::block_in_place(|| self.inner.status())
    }

    async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
        tokio::task::block_in_place(|| self.inner.stop())
    }
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

/// Positive proof that the controller can no longer own a sidecar child.
///
/// `NeverSpawned` is valid only for generation zero. `Reaped` is emitted only
/// after the runtime's exact stop/reap contract succeeds for the recorded
/// generation. A lifecycle label or a closed command channel is deliberately
/// not accepted as absence proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerAbsenceKind {
    NeverSpawned,
    Reaped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerRetirementReceipt {
    runtime_generation: u64,
    absence: ControllerAbsenceKind,
}

impl ControllerRetirementReceipt {
    #[must_use]
    pub const fn runtime_generation(self) -> u64 {
        self.runtime_generation
    }

    #[must_use]
    pub const fn absence(self) -> ControllerAbsenceKind {
        self.absence
    }
}

enum Command {
    Start {
        response: oneshot::Sender<Result<(), NetworkErrorCode>>,
    },
    Request {
        operation_id: String,
        request: IpcRequest,
        cancel: Arc<AtomicBool>,
        timeout: Duration,
        response: oneshot::Sender<Result<IpcResponse, NetworkErrorCode>>,
    },
    Poll {
        response: oneshot::Sender<Result<SidecarLifecycleState, NetworkErrorCode>>,
    },
    Health {
        operation_id: String,
        request: IpcRequest,
        cancel: Arc<AtomicBool>,
        timeout: Duration,
        response: oneshot::Sender<Result<IpcResponse, NetworkErrorCode>>,
    },
    Diagnostics {
        response: oneshot::Sender<Vec<ProductionEvent>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), NetworkErrorCode>>,
    },
    Retire {
        response: oneshot::Sender<Result<ControllerRetirementReceipt, NetworkErrorCode>>,
    },
}

#[derive(Clone)]
struct CancellationRegistration {
    request_id: String,
    cancellable: bool,
    token: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct ProductionControllerHandle {
    commands: mpsc::Sender<Command>,
    cancellations: Arc<Mutex<HashMap<String, CancellationRegistration>>>,
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
        request.validate_protocol()?;
        let permit = self
            .commands
            .reserve()
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let cancel = self.register_cancellation(&operation_id, &request)?;
        let (send, receive) = oneshot::channel();
        permit.send(Command::Request {
            operation_id: operation_id.clone(),
            request,
            cancel: Arc::clone(&cancel),
            timeout,
            response: send,
        });
        let result = receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable);
        self.remove_cancellation(&operation_id, &cancel);
        result?
    }

    pub fn cancel(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let registration = self
            .cancellations
            .lock()
            .get(operation_id)
            .cloned()
            .ok_or(NetworkErrorCode::OperationCancelled)?;
        if !registration.cancellable {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        debug_assert!(!registration.request_id.is_empty());
        registration.token.store(true, Ordering::Release);
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
        if operation_id.is_empty()
            || timeout.is_zero()
            || !matches!(&request.payload, super::IpcRequestPayload::SampleHealth)
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        request.validate_protocol()?;
        let permit = self
            .commands
            .reserve()
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let cancel = self.register_cancellation(&operation_id, &request)?;
        let (send, receive) = oneshot::channel();
        permit.send(Command::Health {
            operation_id: operation_id.clone(),
            request,
            cancel: Arc::clone(&cancel),
            timeout,
            response: send,
        });
        let result = receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable);
        self.remove_cancellation(&operation_id, &cancel);
        result?
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

    /// Permanently closes this exact controller generation after positive
    /// child-absence proof. Shutdown remains reusable; only retirement makes
    /// every later mutation sent through an old handle fail closed.
    pub async fn retire(&self) -> Result<ControllerRetirementReceipt, NetworkErrorCode> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Retire { response: send })
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        receive.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }

    fn register_cancellation(
        &self,
        operation_id: &str,
        request: &IpcRequest,
    ) -> Result<Arc<AtomicBool>, NetworkErrorCode> {
        let token = Arc::new(AtomicBool::new(false));
        let registration = CancellationRegistration {
            request_id: request.request_id.clone(),
            cancellable: matches!(
                &request.payload,
                super::IpcRequestPayload::ConnectTransport { .. } | super::IpcRequestPayload::SampleHealth
            ),
            token: Arc::clone(&token),
        };
        let mut cancellations = self.cancellations.lock();
        if cancellations.contains_key(operation_id) {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        cancellations.insert(operation_id.to_owned(), registration);
        drop(cancellations);
        Ok(token)
    }

    fn remove_cancellation(&self, operation_id: &str, token: &Arc<AtomicBool>) {
        let mut cancellations = self.cancellations.lock();
        if cancellations
            .get(operation_id)
            .is_some_and(|registration| Arc::ptr_eq(&registration.token, token))
        {
            cancellations.remove(operation_id);
        }
    }
}

pub fn spawn_production_controller<R: AsyncProductionRuntime>(
    runtime: R,
    context: SidecarLaunchContext,
    expected_auth_proof: String,
) -> ProductionControllerHandle {
    spawn_production_controller_with_stop_timeout(runtime, context, expected_auth_proof, STOP_TIMEOUT)
}

fn spawn_production_controller_with_stop_timeout<R: AsyncProductionRuntime>(
    runtime: R,
    context: SidecarLaunchContext,
    expected_auth_proof: String,
    stop_timeout: Duration,
) -> ProductionControllerHandle {
    let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
    let cancellations = Arc::new(Mutex::new(HashMap::new()));
    let actor = ProductionController {
        runtime,
        context: Some(context),
        expected_auth_proof: Zeroizing::new(expected_auth_proof),
        state: SidecarLifecycleState::Stopped,
        receiver,
        cancellations: Arc::clone(&cancellations),
        events: VecDeque::new(),
        next_sequence: 1,
        crashes: 0,
        retry_at: None,
        stop_timeout,
        runtime_generation: 0,
        absence: Some(ControllerAbsenceKind::NeverSpawned),
        retired: false,
    };
    tokio::spawn(actor.run());
    ProductionControllerHandle {
        commands,
        cancellations,
    }
}

struct ProductionController<R> {
    runtime: R,
    context: Option<SidecarLaunchContext>,
    expected_auth_proof: Zeroizing<String>,
    state: SidecarLifecycleState,
    receiver: mpsc::Receiver<Command>,
    cancellations: Arc<Mutex<HashMap<String, CancellationRegistration>>>,
    events: VecDeque<ProductionEvent>,
    next_sequence: u64,
    crashes: u8,
    retry_at: Option<Instant>,
    stop_timeout: Duration,
    runtime_generation: u64,
    absence: Option<ControllerAbsenceKind>,
    retired: bool,
}

impl<R: AsyncProductionRuntime> ProductionController<R> {
    async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            match command {
                Command::Start { response } => {
                    let result = if self.retired {
                        Err(NetworkErrorCode::InvalidStateTransition)
                    } else {
                        self.start(true).await
                    };
                    let _ = response.send(result);
                }
                Command::Request {
                    operation_id,
                    request,
                    cancel,
                    timeout,
                    response,
                } => {
                    let result = if self.retired {
                        Err(NetworkErrorCode::InvalidStateTransition)
                    } else {
                        self.execute(operation_id.clone(), request, Arc::clone(&cancel), timeout)
                            .await
                    };
                    self.remove_cancellation(&operation_id, &cancel);
                    let _ = response.send(result);
                }
                Command::Poll { response } => {
                    let result = if self.retired {
                        Err(NetworkErrorCode::InvalidStateTransition)
                    } else {
                        self.poll().await
                    };
                    let _ = response.send(result);
                }
                Command::Health {
                    operation_id,
                    request,
                    cancel,
                    timeout,
                    response,
                } => {
                    let result = if self.retired {
                        Err(NetworkErrorCode::InvalidStateTransition)
                    } else {
                        self.execute(operation_id.clone(), request, Arc::clone(&cancel), timeout)
                            .await
                    };
                    self.remove_cancellation(&operation_id, &cancel);
                    let _ = response.send(result);
                }
                Command::Diagnostics { response } => {
                    let _ = response.send(self.events.iter().cloned().collect());
                }
                Command::Shutdown { response } => {
                    let result = if self.retired {
                        Err(NetworkErrorCode::InvalidStateTransition)
                    } else {
                        self.shutdown().await
                    };
                    let _ = response.send(result);
                }
                Command::Retire { response } => {
                    let _ = response.send(self.retire());
                }
            }
        }
        if !self.retired && self.state != SidecarLifecycleState::Stopped {
            let _ = self.stop_runtime_bounded(None).await;
        }
        self.cancellations.lock().clear();
    }

    async fn start(&mut self, reset_crash_history: bool) -> Result<(), NetworkErrorCode> {
        if self.state != SidecarLifecycleState::Stopped {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.runtime_generation = self
            .runtime_generation
            .checked_add(1)
            .ok_or(NetworkErrorCode::InvalidStateTransition)?;
        self.absence = None;
        self.state = SidecarLifecycleState::Starting;
        let handshake = match self
            .runtime
            .start(self.context.as_ref().ok_or(NetworkErrorCode::InvalidStateTransition)?)
            .await
        {
            Ok(handshake) => handshake,
            Err(primary) => {
                // A runtime may fail after spawning but before returning a
                // handshake. Only its exact stop/reap contract can restore a
                // positive absence receipt for this attempted generation.
                let _ = self.stop_runtime_bounded(None).await;
                self.record(ProductionEventKind::Failed, None, Some(primary));
                return Err(primary);
            }
        };
        if handshake.protocol_version != NETWORK_IPC_PROTOCOL_VERSION {
            let _ = self.stop_runtime_bounded(None).await;
            self.record(
                ProductionEventKind::Failed,
                None,
                Some(NetworkErrorCode::UnsupportedProtocolVersion),
            );
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        let expected_instance = self
            .context
            .as_ref()
            .map(|context| context.instance_id.as_str())
            .ok_or(NetworkErrorCode::InvalidStateTransition)?;
        if handshake.instance_id != expected_instance || handshake.auth_proof != self.expected_auth_proof.as_str() {
            let _ = self.stop_runtime_bounded(None).await;
            self.record(
                ProductionEventKind::Failed,
                None,
                Some(NetworkErrorCode::AuthenticationFailed),
            );
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        self.state = SidecarLifecycleState::Running;
        self.retry_at = None;
        if reset_crash_history {
            self.crashes = 0;
        }
        self.record(ProductionEventKind::Started, None, None);
        Ok(())
    }

    async fn execute(
        &mut self,
        operation_id: String,
        request: IpcRequest,
        cancel: Arc<AtomicBool>,
        timeout: Duration,
    ) -> Result<IpcResponse, NetworkErrorCode> {
        if self.state != SidecarLifecycleState::Running {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        request.validate_protocol()?;
        let result = tokio::time::timeout(timeout, self.runtime.request(request.clone(), cancel)).await;
        match result {
            Err(_) => {
                let _ = self.stop_runtime_bounded(Some(operation_id.clone())).await;
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
                } else if error == NetworkErrorCode::OperationTimedOut {
                    let _ = self.stop_runtime_bounded(Some(operation_id.clone())).await;
                    ProductionEventKind::TimedOut
                } else {
                    let _ = self.stop_runtime_bounded(Some(operation_id.clone())).await;
                    ProductionEventKind::Failed
                };
                self.record(kind, Some(operation_id), Some(error));
                Err(error)
            }
            Ok(Ok(response)) => {
                if let Err(error) = response.validate_protocol(&request) {
                    let _ = self.stop_runtime_bounded(Some(operation_id.clone())).await;
                    self.record(ProductionEventKind::Failed, Some(operation_id), Some(error));
                    return Err(error);
                }
                let response_error = response.result.as_ref().err().map(|error| error.code);
                self.record(
                    ProductionEventKind::RequestCompleted,
                    Some(operation_id),
                    response_error,
                );
                Ok(response)
            }
        }
    }

    async fn poll(&mut self) -> Result<SidecarLifecycleState, NetworkErrorCode> {
        if self.state == SidecarLifecycleState::Backoff {
            if self.retry_at.is_some_and(|deadline| Instant::now() >= deadline) {
                self.state = SidecarLifecycleState::Stopped;
                self.record(ProductionEventKind::Restarting, None, None);
                self.start(false).await?;
            }
            return Ok(self.state);
        }
        if self.state != SidecarLifecycleState::Running {
            return Ok(self.state);
        }
        let runtime_status = match self.runtime.status().await {
            Ok(status) => status,
            Err(error) => {
                let _ = self.stop_runtime_bounded(None).await;
                self.record(ProductionEventKind::Failed, None, Some(error));
                return Err(error);
            }
        };
        match runtime_status {
            SidecarProcessStatus::Running => {
                // A successfully restarted process must be observed alive on a
                // later status poll before its consecutive-crash history is
                // cleared. Immediate restart/exit cycles therefore still
                // converge on CrashLoop, while independent later crashes do not
                // accumulate forever.
                self.crashes = 0;
                self.absence = None;
            }
            SidecarProcessStatus::Exited { .. } => {
                // `Exited` is returned only after the runtime observes and
                // reaps its exact owned child handle.
                self.absence = Some(ControllerAbsenceKind::Reaped);
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
        }
        Ok(self.state)
    }

    async fn shutdown(&mut self) -> Result<(), NetworkErrorCode> {
        let stop_result = self.stop_runtime_bounded(None).await;
        self.crashes = 0;
        self.retry_at = None;
        self.cancellations.lock().clear();
        match stop_result {
            Ok(()) => {
                self.record(ProductionEventKind::Stopped, None, None);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn stop_runtime_bounded(&mut self, operation_id: Option<String>) -> Result<(), NetworkErrorCode> {
        // Graceful termination, forced termination, and child reaping remain
        // the AsyncProductionRuntime implementation's responsibility. The
        // generic actor bounds that contract so a defective runtime cannot
        // block every later lifecycle command indefinitely.
        let result = match tokio::time::timeout(self.stop_timeout, self.runtime.stop()).await {
            Ok(result) => result,
            Err(_) => Err(NetworkErrorCode::OperationTimedOut),
        };
        if let Err(error) = result {
            self.absence = None;
            self.state = SidecarLifecycleState::CrashLoop;
            self.record(ProductionEventKind::Failed, operation_id, Some(error));
        } else {
            self.absence = Some(if self.runtime_generation == 0 {
                ControllerAbsenceKind::NeverSpawned
            } else {
                ControllerAbsenceKind::Reaped
            });
            self.state = SidecarLifecycleState::Stopped;
        }
        result
    }

    fn retire(&mut self) -> Result<ControllerRetirementReceipt, NetworkErrorCode> {
        if self.retired || self.state != SidecarLifecycleState::Stopped || !self.cancellations.lock().is_empty() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let absence = self.absence.ok_or(NetworkErrorCode::SidecarUnavailable)?;
        if (self.runtime_generation == 0) != (absence == ControllerAbsenceKind::NeverSpawned) {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.retired = true;
        self.retry_at = None;
        // Old service/controller Arcs may remain alive indefinitely. Retire
        // must therefore destroy secrets now instead of waiting for actor
        // teardown when the final handle eventually drops.
        drop(self.context.take());
        self.expected_auth_proof.zeroize();
        self.expected_auth_proof.clear();
        if self.context.is_some() || !self.expected_auth_proof.is_empty() {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(ControllerRetirementReceipt {
            runtime_generation: self.runtime_generation,
            absence,
        })
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

    fn remove_cancellation(&self, operation_id: &str, token: &Arc<AtomicBool>) {
        let mut cancellations = self.cancellations.lock();
        if cancellations
            .get(operation_id)
            .is_some_and(|registration| Arc::ptr_eq(&registration.token, token))
        {
            cancellations.remove(operation_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    #[cfg(unix)]
    use crate::networking::SidecarProcessControl;
    use crate::networking::{IpcRequestPayload, IpcResponsePayload};

    #[cfg(unix)]
    struct RejectingLauncher {
        launches: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
    impl StdioSidecarLauncher for RejectingLauncher {
        fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode> {
            assert_eq!(generation, 1, "first broker-style launch must use generation one");
            self.launches.fetch_add(1, Ordering::AcqRel);
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    #[derive(Clone, Copy)]
    enum RequestMode {
        Success,
        DelayedSuccess,
        WaitForCancel,
        Never,
        Stale,
        WrongVersion,
        WrongHandshakeVersion,
        StatusFailure,
        Failure,
    }

    struct FakeRuntime {
        mode: RequestMode,
        stopped: Arc<AtomicUsize>,
        exited: Arc<AtomicBool>,
        instance_id: String,
        hang_stop: bool,
    }

    struct QueueBlockingRuntime {
        request_entries: Arc<AtomicUsize>,
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_stdio_adapter_preserves_the_injected_launcher() -> Result<(), NetworkErrorCode> {
        let launches = Arc::new(AtomicUsize::new(0));
        let runtime = StdioSidecarRuntime::with_launcher(
            std::path::PathBuf::from("/fixed-broker-policy"),
            RejectingLauncher {
                launches: Arc::clone(&launches),
            },
        );
        let mut adapter = AsyncStdioSidecarRuntime::new(runtime);
        let context =
            SidecarLaunchContext::new("production.broker-test".into(), vec![1; 32]).with_private_key(vec![2; 32]);

        assert_eq!(
            AsyncProductionRuntime::start(&mut adapter, &context).await,
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(launches.load(Ordering::Acquire), 1);

        // This type assertion is the regression gate: the async production
        // adapter must return the exact injected launcher rather than silently
        // narrowing the runtime back to `LocalProcessLauncher`.
        let _: StdioSidecarRuntime<RejectingLauncher> = adapter.into_inner();
        Ok(())
    }

    #[async_trait]
    impl AsyncProductionRuntime for QueueBlockingRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            Ok(SidecarHandshake {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: context.instance_id.clone(),
                auth_proof: "proof.test".into(),
            })
        }

        async fn request(
            &mut self,
            _request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            self.request_entries.fetch_add(1, Ordering::AcqRel);
            loop {
                if cancel.load(Ordering::Acquire) {
                    return Err(NetworkErrorCode::OperationCancelled);
                }
                tokio::task::yield_now().await;
            }
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            Ok(SidecarProcessStatus::Running)
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            Ok(())
        }
    }

    #[async_trait]
    impl AsyncProductionRuntime for FakeRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.instance_id.clone_from(&context.instance_id);
            Ok(SidecarHandshake {
                protocol_version: if matches!(self.mode, RequestMode::WrongHandshakeVersion) {
                    NETWORK_IPC_PROTOCOL_VERSION - 1
                } else {
                    NETWORK_IPC_PROTOCOL_VERSION
                },
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
                RequestMode::DelayedSuccess => tokio::time::sleep(Duration::from_millis(50)).await,
                RequestMode::Success
                | RequestMode::Stale
                | RequestMode::WrongVersion
                | RequestMode::WrongHandshakeVersion
                | RequestMode::StatusFailure => {}
            }
            let result = match request.payload {
                IpcRequestPayload::GetStatus => Ok(IpcResponsePayload::Status(super::super::NetworkStatus {
                    state: super::super::NetworkState::Disconnected,
                    active_profile_id: None,
                    active_transport: None,
                    last_error: None,
                })),
                IpcRequestPayload::ApplyProfile(_) => Ok(IpcResponsePayload::Acknowledged),
                IpcRequestPayload::PrepareTunnel => {
                    Ok(IpcResponsePayload::TunnelPrepared(super::super::TunnelDeviceFacts {
                        interface_name: "utun42".into(),
                        mtu: 1420,
                        has_ipv4: true,
                        has_ipv6: true,
                        instance_id: self.instance_id.clone(),
                        operation_id: request.request_id.clone(),
                    }))
                }
                IpcRequestPayload::ConnectTransport { transport } => {
                    Ok(IpcResponsePayload::Status(super::super::NetworkStatus {
                        state: if transport == super::super::TransportKind::Quic {
                            super::super::NetworkState::ConnectedPrimary
                        } else {
                            super::super::NetworkState::DegradedFallback
                        },
                        active_profile_id: Some("profile.test".into()),
                        active_transport: Some(transport),
                        last_error: None,
                    }))
                }
                IpcRequestPayload::DisconnectTransport => Ok(IpcResponsePayload::Status(super::super::NetworkStatus {
                    state: super::super::NetworkState::PreparingTunnel,
                    active_profile_id: Some("profile.test".into()),
                    active_transport: None,
                    last_error: None,
                })),
                IpcRequestPayload::StopTunnel => Ok(IpcResponsePayload::Status(super::super::NetworkStatus {
                    state: super::super::NetworkState::Disconnected,
                    active_profile_id: Some("profile.test".into()),
                    active_transport: None,
                    last_error: None,
                })),
                IpcRequestPayload::SampleHealth => Ok(IpcResponsePayload::Health(super::super::NetworkHealth {
                    reachable: true,
                    latency_ms: 1,
                    jitter_ms: 0,
                    loss_percent: 0,
                })),
                IpcRequestPayload::Connect => Ok(IpcResponsePayload::Status(super::super::NetworkStatus {
                    state: super::super::NetworkState::ConnectedPrimary,
                    active_profile_id: Some("profile.test".into()),
                    active_transport: Some(super::super::TransportKind::Quic),
                    last_error: None,
                })),
                IpcRequestPayload::Disconnect => Ok(IpcResponsePayload::Acknowledged),
                IpcRequestPayload::Cancel { target_request_id } => {
                    Ok(IpcResponsePayload::CancelAccepted { target_request_id })
                }
            };
            Ok(IpcResponse {
                protocol_version: if matches!(self.mode, RequestMode::WrongVersion) {
                    NETWORK_IPC_PROTOCOL_VERSION + 1
                } else {
                    NETWORK_IPC_PROTOCOL_VERSION
                },
                request_id: if matches!(self.mode, RequestMode::Stale) {
                    "request.stale".into()
                } else {
                    request.request_id
                },
                result,
            })
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            if matches!(self.mode, RequestMode::StatusFailure) {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            Ok(if self.exited.load(Ordering::Acquire) {
                SidecarProcessStatus::Exited { success: false }
            } else {
                SidecarProcessStatus::Running
            })
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.stopped.fetch_add(1, Ordering::AcqRel);
            if self.hang_stop {
                std::future::pending::<()>().await;
            }
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

    fn connect_request(request_id: &str) -> IpcRequest {
        IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: request_id.into(),
            payload: IpcRequestPayload::ConnectTransport {
                transport: super::super::TransportKind::Quic,
            },
        }
    }

    fn controller(mode: RequestMode) -> (ProductionControllerHandle, Arc<AtomicUsize>) {
        controller_with_exit(mode, false)
    }

    fn controller_with_exit(mode: RequestMode, exited: bool) -> (ProductionControllerHandle, Arc<AtomicUsize>) {
        let (handle, stopped, _) = controller_with_exit_control(mode, exited);
        (handle, stopped)
    }

    fn controller_with_exit_control(
        mode: RequestMode,
        exited: bool,
    ) -> (ProductionControllerHandle, Arc<AtomicUsize>, Arc<AtomicBool>) {
        controller_with_stop(mode, exited, false, STOP_TIMEOUT)
    }

    fn controller_with_stop(
        mode: RequestMode,
        exited: bool,
        hang_stop: bool,
        stop_timeout: Duration,
    ) -> (ProductionControllerHandle, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let stopped = Arc::new(AtomicUsize::new(0));
        let exited = Arc::new(AtomicBool::new(exited));
        let runtime = FakeRuntime {
            mode,
            stopped: Arc::clone(&stopped),
            exited: Arc::clone(&exited),
            instance_id: String::new(),
            hang_stop,
        };
        let context = SidecarLaunchContext::new("production.test".into(), vec![1; 32]).with_private_key(vec![2; 32]);
        (
            spawn_production_controller_with_stop_timeout(runtime, context, "proof.test".into(), stop_timeout),
            stopped,
            exited,
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
    async fn cancellation_reaches_the_exact_queued_or_inflight_health_operation() -> Result<(), NetworkErrorCode> {
        let (handle, _) = controller(RequestMode::WaitForCancel);
        handle.start().await?;
        let requester = handle.clone();
        let pending = tokio::spawn(async move {
            requester
                .sample_health(
                    "operation.cancel".into(),
                    IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: "request.cancel".into(),
                        payload: IpcRequestPayload::SampleHealth,
                    },
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
    async fn aborting_a_queue_blocked_sender_leaves_no_ghost_cancellation_registration() -> Result<(), NetworkErrorCode>
    {
        let request_entries = Arc::new(AtomicUsize::new(0));
        let context =
            SidecarLaunchContext::new("production.queue-test".into(), vec![1; 32]).with_private_key(vec![2; 32]);
        let handle = spawn_production_controller(
            QueueBlockingRuntime {
                request_entries: Arc::clone(&request_entries),
            },
            context,
            "proof.test".into(),
        );
        handle.start().await?;

        let blocker_handle = handle.clone();
        let blocker = tokio::spawn(async move {
            blocker_handle
                .request(
                    "operation.queue-blocker".into(),
                    connect_request("request.queue-blocker"),
                    Duration::from_secs(2),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while request_entries.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| NetworkErrorCode::OperationTimedOut)?;

        let mut queued_responses = Vec::with_capacity(COMMAND_CAPACITY);
        for _ in 0..COMMAND_CAPACITY {
            let (response, receive) = oneshot::channel();
            handle
                .commands
                .try_send(Command::Poll { response })
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            queued_responses.push(receive);
        }
        assert_eq!(handle.commands.capacity(), 0, "command queue must be full");

        let blocked_handle = handle.clone();
        let (entered_send, entered_receive) = oneshot::channel();
        let blocked_sender = tokio::spawn(async move {
            let _ = entered_send.send(());
            blocked_handle
                .request(
                    "operation.queue-abort".into(),
                    connect_request("request.queue-abort.first"),
                    Duration::from_secs(2),
                )
                .await
        });
        entered_receive
            .await
            .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        tokio::task::yield_now().await;
        assert!(
            !blocked_sender.is_finished(),
            "sender must be blocked on queue capacity"
        );
        assert!(
            !handle.cancellations.lock().contains_key("operation.queue-abort"),
            "a sender waiting for queue capacity must not register cancellation"
        );

        blocked_sender.abort();
        let join_error = match blocked_sender.await {
            Err(error) => error,
            Ok(_) => return Err(NetworkErrorCode::InvalidStateTransition),
        };
        assert!(join_error.is_cancelled());
        assert!(
            !handle.cancellations.lock().contains_key("operation.queue-abort"),
            "aborted sender must not leave a ghost cancellation registration"
        );

        handle.cancel("operation.queue-blocker")?;
        assert_eq!(
            blocker.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?,
            Err(NetworkErrorCode::OperationCancelled)
        );
        for response in queued_responses {
            assert_eq!(
                response.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)??,
                SidecarLifecycleState::Running
            );
        }

        let retry_handle = handle.clone();
        let retry = tokio::spawn(async move {
            retry_handle
                .request(
                    "operation.queue-abort".into(),
                    connect_request("request.queue-abort.retry"),
                    Duration::from_secs(2),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while request_entries.load(Ordering::Acquire) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| NetworkErrorCode::OperationTimedOut)?;
        assert!(handle.cancellations.lock().contains_key("operation.queue-abort"));
        handle.cancel("operation.queue-abort")?;
        assert_eq!(
            retry.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?,
            Err(NetworkErrorCode::OperationCancelled)
        );
        assert!(!handle.cancellations.lock().contains_key("operation.queue-abort"));
        handle.shutdown().await
    }

    #[tokio::test]
    async fn noncancellable_request_rejects_cancel_without_killing_runtime() -> Result<(), NetworkErrorCode> {
        let (handle, stopped) = controller(RequestMode::DelayedSuccess);
        handle.start().await?;
        let requester = handle.clone();
        let pending = tokio::spawn(async move {
            requester
                .request(
                    "operation.noncancel".into(),
                    request("request.noncancel"),
                    Duration::from_secs(1),
                )
                .await
        });
        let mut observed_registration = false;
        for _ in 0..100 {
            match handle.cancel("operation.noncancel") {
                Err(NetworkErrorCode::OperationCancelled) => tokio::task::yield_now().await,
                result => {
                    assert_eq!(result, Err(NetworkErrorCode::InvalidStateTransition));
                    observed_registration = true;
                    break;
                }
            }
        }
        assert!(
            observed_registration,
            "request was never registered for cancellation policy"
        );
        assert!(pending.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?.is_ok());
        assert_eq!(stopped.load(Ordering::Acquire), 0);
        assert_eq!(handle.poll().await?, SidecarLifecycleState::Running);
        handle.shutdown().await
    }

    #[tokio::test]
    async fn timeout_stale_wrong_version_and_runtime_failure_fail_closed() -> Result<(), NetworkErrorCode> {
        for (mode, expected) in [
            (RequestMode::Never, NetworkErrorCode::OperationTimedOut),
            (RequestMode::Stale, NetworkErrorCode::AuthenticationFailed),
            (RequestMode::WrongVersion, NetworkErrorCode::UnsupportedProtocolVersion),
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
            assert_eq!(stopped.load(Ordering::Acquire), 1);
            assert_eq!(handle.poll().await?, SidecarLifecycleState::Stopped);
            assert_eq!(
                handle
                    .request(
                        "operation.after-fatal".into(),
                        request("request.after-fatal"),
                        Duration::from_secs(1)
                    )
                    .await,
                Err(NetworkErrorCode::InvalidStateTransition)
            );
            assert_eq!(stopped.load(Ordering::Acquire), 1);
            let _ = handle.shutdown().await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn handshake_and_status_protocol_failures_stop_before_any_further_ipc() -> Result<(), NetworkErrorCode> {
        let (wrong_handshake, stopped) = controller(RequestMode::WrongHandshakeVersion);
        assert_eq!(
            wrong_handshake.start().await,
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
        assert_eq!(stopped.load(Ordering::Acquire), 1);
        assert_eq!(wrong_handshake.poll().await?, SidecarLifecycleState::Stopped);

        let (status_failure, stopped) = controller(RequestMode::StatusFailure);
        status_failure.start().await?;
        assert_eq!(status_failure.poll().await, Err(NetworkErrorCode::SidecarUnavailable));
        assert_eq!(stopped.load(Ordering::Acquire), 1);
        assert_eq!(status_failure.poll().await?, SidecarLifecycleState::Stopped);
        assert_eq!(
            status_failure
                .request(
                    "operation.after-status-fatal".into(),
                    request("request.after-status-fatal"),
                    Duration::from_secs(1),
                )
                .await,
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        Ok(())
    }

    #[tokio::test]
    async fn stable_restarts_clear_consecutive_crash_history() -> Result<(), NetworkErrorCode> {
        let (handle, _, exited) = controller_with_exit_control(RequestMode::Success, true);
        handle.start().await?;
        for _ in 0..5 {
            assert_eq!(handle.poll().await?, SidecarLifecycleState::Backoff);
            exited.store(false, Ordering::Release);
            tokio::time::sleep(Duration::from_millis(110)).await;
            assert_eq!(handle.poll().await?, SidecarLifecycleState::Running);
            assert_eq!(handle.poll().await?, SidecarLifecycleState::Running);
            exited.store(true, Ordering::Release);
        }
        exited.store(false, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(110)).await;
        assert_eq!(handle.poll().await?, SidecarLifecycleState::Running);
        handle.shutdown().await
    }

    #[tokio::test]
    async fn shutdown_keeps_the_controller_available_for_a_new_session() -> Result<(), NetworkErrorCode> {
        let (handle, stopped) = controller(RequestMode::Success);
        for index in 0..2 {
            handle.start().await?;
            let request_id = format!("request.reuse.{index}");
            let response = handle
                .request(
                    format!("operation.reuse.{index}"),
                    request(&request_id),
                    Duration::from_secs(1),
                )
                .await?;
            assert_eq!(response.request_id, request_id);
            handle.shutdown().await?;
            assert_eq!(handle.poll().await?, SidecarLifecycleState::Stopped);
        }
        assert_eq!(stopped.load(Ordering::Acquire), 2);
        Ok(())
    }

    #[tokio::test]
    async fn hanging_runtime_stop_is_bounded_and_never_claims_reusable_stopped() -> Result<(), NetworkErrorCode> {
        let (handle, stopped, _) = controller_with_stop(RequestMode::Success, false, true, Duration::from_millis(20));
        handle.start().await?;
        let shutdown = tokio::time::timeout(Duration::from_secs(1), handle.shutdown())
            .await
            .map_err(|_| NetworkErrorCode::OperationTimedOut)?;
        assert_eq!(shutdown, Err(NetworkErrorCode::OperationTimedOut));
        assert_eq!(handle.poll().await?, SidecarLifecycleState::CrashLoop);
        assert_eq!(stopped.load(Ordering::Acquire), 1);
        assert!(handle.diagnostics().await?.iter().any(|event| {
            event.kind == ProductionEventKind::Failed && event.error == Some(NetworkErrorCode::OperationTimedOut)
        }));
        assert_eq!(handle.start().await, Err(NetworkErrorCode::InvalidStateTransition));
        assert_eq!(handle.retire().await, Err(NetworkErrorCode::InvalidStateTransition));
        Ok(())
    }

    #[tokio::test]
    async fn never_spawned_controller_retires_with_positive_zero_generation_absence() -> Result<(), NetworkErrorCode> {
        let (handle, stopped) = controller(RequestMode::Success);
        let retained = handle.clone();
        assert_eq!(
            handle.retire().await?,
            ControllerRetirementReceipt {
                runtime_generation: 0,
                absence: ControllerAbsenceKind::NeverSpawned,
            }
        );
        assert_eq!(stopped.load(Ordering::Acquire), 0);
        assert_eq!(retained.start().await, Err(NetworkErrorCode::InvalidStateTransition));
        assert_eq!(retained.shutdown().await, Err(NetworkErrorCode::InvalidStateTransition));
        assert_eq!(retained.poll().await, Err(NetworkErrorCode::InvalidStateTransition));
        assert!(retained.diagnostics().await?.is_empty());
        assert_eq!(retained.retire().await, Err(NetworkErrorCode::InvalidStateTransition));
        Ok(())
    }

    #[tokio::test]
    async fn exact_reap_receipt_terminalizes_every_retained_handle() -> Result<(), NetworkErrorCode> {
        let (handle, stopped) = controller(RequestMode::Success);
        let retained = handle.clone();
        handle.start().await?;
        handle.shutdown().await?;
        assert_eq!(
            handle.retire().await?,
            ControllerRetirementReceipt {
                runtime_generation: 1,
                absence: ControllerAbsenceKind::Reaped,
            }
        );
        assert_eq!(stopped.load(Ordering::Acquire), 1);
        assert_eq!(retained.start().await, Err(NetworkErrorCode::InvalidStateTransition));
        assert_eq!(
            retained
                .request(
                    "operation.retired".into(),
                    request("request.retired"),
                    Duration::from_secs(1),
                )
                .await,
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        assert!(
            retained
                .diagnostics()
                .await?
                .iter()
                .any(|event| event.kind == ProductionEventKind::Stopped)
        );
        Ok(())
    }

    #[tokio::test]
    async fn reusable_shutdowns_advance_the_exact_runtime_generation_before_retirement() -> Result<(), NetworkErrorCode>
    {
        let (handle, stopped) = controller(RequestMode::Success);
        for _ in 0..2 {
            handle.start().await?;
            handle.shutdown().await?;
        }
        assert_eq!(
            handle.retire().await?,
            ControllerRetirementReceipt {
                runtime_generation: 2,
                absence: ControllerAbsenceKind::Reaped,
            }
        );
        assert_eq!(stopped.load(Ordering::Acquire), 2);
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

#[cfg(all(test, unix))]
mod stdio_adapter_tests {
    #[cfg(feature = "networking-dev")]
    use std::time::{Duration, Instant};
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::{
        AsyncProductionRuntime as _, AsyncStdioSidecarRuntime, IpcRequest, NETWORK_IPC_PROTOCOL_VERSION,
        NetworkErrorCode, SidecarLaunchContext, StdioSidecarRuntime,
    };
    use crate::networking::IpcRequestPayload;
    #[cfg(feature = "networking-dev")]
    use crate::networking::{IpcResponsePayload, NetworkState, TransportKind};

    fn context() -> SidecarLaunchContext {
        SidecarLaunchContext::new("adapter.test".into(), vec![0x11; 32]).with_private_key(vec![0x22; 32])
    }

    fn runtime() -> AsyncStdioSidecarRuntime {
        AsyncStdioSidecarRuntime::new(StdioSidecarRuntime::new(PathBuf::from(
            "/var/empty/kyclash-sidecar-does-not-exist",
        )))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridges_missing_sidecar_without_blocking_or_panicking() {
        let mut runtime = runtime();
        assert_eq!(
            runtime.start(&context()).await,
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(runtime.stop().await, Ok(()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn preloaded_cancellation_only_short_circuits_cancellable_requests() {
        let cancel = Arc::new(AtomicBool::new(true));

        let mut cancellable_runtime = runtime();
        let cancellable_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.cancel.connect".into(),
            payload: IpcRequestPayload::ConnectTransport {
                transport: crate::networking::TransportKind::Quic,
            },
        };
        assert_eq!(
            cancellable_runtime
                .request(cancellable_request, Arc::clone(&cancel))
                .await,
            Err(NetworkErrorCode::OperationCancelled)
        );

        let mut noncancellable_runtime = runtime();
        let noncancellable_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.cancel.status".into(),
            payload: IpcRequestPayload::GetStatus,
        };
        assert_eq!(
            noncancellable_runtime
                .request(noncancellable_request, Arc::clone(&cancel))
                .await,
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert!(cancel.load(Ordering::Acquire));
    }

    #[cfg(feature = "networking-dev")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_reaches_actual_blocked_child_and_preserves_correlation() -> Result<(), NetworkErrorCode> {
        let Ok(executable) = std::env::var("KYCLASH_NETWORK_LAB_SIDECAR_BIN") else {
            return Ok(());
        };
        let context =
            SidecarLaunchContext::new("adapter_actual_cancel".into(), vec![0x31; 32]).with_private_key(vec![0x32; 32]);
        let mut stdio = StdioSidecarRuntime::new(executable.into()).with_response_timeout(Duration::from_secs(5));
        let handshake = tokio::task::block_in_place(|| stdio.start_lab(&context))?;
        let mut profile = handshake.lab_profile;
        profile
            .transports
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.transport == TransportKind::Quic)
            .ok_or(NetworkErrorCode::InvalidConfiguration)?
            .url = handshake.cancel_endpoint;
        profile.validate()?;

        let mut runtime = AsyncStdioSidecarRuntime::new(stdio);
        for (request_id, payload) in [
            (
                "request.adapter.profile",
                IpcRequestPayload::ApplyProfile(Box::new(profile)),
            ),
            ("request.adapter.prepare", IpcRequestPayload::PrepareTunnel),
        ] {
            let response = runtime
                .request(
                    IpcRequest {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: request_id.into(),
                        payload,
                    },
                    Arc::new(AtomicBool::new(false)),
                )
                .await?;
            assert!(response.result.is_ok());
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_from_controller = Arc::clone(&cancel);
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_from_controller.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let cancelled = runtime
            .request(
                IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.adapter.connect".into(),
                    payload: IpcRequestPayload::ConnectTransport {
                        transport: TransportKind::Quic,
                    },
                },
                cancel,
            )
            .await;
        canceller.await.map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        assert_eq!(cancelled, Err(NetworkErrorCode::OperationCancelled));
        assert!(started.elapsed() < Duration::from_secs(5));

        let after_cancel = runtime
            .request(
                IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.adapter.status".into(),
                    payload: IpcRequestPayload::GetStatus,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .await?;
        assert!(matches!(
            after_cancel.result,
            Ok(IpcResponsePayload::Status(status))
                if status.state == NetworkState::PreparingTunnel && status.active_transport.is_none()
        ));

        let stopped = runtime
            .request(
                IpcRequest {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: "request.adapter.stop".into(),
                    payload: IpcRequestPayload::StopTunnel,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .await?;
        assert!(stopped.result.is_ok());
        runtime.stop().await
    }
}
