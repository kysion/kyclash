use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use super::{NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarLifecycleState {
    Stopped,
    Starting,
    Running,
    Backoff,
    CrashLoop,
}

#[derive(PartialEq, Eq)]
pub struct SidecarLaunchContext {
    pub instance_id: String,
    auth_token: Vec<u8>,
    private_key: Vec<u8>,
}

impl std::fmt::Debug for SidecarLaunchContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SidecarLaunchContext")
            .field("instance_id", &self.instance_id)
            .field("auth_token", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl SidecarLaunchContext {
    pub const fn new(instance_id: String, auth_token: Vec<u8>) -> Self {
        Self {
            instance_id,
            auth_token,
            private_key: Vec::new(),
        }
    }

    pub fn with_private_key(mut self, private_key: Vec<u8>) -> Self {
        self.private_key = private_key;
        self
    }

    pub fn auth_token(&self) -> &[u8] {
        &self.auth_token
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

impl Drop for SidecarLaunchContext {
    fn drop(&mut self) {
        self.auth_token.zeroize();
        self.private_key.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarHandshake {
    pub protocol_version: u8,
    pub instance_id: String,
    pub auth_proof: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarProcessStatus {
    Running,
    Exited { success: bool },
}

pub trait SidecarRuntime {
    fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode>;
    fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode>;
    fn stop(&mut self) -> Result<(), NetworkErrorCode>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    pub max_restarts: usize,
    pub window_ms: u64,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window_ms: 60_000,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 30_000,
        }
    }
}

pub struct SidecarController<R> {
    runtime: R,
    policy: RestartPolicy,
    state: SidecarLifecycleState,
    context: SidecarLaunchContext,
    expected_auth_proof: String,
    restart_times: VecDeque<u64>,
    consecutive_failures: u32,
    retry_at_ms: Option<u64>,
}

impl<R: SidecarRuntime> SidecarController<R> {
    pub const fn new(
        runtime: R,
        policy: RestartPolicy,
        context: SidecarLaunchContext,
        expected_auth_proof: String,
    ) -> Self {
        Self {
            runtime,
            policy,
            state: SidecarLifecycleState::Stopped,
            context,
            expected_auth_proof,
            restart_times: VecDeque::new(),
            consecutive_failures: 0,
            retry_at_ms: None,
        }
    }

    pub const fn state(&self) -> SidecarLifecycleState {
        self.state
    }

    pub const fn retry_at_ms(&self) -> Option<u64> {
        self.retry_at_ms
    }

    pub fn start(&mut self, now_ms: u64) -> Result<(), NetworkErrorCode> {
        if !matches!(
            self.state,
            SidecarLifecycleState::Stopped | SidecarLifecycleState::Backoff
        ) {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.state = SidecarLifecycleState::Starting;
        let handshake = self.runtime.start(&self.context).inspect_err(|_| {
            self.state = SidecarLifecycleState::Stopped;
        })?;
        if handshake.protocol_version != NETWORK_IPC_PROTOCOL_VERSION {
            self.state = SidecarLifecycleState::Stopped;
            let _ = self.runtime.stop();
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if handshake.instance_id != self.context.instance_id || handshake.auth_proof != self.expected_auth_proof {
            self.state = SidecarLifecycleState::Stopped;
            let _ = self.runtime.stop();
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        self.state = SidecarLifecycleState::Running;
        self.retry_at_ms = None;
        self.prune_restart_window(now_ms);
        Ok(())
    }

    pub fn poll(&mut self, now_ms: u64) -> Result<(), NetworkErrorCode> {
        match self.state {
            SidecarLifecycleState::Running => match self.runtime.status()? {
                SidecarProcessStatus::Running => Ok(()),
                SidecarProcessStatus::Exited { .. } => self.record_crash(now_ms),
            },
            SidecarLifecycleState::Backoff if self.retry_at_ms.is_some_and(|retry_at| now_ms >= retry_at) => {
                self.start(now_ms)
            }
            SidecarLifecycleState::Stopped
            | SidecarLifecycleState::Starting
            | SidecarLifecycleState::Backoff
            | SidecarLifecycleState::CrashLoop => Ok(()),
        }
    }

    pub fn stop(&mut self) -> Result<(), NetworkErrorCode> {
        if matches!(
            self.state,
            SidecarLifecycleState::Running | SidecarLifecycleState::Starting
        ) {
            self.runtime.stop()?;
        }
        self.state = SidecarLifecycleState::Stopped;
        self.retry_at_ms = None;
        self.consecutive_failures = 0;
        self.restart_times.clear();
        Ok(())
    }

    fn record_crash(&mut self, now_ms: u64) -> Result<(), NetworkErrorCode> {
        self.prune_restart_window(now_ms);
        self.restart_times.push_back(now_ms);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.restart_times.len() > self.policy.max_restarts {
            self.state = SidecarLifecycleState::CrashLoop;
            self.retry_at_ms = None;
            return Err(NetworkErrorCode::SidecarUnavailable);
        }
        let exponent = self.consecutive_failures.saturating_sub(1).min(31);
        let delay = self
            .policy
            .initial_backoff_ms
            .saturating_mul(1_u64 << exponent)
            .min(self.policy.max_backoff_ms);
        self.state = SidecarLifecycleState::Backoff;
        self.retry_at_ms = Some(now_ms.saturating_add(delay));
        Ok(())
    }

    fn prune_restart_window(&mut self, now_ms: u64) {
        while self
            .restart_times
            .front()
            .is_some_and(|timestamp| now_ms.saturating_sub(*timestamp) > self.policy.window_ms)
        {
            self.restart_times.pop_front();
        }
        if self.restart_times.is_empty() {
            self.consecutive_failures = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeRuntime {
        running: bool,
        crash_on_poll: bool,
        bad_proof: bool,
        starts: usize,
    }

    impl SidecarRuntime for FakeRuntime {
        fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.running = true;
            self.starts += 1;
            Ok(SidecarHandshake {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: context.instance_id.clone(),
                auth_proof: if self.bad_proof { "invalid" } else { "proof.test" }.into(),
            })
        }

        fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            if self.crash_on_poll {
                self.running = false;
                self.crash_on_poll = false;
            }
            Ok(if self.running {
                SidecarProcessStatus::Running
            } else {
                SidecarProcessStatus::Exited { success: false }
            })
        }

        fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.running = false;
            Ok(())
        }
    }

    fn controller(runtime: FakeRuntime) -> SidecarController<FakeRuntime> {
        SidecarController::new(
            runtime,
            RestartPolicy {
                max_restarts: 2,
                window_ms: 10_000,
                initial_backoff_ms: 100,
                max_backoff_ms: 400,
            },
            SidecarLaunchContext::new("instance.test".into(), b"token-not-logged".to_vec()),
            "proof.test".into(),
        )
    }

    #[test]
    fn starts_authenticates_and_stops() -> Result<(), NetworkErrorCode> {
        let mut controller = controller(FakeRuntime::default());
        controller.start(0)?;
        assert_eq!(controller.state(), SidecarLifecycleState::Running);
        controller.stop()?;
        assert_eq!(controller.state(), SidecarLifecycleState::Stopped);
        Ok(())
    }

    #[test]
    fn rejects_invalid_handshake_proof() {
        let mut controller = controller(FakeRuntime {
            bad_proof: true,
            ..FakeRuntime::default()
        });
        assert_eq!(controller.start(0), Err(NetworkErrorCode::AuthenticationFailed));
        assert_eq!(controller.state(), SidecarLifecycleState::Stopped);
    }

    #[test]
    fn applies_bounded_backoff_and_opens_crash_loop() -> Result<(), NetworkErrorCode> {
        let mut controller = controller(FakeRuntime::default());
        controller.start(0)?;
        for (crash_at, retry_at) in [(10, 110), (120, 320)] {
            controller.runtime.crash_on_poll = true;
            controller.poll(crash_at)?;
            assert_eq!(controller.state(), SidecarLifecycleState::Backoff);
            assert_eq!(controller.retry_at_ms(), Some(retry_at));
            controller.poll(retry_at)?;
            assert_eq!(controller.state(), SidecarLifecycleState::Running);
        }
        controller.runtime.crash_on_poll = true;
        assert_eq!(controller.poll(330), Err(NetworkErrorCode::SidecarUnavailable));
        assert_eq!(controller.state(), SidecarLifecycleState::CrashLoop);
        Ok(())
    }
}
