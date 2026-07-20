use super::{NetworkErrorCode, NetworkState, NetworkStateEvent};

pub struct NetworkOperation {
    operation_id: String,
    state: NetworkState,
    deadline_ms: u64,
    next_sequence: u64,
    events: Vec<NetworkStateEvent>,
}

impl NetworkOperation {
    pub fn new(operation_id: String, started_at_ms: u64, timeout_ms: u64) -> Result<Self, NetworkErrorCode> {
        if !valid_operation_id(&operation_id) || timeout_ms == 0 {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let mut operation = Self {
            operation_id,
            state: NetworkState::Disconnected,
            deadline_ms: started_at_ms.saturating_add(timeout_ms),
            next_sequence: 1,
            events: Vec::new(),
        };
        operation.record(None);
        Ok(operation)
    }

    pub const fn state(&self) -> NetworkState {
        self.state
    }

    pub fn events(&self) -> &[NetworkStateEvent] {
        &self.events
    }

    pub fn transition(&mut self, next: NetworkState, reason: Option<NetworkErrorCode>) -> Result<(), NetworkErrorCode> {
        self.state.transition_to(next)?;
        self.record(reason);
        Ok(())
    }

    pub fn cancel(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        if operation_id != self.operation_id {
            return Err(NetworkErrorCode::OperationCancelled);
        }
        self.terminate(NetworkErrorCode::OperationCancelled)
    }

    pub fn check_timeout(&mut self, now_ms: u64) -> Result<bool, NetworkErrorCode> {
        if now_ms < self.deadline_ms || self.state == NetworkState::Disconnected {
            return Ok(false);
        }
        self.terminate(NetworkErrorCode::OperationTimedOut)?;
        Ok(true)
    }

    fn terminate(&mut self, reason: NetworkErrorCode) -> Result<(), NetworkErrorCode> {
        match self.state {
            NetworkState::Disconnected => Ok(()),
            NetworkState::Error => self.transition(NetworkState::Disconnected, Some(reason)),
            NetworkState::Disconnecting => self.transition(NetworkState::Disconnected, Some(reason)),
            _ => {
                self.transition(NetworkState::Disconnecting, Some(reason))?;
                self.transition(NetworkState::Disconnected, Some(reason))
            }
        }
    }

    fn record(&mut self, reason: Option<NetworkErrorCode>) {
        self.events.push(NetworkStateEvent {
            sequence: self.next_sequence,
            operation_id: self.operation_id.clone(),
            state: self.state,
            reason,
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
    }
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric() || (index > 0 && matches!(character, '.' | '_' | ':' | '-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connecting_operation() -> Result<NetworkOperation, NetworkErrorCode> {
        let mut operation = NetworkOperation::new("operation.test".into(), 1_000, 500)?;
        for state in [
            NetworkState::Authenticating,
            NetworkState::FetchingConfig,
            NetworkState::PreparingTunnel,
            NetworkState::ConnectingPrimary,
        ] {
            operation.transition(state, None)?;
        }
        Ok(operation)
    }

    #[test]
    fn events_are_monotonic_and_preserve_structured_reasons() -> Result<(), NetworkErrorCode> {
        let mut operation = connecting_operation()?;
        operation.cancel("operation.test")?;
        assert_eq!(operation.state(), NetworkState::Disconnected);
        assert!(
            operation
                .events()
                .windows(2)
                .all(|pair| pair[1].sequence == pair[0].sequence + 1)
        );
        assert_eq!(
            operation.events().last().and_then(|event| event.reason),
            Some(NetworkErrorCode::OperationCancelled)
        );
        Ok(())
    }

    #[test]
    fn timeout_is_deterministic_and_idempotent_after_cleanup() -> Result<(), NetworkErrorCode> {
        let mut operation = connecting_operation()?;
        assert!(!operation.check_timeout(1_499)?);
        assert!(operation.check_timeout(1_500)?);
        assert_eq!(operation.state(), NetworkState::Disconnected);
        let event_count = operation.events().len();
        assert!(!operation.check_timeout(2_000)?);
        assert_eq!(operation.events().len(), event_count);
        assert_eq!(
            operation.events().last().and_then(|event| event.reason),
            Some(NetworkErrorCode::OperationTimedOut)
        );
        Ok(())
    }

    #[test]
    fn cancellation_for_another_operation_cannot_mutate_state() -> Result<(), NetworkErrorCode> {
        let mut operation = connecting_operation()?;
        let state = operation.state();
        let event_count = operation.events().len();
        assert_eq!(
            operation.cancel("operation.other"),
            Err(NetworkErrorCode::OperationCancelled)
        );
        assert_eq!(operation.state(), state);
        assert_eq!(operation.events().len(), event_count);
        Ok(())
    }

    #[test]
    fn invalid_identifiers_and_zero_timeout_fail_closed() {
        assert!(matches!(
            NetworkOperation::new("bad/id".into(), 0, 1),
            Err(NetworkErrorCode::InvalidConfiguration)
        ));
        assert!(matches!(
            NetworkOperation::new("operation.test".into(), 0, 0),
            Err(NetworkErrorCode::InvalidConfiguration)
        ));
    }
}
