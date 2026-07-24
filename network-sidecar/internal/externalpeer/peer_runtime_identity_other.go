//go:build !darwin

package externalpeer

func observeCurrentPeerRuntime(
	PeerSupervisorConfig,
) (PeerRuntimeObservation, error) {
	return PeerRuntimeObservation{}, ErrSupervisorState
}

func observeCurrentPeerRecoveryRuntime(
	PeerSupervisorConfig,
) (PeerRecoveryRuntimeObservation, error) {
	return PeerRecoveryRuntimeObservation{}, ErrSupervisorState
}
