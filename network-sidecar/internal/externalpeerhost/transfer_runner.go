package externalpeerhost

import "context"

// FixedTransferRunner is the fixed Layer-B transfer boundary implemented by
// StartLabRunner. It:
//   - loads only the fixed control workspace and signs sequence 0/1, then
//     sequence 2 only after the peer bundle arrives;
//   - creates sequence 3 only on the one terminal cancellation branch;
//   - re-resolve the two exact VM identities before every public transfer;
//   - use separate pinned management-SSH identities and known-hosts files;
//   - create only the reviewed console-user inbox names and no-argument wake;
//   - observe public status without starting, stopping, or signalling a root
//     supervisor or peer child; and
//   - honor cancellation and the same 120-second transaction deadline.
//
// It accepts no path, endpoint, VM name, credential, command, or policy from a
// caller. Building and unit-testing the implementation is Layer A work; using
// it against live VMs still requires the per-run Layer-B authorization gate.
type FixedTransferRunner interface {
	StartLab(context.Context) error
}
