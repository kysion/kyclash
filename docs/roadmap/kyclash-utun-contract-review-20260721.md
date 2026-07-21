# KyClash owned-utun contract review

Status: approved and locked for S1.09

Date: 2026-07-21

## Finding

The existing `prepare_tunnel` acknowledgement cannot prove ownership of a real
macOS utun. Treating an arbitrary `utunN` observation as ownership would allow
KyClash to report or destroy another VPN's interface. The Go backend also needs
the authenticated sidecar instance and exact prepare operation to bind cleanup
to the creator.

## Locked amendment

- The authenticated bootstrap instance ID and `prepare_tunnel` request ID form
  the immutable tunnel owner record.
- A successful prepare response is `tunnel_prepared` with only interface name,
  MTU, address-family flags, instance ID, and operation ID. It contains no key,
  address, endpoint, file path, or credential reference.
- Interface names must be returned by the created device and match `utun` plus
  decimal digits. Names supplied by callers or discovered later never establish
  ownership.
- The reviewed MTU remains 1420. Local prefixes are validated before device
  creation. Route and DNS mutation remain forbidden in S1.09.
- Default and lab builds continue using the userspace netstack. Only the
  separately bundled macOS production sidecar is compiled with the reviewed
  `kyclash_utun` build tag.
- stdin EOF, malformed IPC, explicit stop, controller disconnect, and process
  teardown all close the exact device object held by the owner record. Cleanup
  never opens or deletes a device by a string name.

The IPC protocol version remains 1 because this adds a response variant to a
request that production builds have not enabled. Rust and Go are updated and
tested together before the production feature is activated.

## Evidence gates

- Pure injected tests reject forged names, mismatched owner records, invalid
  prefixes, wrong MTU, duplicate prepare, and cleanup of an unowned device.
- macOS compile checks prove the tagged adapter uses wireguard-go `tun.Device`.
- Real create/up/traffic/down and final-absence evidence runs only in the
  authorized disposable VM.
