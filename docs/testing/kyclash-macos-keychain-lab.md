# KyClash macOS Keychain lab

Status: GitHub-hosted disposable account gate prepared; execution pending

The `networking-keychain-lab` executable validates the real Security Framework
adapter without accepting a credential, service, account, or value from the
caller.

## Fixed scope

- Service: `net.kysion.kyclash.test`
- Account: `keychain:kyclash.test.synthetic.v1`
- Value: 32 random bytes generated in process, never printed or persisted
- Operations: refuse pre-existing value, create, read, exact compare,
  delete, and verify absence
- An exact confirmation value is required. No application command invokes the
  lab and the feature is absent from normal builds.

Run only in a disposable local macOS account whose login Keychain may be
modified. This prevents a failed or mis-scoped create/update/delete cycle from
polluting or deleting real entries. Do not run in a daily-use or production
account.

This destructive lifecycle check is manual and release-evidence-only. Its
absence does not block other source development or non-destructive credential
adapter tests.

## Build and execute

```bash
cargo build -p clash-verge \
  --features networking-keychain-lab \
  --bin kyclash-keychain-lab

KYCLASH_KEYCHAIN_LAB_CONFIRM=authorized-disposable-macos-account \
  target/debug/kyclash-keychain-lab cycle
```

The command may trigger an operating-system Keychain prompt. Accept only if the
binary path and fixed KyClash service are expected. A successful run leaves the
synthetic account absent.

If a prior interrupted run left the fixed synthetic account behind:

```bash
KYCLASH_KEYCHAIN_LAB_CONFIRM=authorized-disposable-macos-account \
  target/debug/kyclash-keychain-lab cleanup
```

Record the OS build, exit status, prompt behavior, and confirmation that the
item is absent afterward. Never capture Keychain contents, access-control data,
or unrelated item names.

This harness closes source preparation only. The credential lifecycle release
gate remains open until its cycle and cleanup behavior pass in the disposable
account.

## GitHub-hosted runner gate

`scripts/macos-system-lab.sh` runs cleanup, the fixed create/read/compare/delete
cycle, and an independent absence check in the ephemeral `macos-15` runner
account. No secret or item contents are captured; retained evidence records only
the OS/toolchain versions and pass/fail outcome.
