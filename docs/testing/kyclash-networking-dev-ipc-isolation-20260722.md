# KyClash networking-dev IPC isolation

`networking-dev` must not attach to the IPC socket used by an installed or
release-mode KyClash instance. The production fallback remains unchanged:

```text
/tmp/verge/verge-mihomo.sock
```

On Unix, `ipc_path()` accepts an explicit `KYCLASH_IPC_PATH` override. The
override is intentionally fail-closed: it must be an absolute path no longer
than the Unix-domain socket limit, contain no `.` or `..` path components, use
an ASCII filename ending in `.sock`, have an existing non-symlink,
non-group/world-writable parent directory, and either not exist or already be
a socket. Windows continues to use the existing named pipe and ignores this
Unix-only variable.

The supported development entry point is:

```sh
pnpm dev:networking
```

The wrapper creates a private `target/kyclash-networking-dev` directory and
sets `KYCLASH_IPC_PATH` to:

```text
<workspace>/target/kyclash-networking-dev/verge-mihomo.sock
```

This keeps the development Mihomo process separate from the release socket.
Do not set the variable to `/tmp/verge/verge-mihomo.sock` while a release app
is running, and do not use a production socket for tests.

The path contract is covered by the Rust `utils::dirs` tests. A local check is:

```sh
cargo test -p clash-verge --features networking-production --lib \
  utils::dirs::tests:: -- --test-threads=1
node --check scripts/dev-networking.mjs
```
