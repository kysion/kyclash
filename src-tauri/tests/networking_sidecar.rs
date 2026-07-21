#![cfg(all(feature = "networking-dev", unix))]

use std::fs;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use app_lib::networking::{
    NetworkErrorCode, RestartPolicy, SidecarController, SidecarLaunchContext, SidecarLifecycleState, UnixSidecarRuntime,
};

fn mock_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kyclash-network-mock"))
}

#[test]
fn real_mock_process_authenticates_runs_and_stops() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let token = "integration-token-not-in-argv".to_owned();
    let runtime = UnixSidecarRuntime::new(mock_binary(), runtime_dir.path().to_owned());
    let mut controller = SidecarController::new(
        runtime,
        RestartPolicy::default(),
        SidecarLaunchContext::new("integration.test".into(), token.clone().into_bytes()),
        token,
    );

    controller.start(0).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(controller.state(), SidecarLifecycleState::Running);
    controller.poll(1).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    controller.stop().map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(controller.state(), SidecarLifecycleState::Stopped);
    assert!(!runtime_dir.path().join("integration.test.sock").exists());
    Ok(())
}

#[test]
fn stale_socket_is_recovered_but_regular_file_is_never_removed() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let stale_path = runtime_dir.path().join("stale.test.sock");
    let stale_listener = UnixListener::bind(&stale_path)?;
    drop(stale_listener);

    let token = "integration-token-not-in-argv".to_owned();
    let runtime = UnixSidecarRuntime::new(mock_binary(), runtime_dir.path().to_owned());
    let mut controller = SidecarController::new(
        runtime,
        RestartPolicy::default(),
        SidecarLaunchContext::new("stale.test".into(), token.clone().into_bytes()),
        token,
    );
    controller.start(0).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    controller.stop().map_err(|error| anyhow::anyhow!("{error:?}"))?;

    let protected_path = runtime_dir.path().join("protected.test.sock");
    fs::write(&protected_path, b"must-not-delete")?;
    let token = "integration-token-not-in-argv".to_owned();
    let runtime = UnixSidecarRuntime::new(mock_binary(), runtime_dir.path().to_owned());
    let mut controller = SidecarController::new(
        runtime,
        RestartPolicy::default(),
        SidecarLaunchContext::new("protected.test".into(), token.clone().into_bytes()),
        token,
    );
    assert_eq!(controller.start(0), Err(NetworkErrorCode::PermissionDenied));
    assert_eq!(fs::read(&protected_path)?, b"must-not-delete");
    Ok(())
}
