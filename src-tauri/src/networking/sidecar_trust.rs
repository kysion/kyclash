use std::{fs, io::Read as _, path::Path, process::Command};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use super::NetworkErrorCode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarTrustManifest {
    pub schema_version: u8,
    pub sha256: String,
    pub architecture: String,
    pub team_id: String,
    pub designated_requirement: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SidecarFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct SidecarSnapshot {
    bytes: Vec<u8>,
    identity: SidecarFileIdentity,
}

pub fn verify_macos_sidecar(path: &Path, manifest: &SidecarTrustManifest) -> Result<(), NetworkErrorCode> {
    if manifest.schema_version != 1
        || manifest.sha256.len() != 64
        || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !valid_identifier(&manifest.team_id)
        || manifest.designated_requirement.is_empty()
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    #[cfg(unix)]
    let before = read_sidecar_snapshot(path)?;
    #[cfg(unix)]
    let bytes = before.bytes.as_slice();
    #[cfg(not(unix))]
    let bytes = read_sidecar_bytes_fallback(path)?;
    if macho_architecture(bytes) != Some(manifest.architecture.as_str())
        || hex(digest(&SHA256, bytes).as_ref()) != manifest.sha256.to_ascii_lowercase()
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    verify_code_signature(path, manifest)?;

    // `codesign` accepts a path rather than our already-open descriptor.  A
    // hostile writable bundle could otherwise swap that path between the
    // hash and signature checks. Re-open with O_NOFOLLOW after codesign and
    // require the same inode/device/size and exact bytes; any ambiguity fails
    // closed before the caller can spawn the child.
    #[cfg(unix)]
    {
        let after = read_sidecar_snapshot(path)?;
        if before.identity != after.identity || before.bytes != after.bytes {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_sidecar_snapshot(path: &Path) -> Result<SidecarSnapshot, NetworkErrorCode> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            NetworkErrorCode::AuthenticationFailed
        } else {
            NetworkErrorCode::SidecarUnavailable
        }
    })?;
    let metadata = file.metadata().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if !metadata.is_file() {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    let identity = SidecarFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    // Detect a concurrent truncate/extend through the same descriptor. A
    // later digest comparison catches in-place content replacement.
    let final_size = file
        .metadata()
        .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
        .size();
    if final_size != identity.size || bytes.len() as u64 != identity.size {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(SidecarSnapshot { bytes, identity })
}

#[cfg(not(unix))]
fn read_sidecar_bytes_fallback(path: &Path) -> Result<Vec<u8>, NetworkErrorCode> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    fs::read(path).map_err(|_| NetworkErrorCode::SidecarUnavailable)
}

#[cfg(target_os = "macos")]
fn verify_code_signature(path: &Path, manifest: &SidecarTrustManifest) -> Result<(), NetworkErrorCode> {
    let requirement = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2", "-R"])
        .arg(&manifest.designated_requirement)
        .arg(path)
        .status()
        .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    if !requirement.success() {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    let text = String::from_utf8_lossy(&details.stderr);
    if !details.status.success()
        || !text
            .lines()
            .any(|line| line == format!("TeamIdentifier={}", manifest.team_id))
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_code_signature(_: &Path, _: &SidecarTrustManifest) -> Result<(), NetworkErrorCode> {
    Err(NetworkErrorCode::AuthenticationFailed)
}

fn macho_architecture(bytes: &[u8]) -> Option<&'static str> {
    let header: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    match (&header[..4], u32::from_le_bytes(header[4..].try_into().ok()?)) {
        ([0xcf, 0xfa, 0xed, 0xfe], 0x0100_000c) => Some("arm64"),
        ([0xcf, 0xfa, 0xed, 0xfe], 0x0100_0007) => Some("x86_64"),
        _ => None,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_reviewed_thin_macho_architectures() {
        let mut arm = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
        arm.resize(32, 0);
        assert_eq!(macho_architecture(&arm), Some("arm64"));
        arm[4] = 7;
        assert_eq!(macho_architecture(&arm), Some("x86_64"));
        arm[0] = 0;
        assert_eq!(macho_architecture(&arm), None);
    }

    #[test]
    fn manifest_rejects_injection_shaped_team_identity_before_execution() {
        let manifest = SidecarTrustManifest {
            schema_version: 1,
            sha256: "0".repeat(64),
            architecture: "arm64".into(),
            team_id: "TEAM;touch bad".into(),
            designated_requirement: "identifier net.kysion.kyclash.network-sidecar".into(),
        };
        assert_eq!(
            verify_macos_sidecar(Path::new("missing"), &manifest),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_snapshot_refuses_symlink_and_captures_stable_identity() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let regular = directory.path().join("sidecar");
        let link = directory.path().join("sidecar-link");
        std::fs::write(&regular, b"sidecar-bytes")?;
        symlink(&regular, &link)?;

        let snapshot = read_sidecar_snapshot(&regular).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(snapshot.bytes, b"sidecar-bytes");
        assert!(snapshot.identity.inode > 0);
        assert_eq!(
            read_sidecar_snapshot(&link).err(),
            Some(NetworkErrorCode::AuthenticationFailed)
        );
        Ok(())
    }
}
