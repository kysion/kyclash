use std::{fs, path::Path, process::Command};

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

pub fn verify_macos_sidecar(path: &Path, manifest: &SidecarTrustManifest) -> Result<(), NetworkErrorCode> {
    if manifest.schema_version != 1
        || manifest.sha256.len() != 64
        || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !valid_identifier(&manifest.team_id)
        || manifest.designated_requirement.is_empty()
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    let metadata = path
        .symlink_metadata()
        .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
    }
    let bytes = fs::read(path).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if macho_architecture(&bytes) != Some(manifest.architecture.as_str())
        || hex(digest(&SHA256, &bytes).as_ref()) != manifest.sha256.to_ascii_lowercase()
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    verify_code_signature(path, manifest)
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
}
