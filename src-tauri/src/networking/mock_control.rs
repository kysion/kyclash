use super::{NetworkErrorCode, NetworkProfile};

#[derive(Debug, Clone)]
pub struct MockControlPlane {
    profile: NetworkProfile,
}

impl MockControlPlane {
    pub fn new(profile: NetworkProfile) -> Result<Self, NetworkErrorCode> {
        profile.validate()?;
        Ok(Self { profile })
    }

    pub fn fetch_profile(&self, identity_ref: &str) -> Result<NetworkProfile, NetworkErrorCode> {
        if identity_ref != self.profile.identity_ref {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(self.profile.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");

    #[test]
    fn mock_control_plane_authenticates_without_network_io() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let control_plane = MockControlPlane::new(profile.clone()).map_err(|error| anyhow::anyhow!("{error:?}"))?;

        assert_eq!(control_plane.fetch_profile(&profile.identity_ref), Ok(profile));
        assert_eq!(
            control_plane.fetch_profile("keychain:unknown"),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
        Ok(())
    }
}
