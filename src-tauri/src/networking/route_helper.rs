use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, TunnelDeviceFacts};

pub const ROUTE_HELPER_PROTOCOL_VERSION: u8 = 1;
pub const ROUTE_HELPER_LABEL: &str = "net.kysion.kyclash.route-helper";
pub const ROUTE_HELPER_APP_REQUIREMENT: &str =
    "anchor apple generic and identifier \"net.kysion.kyclash\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\"";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseOwner {
    pub protocol_version: u8,
    pub lease_id: String,
    pub operation_id: String,
    pub sidecar_instance_id: String,
    pub profile_revision: u64,
    pub tunnel: TunnelDeviceFacts,
    pub private_cidrs: Vec<String>,
}

impl RouteLeaseOwner {
    pub fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version != ROUTE_HELPER_PROTOCOL_VERSION
            || !valid_identifier(&self.lease_id)
            || !valid_identifier(&self.operation_id)
            || !valid_identifier(&self.sidecar_instance_id)
            || self.profile_revision == 0
            || self.private_cidrs.is_empty()
            || self.private_cidrs.len() > 64
            || !all_unique(self.private_cidrs.iter())
            || !self.private_cidrs.iter().all(|cidr| valid_cidr(cidr))
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        self.tunnel
            .validate(&self.sidecar_instance_id, &format!("{}.prepare", self.operation_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseReference {
    pub protocol_version: u8,
    pub lease_id: String,
    pub operation_id: String,
}

impl RouteLeaseReference {
    pub fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version != ROUTE_HELPER_PROTOCOL_VERSION
            || !valid_identifier(&self.lease_id)
            || !valid_identifier(&self.operation_id)
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn matches(&self, owner: &RouteLeaseOwner) -> bool {
        self.validate().is_ok() && self.lease_id == owner.lease_id && self.operation_id == owner.operation_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHelperState {
    Idle,
    Prepared,
    Applied,
    RollingBack,
    FailedClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteHelperStatus {
    pub protocol_version: u8,
    pub state: RouteHelperState,
    pub operation_id: Option<String>,
    pub error_code: Option<NetworkErrorCode>,
}

fn valid_identifier(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    !address.is_unspecified() && !address.is_multicast() && prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn all_unique<'a>(mut values: impl Iterator<Item = &'a String>) -> bool {
    let mut seen = HashSet::new();
    values.all(|value| seen.insert(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> RouteLeaseOwner {
        RouteLeaseOwner {
            protocol_version: 1,
            lease_id: "lease.test.001".into(),
            operation_id: "operation.test".into(),
            sidecar_instance_id: "instance.test".into(),
            profile_revision: 42,
            tunnel: TunnelDeviceFacts {
                interface_name: "utun42".into(),
                mtu: 1420,
                has_ipv4: true,
                has_ipv6: true,
                instance_id: "instance.test".into(),
                operation_id: "operation.test.prepare".into(),
            },
            private_cidrs: vec!["10.127.0.0/16".into(), "fd00:127::/48".into()],
        }
    }

    #[test]
    fn exact_owner_tuple_is_accepted_and_reference_must_match() {
        let owner = owner();
        assert_eq!(owner.validate(), Ok(()));
        let reference = RouteLeaseReference {
            protocol_version: 1,
            lease_id: owner.lease_id.clone(),
            operation_id: owner.operation_id.clone(),
        };
        assert!(reference.matches(&owner));
        assert!(
            !RouteLeaseReference {
                lease_id: "lease.replayed".into(),
                ..reference
            }
            .matches(&owner)
        );
    }

    #[test]
    fn malformed_or_injection_shaped_owner_fails_closed() {
        let valid = owner();
        let mut cases = Vec::new();
        let mut wrong_tunnel = valid.clone();
        wrong_tunnel.tunnel.interface_name = "utun42;route delete default".into();
        cases.push(wrong_tunnel);
        let mut wrong_instance = valid.clone();
        wrong_instance.tunnel.instance_id = "instance.other".into();
        cases.push(wrong_instance);
        let mut duplicate = valid.clone();
        duplicate.private_cidrs.push("10.127.0.0/16".into());
        cases.push(duplicate);
        let mut default_route = valid.clone();
        default_route.private_cidrs = vec!["0.0.0.0/0".into()];
        cases.push(default_route);
        let mut zero_revision = valid;
        zero_revision.profile_revision = 0;
        cases.push(zero_revision);
        for invalid in cases {
            assert!(invalid.validate().is_err(), "accepted invalid owner: {invalid:?}");
        }
    }

    #[test]
    fn unknown_wire_fields_are_rejected() -> anyhow::Result<()> {
        let mut value = serde_json::to_value(owner())?;
        value["command"] = serde_json::json!("/sbin/route delete default");
        assert!(serde_json::from_value::<RouteLeaseOwner>(value).is_err());
        Ok(())
    }
}
