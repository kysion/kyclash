use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, TunnelDeviceFacts};

pub const ROUTE_HELPER_PROTOCOL_VERSION: u8 = 2;
pub const ROUTE_HELPER_LABEL: &str = "net.kysion.kyclash.route-helper";
pub const ROUTE_HELPER_APP_REQUIREMENT: &str =
    "anchor apple generic and identifier \"net.kysion.kyclash\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\"";

const MAX_MIHOMO_TUN_INTERFACES: usize = 1;
const MAX_DARWIN_INTERFACE_BYTES: usize = 15;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLeaseOwner {
    pub protocol_version: u8,
    pub lease_id: String,
    pub operation_id: String,
    pub sidecar_instance_id: String,
    pub profile_revision: u64,
    pub tunnel: TunnelDeviceFacts,
    pub active_mihomo_tun_interfaces: Vec<String>,
    pub private_cidrs: Vec<String>,
}

impl RouteLeaseOwner {
    pub fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version != ROUTE_HELPER_PROTOCOL_VERSION
            || !valid_identifier(&self.lease_id)
            || !valid_identifier(&self.operation_id)
            || !valid_identifier(&self.sidecar_instance_id)
            || self.profile_revision == 0
            || self.profile_revision > i64::MAX as u64
            || self.private_cidrs.is_empty()
            || self.private_cidrs.len() > 64
            || !all_unique(self.private_cidrs.iter())
            || !self.private_cidrs.iter().all(|cidr| valid_cidr(cidr))
            || !self
                .private_cidrs
                .iter()
                .all(|cidr| tunnel_supports_cidr(&self.tunnel, cidr))
            || !valid_utun_interface(&self.tunnel.interface_name)
            || !valid_mihomo_interfaces(&self.active_mihomo_tun_interfaces)
            || self
                .active_mihomo_tun_interfaces
                .iter()
                .any(|interface| interface == &self.tunnel.interface_name)
            || !cidrs_are_non_overlapping(self.private_cidrs.iter())
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

impl RouteHelperStatus {
    pub fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version != ROUTE_HELPER_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if self
            .operation_id
            .as_deref()
            .is_some_and(|operation| !valid_identifier(operation))
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    super::valid_ipc_id(value)
}

pub(crate) fn valid_utun_interface(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 5
        && bytes.len() <= MAX_DARWIN_INTERFACE_BYTES
        && bytes.starts_with(b"utun")
        && (bytes.len() == 5 || bytes[4] != b'0')
        && bytes[4..].iter().all(u8::is_ascii_digit)
}

fn valid_mihomo_interfaces(values: &[String]) -> bool {
    values.len() <= MAX_MIHOMO_TUN_INTERFACES
        && all_unique(values.iter())
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|interface| valid_utun_interface(interface))
}

fn valid_cidr(value: &str) -> bool {
    parse_cidr(value).is_some()
}

fn tunnel_supports_cidr(tunnel: &TunnelDeviceFacts, cidr: &str) -> bool {
    match parse_cidr(cidr).map(|(address, _)| address) {
        Some(IpAddr::V4(_)) => tunnel.has_ipv4,
        Some(IpAddr::V6(_)) => tunnel.has_ipv6,
        None => false,
    }
}

fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = value.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix == 0
        || address.is_unspecified()
        || address.is_multicast()
        || prefix > if address.is_ipv4() { 32 } else { 128 }
    {
        return None;
    }
    is_network_base(address, prefix).then_some((address, prefix))
}

fn cidrs_are_non_overlapping<'a>(values: impl Iterator<Item = &'a String>) -> bool {
    let mut parsed = Vec::new();
    for value in values {
        let Some(cidr) = parse_cidr(value) else {
            return false;
        };
        parsed.push(cidr);
    }
    for (index, (address, prefix)) in parsed.iter().enumerate() {
        for (other_address, other_prefix) in parsed.iter().skip(index + 1) {
            if cidr_overlaps(*address, *prefix, *other_address, *other_prefix) {
                return false;
            }
        }
    }
    true
}

fn cidr_overlaps(left: IpAddr, left_prefix: u8, right: IpAddr, right_prefix: u8) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            let left = u32::from(left);
            let right = u32::from(right);
            let prefix = left_prefix.min(right_prefix);
            let mask = u32::MAX << (32 - u32::from(prefix));
            left & mask == right & mask
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            let left = u128::from(left);
            let right = u128::from(right);
            let prefix = left_prefix.min(right_prefix);
            let mask = u128::MAX << (128 - u32::from(prefix));
            left & mask == right & mask
        }
        _ => false,
    }
}

fn is_network_base(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(value) => {
            let host_bits = 32 - u32::from(prefix);
            let mask = if host_bits == 32 {
                u32::MAX
            } else {
                (1u32 << host_bits) - 1
            };
            u32::from_be_bytes(value.octets()) & mask == 0
        }
        IpAddr::V6(value) => {
            let bytes = value.octets();
            let mut remaining = 128 - usize::from(prefix);
            let mut index = usize::from(prefix / 8);
            if remaining > 0 && !prefix.is_multiple_of(8) {
                let host_bits = 8 - (prefix % 8);
                let mask = (1u8 << host_bits) - 1;
                if bytes[index] & mask != 0 {
                    return false;
                }
                remaining -= usize::from(host_bits);
                index += 1;
            }
            while remaining >= 8 {
                if bytes[index] != 0 {
                    return false;
                }
                remaining -= 8;
                index += 1;
            }
            true
        }
    }
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
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
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
            active_mihomo_tun_interfaces: vec!["utun1024".into()],
            private_cidrs: vec!["10.127.0.0/16".into(), "fd00:127::/48".into()],
        }
    }

    #[test]
    fn exact_owner_tuple_is_accepted_and_reference_must_match() {
        let owner = owner();
        assert_eq!(owner.validate(), Ok(()));
        let reference = RouteLeaseReference {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
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
        let mut noncanonical_tunnel = valid.clone();
        noncanonical_tunnel.tunnel.interface_name = "utun042".into();
        cases.push(noncanonical_tunnel);
        let mut wrong_instance = valid.clone();
        wrong_instance.tunnel.instance_id = "instance.other".into();
        cases.push(wrong_instance);
        let mut duplicate = valid.clone();
        duplicate.private_cidrs.push("10.127.0.0/16".into());
        cases.push(duplicate);
        let mut default_route = valid.clone();
        default_route.private_cidrs = vec!["0.0.0.0/0".into()];
        cases.push(default_route);
        let mut host_bits = valid.clone();
        host_bits.private_cidrs = vec!["10.127.1.0/16".into()];
        cases.push(host_bits);
        let mut multicast = valid.clone();
        multicast.private_cidrs = vec!["224.0.0.0/4".into()];
        cases.push(multicast);
        let mut malformed_prefix = valid.clone();
        malformed_prefix.private_cidrs = vec!["10.127.0.0/nope".into()];
        cases.push(malformed_prefix);
        let mut overlapping = valid.clone();
        overlapping.private_cidrs = vec!["10.127.0.0/16".into(), "10.127.1.0/24".into()];
        cases.push(overlapping);
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

    #[test]
    fn missing_mihomo_list_is_rejected_on_the_wire() -> anyhow::Result<()> {
        let mut value = serde_json::to_value(owner())?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("owner must encode as an object"))?;
        object.remove("active_mihomo_tun_interfaces");
        assert!(serde_json::from_value::<RouteLeaseOwner>(value).is_err());
        Ok(())
    }

    #[test]
    fn mihomo_interface_allowlist_is_canonical_and_scoped() {
        let valid = owner();
        let mut malformed = valid.clone();
        malformed.active_mihomo_tun_interfaces = vec!["utun-other".into()];
        assert!(malformed.validate().is_err());

        let mut leading_zero = valid.clone();
        leading_zero.active_mihomo_tun_interfaces = vec!["utun007".into()];
        assert!(leading_zero.validate().is_err());

        let mut too_many = valid.clone();
        too_many.active_mihomo_tun_interfaces = vec!["utun1".into(), "utun2".into()];
        assert!(too_many.validate().is_err());

        let mut unsorted = valid.clone();
        // The cardinality bound currently makes this an invalid owner before
        // ordering can be observed; retain the explicit check for future
        // multi-interface revisions.
        unsorted.active_mihomo_tun_interfaces = vec!["utun2".into(), "utun1".into()];
        assert!(unsorted.validate().is_err());

        let mut same_as_owned = valid;
        same_as_owned.active_mihomo_tun_interfaces = vec!["utun42".into()];
        assert!(same_as_owned.validate().is_err());
    }

    #[test]
    fn tunnel_family_facts_are_bound_to_private_cidrs() {
        let valid = owner();
        let mut no_ipv4 = valid.clone();
        no_ipv4.tunnel.has_ipv4 = false;
        assert!(no_ipv4.validate().is_err());

        let mut no_ipv6 = valid;
        no_ipv6.tunnel.has_ipv6 = false;
        assert!(no_ipv6.validate().is_err());
    }

    #[test]
    fn status_requires_current_protocol_and_bounded_operation() {
        let status = RouteHelperStatus {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            state: RouteHelperState::Idle,
            operation_id: None,
            error_code: None,
        };
        assert_eq!(status.validate(), Ok(()));
        assert_eq!(
            RouteHelperStatus {
                protocol_version: 1,
                ..status.clone()
            }
            .validate(),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
        assert_eq!(
            RouteHelperStatus {
                operation_id: Some("bad operation".into()),
                ..status
            }
            .validate(),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
    }
}
