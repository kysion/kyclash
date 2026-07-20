use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
use std::{path::PathBuf, process::Command};

use super::{ExistingRoute, NetworkErrorCode};
#[cfg(target_os = "macos")]
use super::{RoutePlatform, RouteSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsRouteFamily {
    Ipv4,
    Ipv6,
}

#[cfg(target_os = "macos")]
pub struct MacOsReadOnlyRoutePlatform {
    netstat_path: PathBuf,
}

#[cfg(target_os = "macos")]
impl Default for MacOsReadOnlyRoutePlatform {
    fn default() -> Self {
        Self {
            netstat_path: PathBuf::from("/usr/sbin/netstat"),
        }
    }
}

#[cfg(target_os = "macos")]
impl MacOsReadOnlyRoutePlatform {
    pub const fn new(netstat_path: PathBuf) -> Self {
        Self { netstat_path }
    }

    fn discover_family(&self, family: MacOsRouteFamily) -> Result<Vec<ExistingRoute>, NetworkErrorCode> {
        let family_argument = match family {
            MacOsRouteFamily::Ipv4 => "inet",
            MacOsRouteFamily::Ipv6 => "inet6",
        };
        let output = Command::new(&self.netstat_path)
            .args(["-rn", "-f", family_argument])
            .output()
            .map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?;
        if !output.status.success() {
            return Err(NetworkErrorCode::RouteDiscoveryFailed);
        }
        let stdout = String::from_utf8(output.stdout).map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?;
        parse_macos_netstat(&stdout, family)
    }
}

#[cfg(target_os = "macos")]
impl RoutePlatform for MacOsReadOnlyRoutePlatform {
    fn list_routes(&mut self) -> Result<Vec<ExistingRoute>, NetworkErrorCode> {
        let mut routes = self.discover_family(MacOsRouteFamily::Ipv4)?;
        routes.extend(self.discover_family(MacOsRouteFamily::Ipv6)?);
        Ok(routes)
    }

    fn add_route(&mut self, _: &RouteSpec) -> Result<(), NetworkErrorCode> {
        Err(NetworkErrorCode::PermissionDenied)
    }

    fn remove_route(&mut self, _: &RouteSpec) -> Result<(), NetworkErrorCode> {
        Err(NetworkErrorCode::PermissionDenied)
    }
}

/// Parse the stable columns emitted by `netstat -rn -f inet` or
/// `netstat -rn -f inet6`. This function performs no process or network I/O.
pub fn parse_macos_netstat(output: &str, family: MacOsRouteFamily) -> Result<Vec<ExistingRoute>, NetworkErrorCode> {
    let mut found_header = false;
    let mut routes = Vec::new();
    for line in output.lines() {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.first() == Some(&"Destination") {
            found_header = true;
            continue;
        }
        if !found_header || columns.is_empty() {
            continue;
        }
        if columns.len() < 4 {
            return Err(NetworkErrorCode::RouteDiscoveryFailed);
        }
        let flags = columns[2];
        let destination = normalize_destination(columns[0], flags, family)?;
        let gateway = match columns[1] {
            value if value.starts_with("link#") || value == "-" => None,
            value => Some(value.to_owned()),
        };
        routes.push(ExistingRoute {
            destination,
            interface: columns[3].to_owned(),
            gateway,
        });
    }
    if !found_header {
        return Err(NetworkErrorCode::RouteDiscoveryFailed);
    }
    Ok(routes)
}

fn normalize_destination(destination: &str, flags: &str, family: MacOsRouteFamily) -> Result<String, NetworkErrorCode> {
    if destination == "default" {
        return Ok(match family {
            MacOsRouteFamily::Ipv4 => "0.0.0.0/0",
            MacOsRouteFamily::Ipv6 => "::/0",
        }
        .into());
    }
    match family {
        MacOsRouteFamily::Ipv4 => normalize_ipv4_destination(destination, flags),
        MacOsRouteFamily::Ipv6 => normalize_ipv6_destination(destination, flags),
    }
}

fn normalize_ipv4_destination(destination: &str, flags: &str) -> Result<String, NetworkErrorCode> {
    let (address, explicit_prefix) = destination
        .split_once('/')
        .map_or((destination, None), |(address, prefix)| (address, Some(prefix)));
    let octets = address.split('.').collect::<Vec<_>>();
    if octets.is_empty() || octets.len() > 4 {
        return Err(NetworkErrorCode::RouteDiscoveryFailed);
    }
    let mut expanded = [0_u8; 4];
    for (index, octet) in octets.iter().enumerate() {
        expanded[index] = octet
            .parse::<u8>()
            .map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?;
    }
    let prefix = match explicit_prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?,
        None if flags.contains('H') => 32,
        None => u8::try_from(octets.len() * 8).map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?,
    };
    if prefix > 32 {
        return Err(NetworkErrorCode::RouteDiscoveryFailed);
    }
    Ok(format!("{}/{}", Ipv4Addr::from(expanded), prefix))
}

fn normalize_ipv6_destination(destination: &str, flags: &str) -> Result<String, NetworkErrorCode> {
    let (address, explicit_prefix) = destination
        .split_once('/')
        .map_or((destination, None), |(address, prefix)| (address, Some(prefix)));
    let address = address.split_once('%').map_or(address, |(address, _)| address);
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?;
    let prefix = match explicit_prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .map_err(|_| NetworkErrorCode::RouteDiscoveryFailed)?,
        None if flags.contains('H') => 128,
        None => 128,
    };
    if prefix > 128 {
        return Err(NetworkErrorCode::RouteDiscoveryFailed);
    }
    Ok(format!("{address}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_ROUTES: &str = r"
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
10.64/16           link#22            UCS                 utun4
10.64.0.1          10.64.0.1          UH                  utun4
127                127.0.0.1          UCS                   lo0
224.0.0/4          link#14            UmCS                  en0
";

    const IPV6_ROUTES: &str = r"
Routing tables

Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                     UGcg            en0
fd00:64::/48                            link#22                         UCS           utun4
fe80::1%lo0                             fe80::1%lo0                     UH              lo0
";

    #[test]
    fn parses_and_normalizes_ipv4_route_table() -> Result<(), NetworkErrorCode> {
        let routes = parse_macos_netstat(IPV4_ROUTES, MacOsRouteFamily::Ipv4)?;
        assert_eq!(routes[0].destination, "0.0.0.0/0");
        assert_eq!(routes[1].destination, "10.64.0.0/16");
        assert_eq!(routes[1].gateway, None);
        assert_eq!(routes[2].destination, "10.64.0.1/32");
        assert_eq!(routes[3].destination, "127.0.0.0/8");
        assert_eq!(routes[4].destination, "224.0.0.0/4");
        Ok(())
    }

    #[test]
    fn parses_and_normalizes_ipv6_route_table() -> Result<(), NetworkErrorCode> {
        let routes = parse_macos_netstat(IPV6_ROUTES, MacOsRouteFamily::Ipv6)?;
        assert_eq!(routes[0].destination, "::/0");
        assert_eq!(routes[1].destination, "fd00:64::/48");
        assert_eq!(routes[2].destination, "fe80::1/128");
        Ok(())
    }

    #[test]
    fn malformed_or_headerless_output_fails_closed() {
        assert_eq!(
            parse_macos_netstat("route output unavailable", MacOsRouteFamily::Ipv4),
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
        assert_eq!(
            parse_macos_netstat(
                "Destination Gateway Flags Netif\n10.bad link#2 U en0",
                MacOsRouteFamily::Ipv4
            ),
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_only_adapter_discovers_local_routes_and_refuses_mutation() -> Result<(), NetworkErrorCode> {
        let mut platform = MacOsReadOnlyRoutePlatform::default();
        let routes = platform.list_routes()?;
        assert!(!routes.is_empty());
        assert!(routes.iter().any(|route| route.destination == "0.0.0.0/0"));
        let route = RouteSpec {
            destination: "10.64.0.0/16".into(),
            interface: "utun.test".into(),
        };
        assert_eq!(platform.add_route(&route), Err(NetworkErrorCode::PermissionDenied));
        assert_eq!(platform.remove_route(&route), Err(NetworkErrorCode::PermissionDenied));
        Ok(())
    }
}
