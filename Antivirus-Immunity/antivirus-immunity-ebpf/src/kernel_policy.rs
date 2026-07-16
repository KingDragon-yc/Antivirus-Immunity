//! Versioned userspace policy compiled into bounded eBPF maps.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

const MAX_NETWORKS: usize = 4096;
const MAX_PORTS: usize = 256;
const MAX_PATHS: usize = 256;
const KERNEL_PATH_LEN: usize = 256;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct KernelPolicy {
    pub generation: u64,
    pub enforce: bool,
    pub fail_closed: bool,
    pub allow_legacy_tc: bool,
    pub interfaces: Vec<String>,
    pub networks: Vec<NetworkCidr>,
    pub blocked_ports: Vec<u16>,
    pub protected_paths: Vec<ProtectedPathRule>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum NetworkCidr {
    V4 { prefix: u32, address: [u8; 4] },
    V6 { prefix: u32, address: [u8; 16] },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathRule {
    pub path: String,
    #[serde(default = "default_deny_operations")]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow_processes: Vec<String>,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    fail_closed: bool,
    #[serde(default)]
    allow_legacy_tc: bool,
    #[serde(default)]
    interfaces: Vec<String>,
    #[serde(default)]
    network_blacklist: Vec<String>,
    #[serde(default)]
    blocked_ports: Vec<u16>,
    #[serde(default)]
    protected_paths: Vec<ProtectedPathRule>,
}

fn default_deny_operations() -> Vec<String> {
    vec!["write".to_owned()]
}

impl KernelPolicy {
    pub fn load(
        path: Option<&Path>,
        enforce: bool,
        cli_interfaces: &[String],
        cli_protected_paths: &[String],
    ) -> Result<Self> {
        let file = match path {
            Some(path) => {
                let mut bytes = Vec::new();
                File::open(path)
                    .with_context(|| format!("open kernel policy {}", path.display()))?
                    .take(MAX_POLICY_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .with_context(|| format!("read kernel policy {}", path.display()))?;
                if bytes.len() as u64 > MAX_POLICY_BYTES {
                    bail!("kernel policy exceeds {MAX_POLICY_BYTES} bytes");
                }
                let file = serde_json::from_slice::<PolicyFile>(&bytes)
                    .with_context(|| format!("parse kernel policy {}", path.display()))?;
                if file.version != 1 {
                    bail!("unsupported kernel policy version {}", file.version);
                }
                file
            }
            None => PolicyFile {
                version: 1,
                ..PolicyFile::default()
            },
        };

        let mut interfaces = if cli_interfaces.is_empty() {
            file.interfaces
        } else {
            cli_interfaces.to_vec()
        };
        interfaces.sort();
        interfaces.dedup();
        let protected_paths = if path.is_none() {
            cli_protected_paths
                .iter()
                .filter(|path| !path.is_empty())
                .map(|path| ProtectedPathRule {
                    path: path.clone(),
                    deny: default_deny_operations(),
                    allow_processes: Vec::new(),
                    // CLI paths historically meant protected prefixes. The
                    // kernel boundary check still prevents `/etc/shadow` from
                    // matching `/etc/shadow.bak`.
                    recursive: true,
                })
                .collect()
        } else {
            file.protected_paths
        };

        let networks = file
            .network_blacklist
            .iter()
            .map(|cidr| parse_cidr(cidr))
            .collect::<Result<Vec<_>>>()?;
        let policy = Self {
            generation: file.generation,
            enforce,
            fail_closed: file.fail_closed,
            allow_legacy_tc: file.allow_legacy_tc,
            interfaces,
            networks,
            blocked_ports: file.blocked_ports,
            protected_paths,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        if self.networks.len() > MAX_NETWORKS {
            bail!("network blacklist exceeds {MAX_NETWORKS} entries");
        }
        if self.networks.iter().collect::<HashSet<_>>().len() != self.networks.len() {
            bail!("network blacklist contains duplicate CIDRs");
        }
        if self.blocked_ports.len() > MAX_PORTS {
            bail!("blocked port list exceeds {MAX_PORTS} entries");
        }
        if self.blocked_ports.contains(&0) {
            bail!("blocked port 0 is invalid");
        }
        if self.blocked_ports.iter().collect::<HashSet<_>>().len() != self.blocked_ports.len() {
            bail!("blocked port list contains duplicates");
        }
        if self.protected_paths.len() > MAX_PATHS {
            bail!("protected path list exceeds {MAX_PATHS} entries");
        }
        for interface in &self.interfaces {
            if interface.is_empty()
                || interface.len() >= 16
                || interface
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
                || interface.contains('/')
            {
                bail!("network interface names must contain 1..15 safe non-space bytes");
            }
        }
        let mut unique_paths = HashSet::new();
        for rule in &self.protected_paths {
            let normalized = normalize_path(&rule.path);
            if !normalized.starts_with('/') {
                bail!("protected path must be absolute: {}", rule.path);
            }
            if normalized.len() >= KERNEL_PATH_LEN {
                bail!(
                    "protected path is too long for the kernel ABI: {}",
                    rule.path
                );
            }
            if normalized.as_bytes().contains(&0) {
                bail!("protected path contains NUL: {}", rule.path);
            }
            if normalized == "/" {
                bail!("protecting the filesystem root is unsafe; list explicit paths");
            }
            if normalized.contains("//")
                || normalized
                    .split('/')
                    .any(|part| part == "." || part == "..")
            {
                bail!("protected path must be lexically normalized: {}", rule.path);
            }
            if !unique_paths.insert((normalized.clone(), rule.recursive)) {
                bail!("duplicate protected path rule: {}", rule.path);
            }
            if rule.deny.is_empty() {
                bail!("protected path {} has an empty deny list", rule.path);
            }
            for operation in &rule.deny {
                match operation.as_str() {
                    "open" | "write" => {}
                    other => bail!("unsupported file operation {other:?} for {}", rule.path),
                }
            }
            if !rule.allow_processes.is_empty() {
                bail!(
                    "allow_processes is intentionally unsupported because Linux comm names are spoofable; use an empty list"
                );
            }
        }
        Ok(())
    }
}

pub fn normalize_path(path: &str) -> String {
    if path == "/" {
        "/".to_owned()
    } else {
        path.trim_end_matches('/').to_owned()
    }
}

pub fn deny_mask(operations: &[String]) -> u32 {
    operations.iter().fold(0, |mask, operation| {
        mask | match operation.as_str() {
            "open" => 1 << 0,
            "write" => 1 << 1,
            _ => 0,
        }
    })
}

fn parse_cidr(value: &str) -> Result<NetworkCidr> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let ip: IpAddr = address
        .parse()
        .with_context(|| format!("invalid network address {value:?}"))?;
    match ip {
        IpAddr::V4(address) => {
            let prefix = parse_prefix(prefix, 32, value)?;
            Ok(NetworkCidr::V4 {
                prefix,
                address: mask_v4(address, prefix),
            })
        }
        IpAddr::V6(address) => {
            let prefix = parse_prefix(prefix, 128, value)?;
            Ok(NetworkCidr::V6 {
                prefix,
                address: mask_v6(address, prefix),
            })
        }
    }
}

fn parse_prefix(prefix: Option<&str>, max: u32, original: &str) -> Result<u32> {
    let prefix = prefix
        .map_or(Ok(max), |value| value.parse::<u32>())
        .with_context(|| format!("invalid CIDR prefix in {original:?}"))?;
    if prefix > max {
        bail!("CIDR prefix {prefix} exceeds {max} in {original:?}");
    }
    Ok(prefix)
}

fn mask_v4(address: Ipv4Addr, prefix: u32) -> [u8; 4] {
    let value = u32::from(address);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (value & mask).to_be_bytes()
}

fn mask_v6(address: Ipv6Addr, prefix: u32) -> [u8; 16] {
    let mut bytes = address.octets();
    for bit in prefix..128 {
        bytes[(bit / 8) as usize] &= !(1 << (7 - bit % 8));
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parser_normalizes_host_bits() {
        assert_eq!(
            parse_cidr("10.2.3.4/16").unwrap(),
            NetworkCidr::V4 {
                prefix: 16,
                address: [10, 2, 0, 0]
            }
        );
        assert!(parse_cidr("10.0.0.1/33").is_err());
    }

    #[test]
    fn policy_rejects_relative_and_oversized_values() {
        let policy = KernelPolicy {
            generation: 1,
            enforce: true,
            fail_closed: false,
            allow_legacy_tc: false,
            interfaces: vec!["eth0".to_owned()],
            networks: vec![],
            blocked_ports: vec![],
            protected_paths: vec![ProtectedPathRule {
                path: "etc/shadow".to_owned(),
                deny: vec!["write".to_owned()],
                allow_processes: vec![],
                recursive: false,
            }],
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_rejects_duplicate_rules_and_unsafe_interface_names() {
        let network = NetworkCidr::V4 {
            prefix: 24,
            address: [10, 0, 0, 0],
        };
        let mut policy = KernelPolicy {
            generation: 1,
            enforce: false,
            fail_closed: false,
            allow_legacy_tc: false,
            interfaces: vec!["eth0".to_owned()],
            networks: vec![network.clone(), network],
            blocked_ports: vec![443, 443],
            protected_paths: vec![],
        };
        assert!(policy.validate().is_err());
        policy.networks.pop();
        assert!(policy.validate().is_err());
        policy.blocked_ports.pop();
        policy.interfaces = vec!["eth0\nforged".to_owned()];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_file_has_explicit_empty_lists_and_strict_rule_fields() {
        assert!(
            serde_json::from_str::<PolicyFile>(
                r#"{"version":1,"protected_paths":[{"path":"/etc/shadow","recusrive":true}]}"#
            )
            .is_err()
        );

        let path =
            std::env::temp_dir().join(format!("immunity-policy-{}.json", std::process::id()));
        std::fs::write(&path, r#"{"version":1,"protected_paths":[]}"#).unwrap();
        let policy = KernelPolicy::load(
            Some(path.as_path()),
            false,
            &[],
            &["/etc/shadow".to_owned()],
        )
        .unwrap();
        assert!(policy.protected_paths.is_empty());
        let _ = std::fs::remove_file(path);
    }
}
