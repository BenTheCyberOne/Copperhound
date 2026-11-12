//! Network conduits configuration (docs/OT.md, "Network reachability"):
//! parse, validate and resolve against a graph into a [`NetModel`].
//!
//! ```json
//! {"attacker_zone": "IT",
//!  "conduits": [
//!    {"from": "IT", "to": "OT-DMZ", "services": ["rdp"]},
//!    {"from": "OT-DMZ", "to": "OT-L2", "services": ["rdp", "smb"]},
//!    {"from": "OT-L2", "to": "OT-L1", "services": ["plc"]}]}
//! ```
//!
//! Hosts are placed in zones by their `net_zone` property. Zone names match
//! case-insensitively; `"*"` as `from` or `to` means every zone.

use ch_engine::net::{svc, NetModel, NO_ZONE};
use ch_query::{run_capped, Cancel};
use ch_store::Graph;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Conduits {
    /// Zone an attacker starts in (principals that are not zoned hosts).
    pub attacker_zone: String,
    /// Zones declared up front (others come from conduits and `net_zone`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(default)]
    pub conduits: Vec<Conduit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Conduit {
    pub from: String,
    pub to: String,
    /// `smb`, `rdp`, `winrm`, `rpc`, `mssql`, `plc`, `ssh` or `*`.
    pub services: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Zone summary for APIs.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneInfo {
    pub name: String,
    /// Nodes with this `net_zone`.
    pub hosts: u64,
}

fn valid_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.len() <= 100 && !s.chars().any(char::is_control)
}

impl Conduits {
    /// Structural checks that need no graph.
    pub fn validate(&self) -> Result<(), String> {
        if !valid_name(&self.attacker_zone) || self.attacker_zone.trim() == "*" {
            return Err("attacker_zone must name a zone".into());
        }
        if self.conduits.len() > 10_000 || self.zones.len() > 1_000 {
            return Err("too many zones or conduits".into());
        }
        for z in &self.zones {
            if !valid_name(z) || z.trim() == "*" {
                return Err(format!("invalid zone name '{z}'"));
            }
        }
        for (i, c) in self.conduits.iter().enumerate() {
            if !valid_name(&c.from) || !valid_name(&c.to) {
                return Err(format!("conduit #{}: from and to must name zones (or *)", i + 1));
            }
            if c.services.is_empty() {
                return Err(format!("conduit #{} ({} → {}): no services", i + 1, c.from, c.to));
            }
            for s in &c.services {
                if svc::parse(s).is_none() {
                    return Err(format!(
                        "conduit #{} ({} → {}): unknown service '{s}' (use {} or *)",
                        i + 1,
                        c.from,
                        c.to,
                        svc::NAMES.join(", ")
                    ));
                }
            }
        }
        Ok(())
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Distinct `net_zone` values and the nodes carrying each.
fn graph_zones(g: &Graph) -> Result<Vec<(String, Vec<u32>)>, String> {
    let cap = g.node_count().max(1);
    let never = Cancel::never();
    let r = run_capped(g, "MATCH (n) WHERE n.net_zone IS NOT NULL RETURN DISTINCT n.net_zone", cap, cap, &never)
        .map_err(|e| format!("net_zone lookup: {e}"))?;
    let mut out = Vec::new();
    for row in r.rows {
        let Some(name) = row.first().and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) else { continue };
        let q = format!("MATCH (n) WHERE n.net_zone = '{}' RETURN n", esc(name));
        let nodes = run_capped(g, &q, cap, cap, &never).map_err(|e| format!("net_zone lookup: {e}"))?.nodes;
        out.push((name.to_string(), nodes));
    }
    Ok(out)
}

/// Resolve the configuration against a graph.
pub fn build_model(g: &Graph, c: &Conduits) -> Result<(NetModel, Vec<ZoneInfo>), String> {
    c.validate()?;
    let mut zones: Vec<String> = Vec::new();
    let index = |zones: &mut Vec<String>, name: &str| -> u16 {
        let name = name.trim();
        match zones.iter().position(|z| z.eq_ignore_ascii_case(name)) {
            Some(i) => i as u16,
            None => {
                zones.push(name.to_string());
                (zones.len() - 1) as u16
            }
        }
    };
    let origin = index(&mut zones, &c.attacker_zone);
    for z in &c.zones {
        index(&mut zones, z);
    }
    for k in &c.conduits {
        for e in [&k.from, &k.to] {
            if e.trim() != "*" {
                index(&mut zones, e);
            }
        }
    }
    let mut zone_of = vec![NO_ZONE; g.node_count()];
    let mut hosts = Vec::new();
    for (name, nodes) in graph_zones(g)? {
        let z = index(&mut zones, &name);
        for &n in &nodes {
            zone_of[n as usize] = z;
        }
        hosts.push((z, nodes.len() as u64));
    }
    if zones.len() >= NO_ZONE as usize {
        return Err("too many zones".into());
    }
    let all: Vec<u16> = (0..zones.len() as u16).collect();
    let pick = |name: &str, zones: &[String]| -> Vec<u16> {
        if name.trim() == "*" {
            all.clone()
        } else {
            zones.iter().position(|z| z.eq_ignore_ascii_case(name.trim())).map(|i| vec![i as u16]).unwrap_or_default()
        }
    };
    let mut rules = Vec::new();
    for k in &c.conduits {
        let s = k.services.iter().filter_map(|s| svc::parse(s)).fold(0u8, |a, b| a | b);
        for &a in &pick(&k.from, &zones) {
            for &b in &pick(&k.to, &zones) {
                rules.push((a, b, s));
            }
        }
    }
    let info = zones
        .iter()
        .enumerate()
        .map(|(i, name)| ZoneInfo { name: name.clone(), hosts: hosts.iter().filter(|h| h.0 == i as u16).map(|h| h.1).sum() })
        .collect();
    Ok((NetModel::new(g, zones, zone_of, &rules, origin), info))
}
