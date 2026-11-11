//! Synthetic directory as `ldapsearch` LDIF (binary values base64, lines
//! folded at 76 columns), for benchmarking the raw-LDAP ingest path.
//!
//! Every object carries objectSid / objectGUID and an `nTSecurityDescriptor`
//! shaped like a real default DACL (owner + ~16 ACEs, mostly read-only grants
//! that produce no edges), so parse cost per object is realistic.

use super::{Rng, SynthConfig, SynthSummary, DOMAIN_SID};
use anyhow::Result;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

const BASE: &str = "DC=synth,DC=local";

fn sid_bytes(s: &str) -> Vec<u8> {
    let p: Vec<&str> = s.split('-').collect();
    let subs: Vec<u32> = p[3..].iter().map(|x| x.parse().unwrap_or(0)).collect();
    let mut v = vec![p[1].parse().unwrap_or(1), subs.len() as u8];
    v.extend_from_slice(&p[2].parse::<u64>().unwrap_or(0).to_be_bytes()[2..]);
    for x in subs {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

/// `(mask, object type GUID bytes, trustee)`
type Ace<'a> = (u32, Option<[u8; 16]>, &'a [u8]);

fn sd(owner: &[u8], aces: &[Ace]) -> Vec<u8> {
    let mut acl = Vec::with_capacity(aces.len() * 48);
    for (mask, ot, sid) in aces {
        let ty = if ot.is_some() { 5u8 } else { 0 };
        let size = 8 + if ot.is_some() { 4 + 16 } else { 0 } + sid.len();
        acl.extend_from_slice(&[ty, 0x12]); // inherited + container-inherit
        acl.extend_from_slice(&(size as u16).to_le_bytes());
        acl.extend_from_slice(&mask.to_le_bytes());
        if let Some(g) = ot {
            acl.extend_from_slice(&1u32.to_le_bytes());
            acl.extend_from_slice(g);
        }
        acl.extend_from_slice(sid);
    }
    let mut out = vec![1u8, 0, 0x04, 0x84]; // self-relative, DACL present, auto-inherited
    let dacl_off = 20 + owner.len();
    for off in [20u32, 0, 0, dacl_off as u32] {
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(owner);
    out.extend_from_slice(&[2, 0]);
    out.extend_from_slice(&((acl.len() + 8) as u16).to_le_bytes());
    out.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&acl);
    out
}

fn b64(data: &[u8], out: &mut String) {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
}

struct Writer {
    w: BufWriter<File>,
    line: String,
    bytes: u64,
}

impl Writer {
    /// Write `name: value` (or `name:: base64`), folded at 76 columns.
    fn attr(&mut self, name: &str, value: &str) -> std::io::Result<()> {
        self.line.clear();
        self.line.push_str(name);
        self.line.push_str(": ");
        self.line.push_str(value);
        self.flush_line()
    }
    fn bin(&mut self, name: &str, value: &[u8]) -> std::io::Result<()> {
        self.line.clear();
        self.line.push_str(name);
        self.line.push_str(":: ");
        b64(value, &mut self.line);
        self.flush_line()
    }
    fn flush_line(&mut self) -> std::io::Result<()> {
        let b = self.line.as_bytes();
        let mut first = true;
        let mut i = 0;
        while i < b.len() {
            let take = if first { 76 } else { 75 }.min(b.len() - i);
            if !first {
                self.w.write_all(b" ")?;
            }
            self.w.write_all(&b[i..i + take])?;
            self.w.write_all(b"\n")?;
            self.bytes += take as u64 + 1 + u64::from(!first);
            i += take;
            first = false;
        }
        Ok(())
    }
    fn end(&mut self) -> std::io::Result<()> {
        self.bytes += 1;
        self.w.write_all(b"\n")
    }
}

fn guid(n: u64) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..8].copy_from_slice(&n.to_le_bytes());
    g[8..].copy_from_slice(&(n ^ 0x5a5a_5a5a_5a5a_5a5a).to_le_bytes());
    g
}

/// Write one LDIF file with `cfg.users` users, `cfg.computers` computers and
/// `cfg.groups` groups (plus the domain and a few containers).
pub fn generate_ldif(cfg: &SynthConfig, out: &Path) -> Result<SynthSummary> {
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let (users, computers, groups) = (cfg.users.max(10), cfg.computers.max(4), cfg.groups.max(20));
    let mut rng = Rng(cfg.seed);
    let mut w = Writer { w: BufWriter::with_capacity(8 << 20, File::create(out)?), line: String::new(), bytes: 0 };
    let mut summary = SynthSummary { files: vec![out.to_path_buf()], ..Default::default() };
    summary.service_account = "SVC_BACKUP@SYNTH.LOCAL".into();

    let rid_user = |i: u32| 100_000 + i as u64;
    let rid_group = |j: u32| 100_000 + users as u64 + j as u64;
    let rid_comp = |c: u32| 100_000 + users as u64 + groups as u64 + c as u64;
    let s = |rid: u64| sid_bytes(&format!("{DOMAIN_SID}-{rid}"));
    let (da, ea, du, auth, acc_ops, self_sid, admins) = (
        s(512),
        s(519),
        s(513),
        sid_bytes("S-1-5-11"),
        sid_bytes("S-1-5-32-548"),
        sid_bytes("S-1-5-10"),
        sid_bytes("S-1-5-32-544"),
    );
    // Property-set GUIDs (wire layout irrelevant for size realism).
    let ps: Vec<[u8; 16]> = (0..6).map(|k| guid(0xABCD_0000 + k)).collect();
    let base_aces = |extra: &[Ace<'_>]| -> Vec<u8> {
        let mut a: Vec<Ace> = vec![
            (0xF01FF, None, &da),
            (0xF01FF, None, &ea),
            (0xF01FF, None, &acc_ops),
            (0x20094, None, &auth),
            (0x20094, None, &admins),
            (0x10, Some(ps[0]), &auth),
            (0x10, Some(ps[1]), &auth),
            (0x10, Some(ps[2]), &auth),
            (0x10, Some(ps[3]), &du),
            (0x20, Some(ps[4]), &self_sid),
            (0x20, Some(ps[5]), &self_sid),
            (0x100, Some(ps[0]), &self_sid),
            (0x20094, None, &self_sid),
            (0x30, Some(ps[1]), &admins),
        ];
        a.extend_from_slice(extra);
        sd(&da, &a)
    };

    // ---- membership: each user in 1–4 groups, 30% of groups nested.
    let mut members: Vec<Vec<String>> = vec![Vec::new(); groups as usize];
    let udn = |i: u32| format!("CN=user{i},OU=People,{BASE}");
    let gdn = |j: u32| format!("CN=group{j},OU=Groups,{BASE}");
    for i in 0..users {
        for _ in 0..rng.range(1, 5) {
            members[rng.below(groups) as usize].push(udn(i));
        }
    }
    for j in 1..groups {
        if rng.chance(0.3) {
            members[rng.below(j) as usize].push(gdn(j));
        }
    }

    w.w.write_all(b"version: 1\n\n")?;
    // ---- domain + containers
    let svc = s(rid_user(users - 1));
    // DS-Replication-Get-Changes(-All), wire layout: svc_backup can DCSync.
    let get_changes = [0xaa, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2];
    let mut get_changes_all = get_changes;
    get_changes_all[0] = 0xad;
    let dom_sd = base_aces(&[(0x100, Some(get_changes), &svc), (0x100, Some(get_changes_all), &svc)]);
    w.attr("dn", BASE)?;
    for c in ["top", "domain", "domainDNS"] {
        w.attr("objectClass", c)?;
    }
    w.bin("objectSid", &sid_bytes(DOMAIN_SID))?;
    w.bin("objectGUID", &guid(0))?;
    w.bin("nTSecurityDescriptor", &dom_sd)?;
    w.end()?;
    for (k, ou) in ["People", "Groups", "Workstations"].iter().enumerate() {
        w.attr("dn", &format!("OU={ou},{BASE}"))?;
        w.attr("objectClass", "top")?;
        w.attr("objectClass", "organizationalUnit")?;
        w.attr("name", ou)?;
        w.bin("objectGUID", &guid(10 + k as u64))?;
        w.bin("nTSecurityDescriptor", &base_aces(&[]))?;
        w.end()?;
    }
    summary.objects = 4;

    let mut extra_sid = Vec::new();
    // ---- users
    for i in 0..users {
        let name = if i == users - 1 { "svc_backup".to_string() } else { format!("user{i}") };
        w.attr("dn", &udn(i))?;
        for c in ["top", "person", "organizationalPerson", "user"] {
            w.attr("objectClass", c)?;
        }
        w.attr("cn", &format!("user{i}"))?;
        w.attr("sAMAccountName", &name)?;
        w.attr("userPrincipalName", &format!("{name}@synth.local"))?;
        w.attr("description", "Synthetic account generated for ingest benchmarks")?;
        w.attr("userAccountControl", if rng.chance(0.05) { "514" } else { "66048" })?;
        w.attr("primaryGroupID", "513")?;
        w.attr("whenCreated", "20240102030405.0Z")?;
        w.attr("pwdLastSet", "133500000000000000")?;
        w.attr("lastLogonTimestamp", "133600000000000000")?;
        if rng.chance(0.01) {
            w.attr("servicePrincipalName", &format!("MSSQLSvc/sql{i}.synth.local:1433"))?;
        }
        w.bin("objectSid", &s(rid_user(i)))?;
        w.bin("objectGUID", &guid(1_000_000 + i as u64))?;
        extra_sid.clear();
        if rng.chance(0.01) {
            extra_sid = s(rid_group(rng.below(groups)));
        }
        let extra: Vec<Ace> = if extra_sid.is_empty() { vec![] } else { vec![(0xF01FF, None, &extra_sid)] };
        w.bin("nTSecurityDescriptor", &base_aces(&extra))?;
        w.end()?;
    }
    // ---- groups
    for (j, m) in members.iter().enumerate() {
        let j = j as u32;
        w.attr("dn", &gdn(j))?;
        w.attr("objectClass", "top")?;
        w.attr("objectClass", "group")?;
        w.attr("cn", &format!("group{j}"))?;
        w.attr("sAMAccountName", &format!("group{j}"))?;
        w.attr("whenCreated", "20240102030405.0Z")?;
        for dn in m {
            w.attr("member", dn)?;
        }
        w.bin("objectSid", &s(rid_group(j)))?;
        w.bin("objectGUID", &guid(3_000_000 + j as u64))?;
        w.bin("nTSecurityDescriptor", &base_aces(&[]))?;
        w.end()?;
    }
    // ---- computers
    for c in 0..computers {
        w.attr("dn", &format!("CN=WS{c},OU=Workstations,{BASE}"))?;
        for cl in ["top", "person", "organizationalPerson", "user", "computer"] {
            w.attr("objectClass", cl)?;
        }
        w.attr("cn", &format!("WS{c}"))?;
        w.attr("sAMAccountName", &format!("WS{c}$"))?;
        w.attr("dNSHostName", &format!("ws{c}.synth.local"))?;
        w.attr("userAccountControl", "4096")?;
        w.attr("primaryGroupID", "515")?;
        w.attr("operatingSystem", "Windows 11 Enterprise")?;
        w.attr("whenCreated", "20240102030405.0Z")?;
        w.bin("objectSid", &s(rid_comp(c)))?;
        w.bin("objectGUID", &guid(5_000_000 + c as u64))?;
        w.bin("nTSecurityDescriptor", &base_aces(&[]))?;
        w.end()?;
    }
    w.w.flush()?;
    summary.objects += users as u64 + groups as u64 + computers as u64;
    summary.bytes = w.bytes + "version: 1\n\n".len() as u64;
    Ok(summary)
}
