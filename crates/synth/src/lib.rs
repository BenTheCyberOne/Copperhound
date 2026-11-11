//! Synthetic Active Directory generator emitting SharpHound v6-format JSON.
//!
//! Produces a plausible structure — nested groups, local admin rights,
//! sessions, a few ACL misconfigurations and a DCSync-capable service account —
//! so ingest and analysis can be benchmarked at any scale without real data.
//!
//! Also covers the trust and hybrid derivations: a child domain
//! (SameForestTrust), a cross-forest trust without SID filtering and with TGT
//! delegation (SpoofSIDHistory / AbuseTGTDelegation), unconstrained delegation
//! workstations (CoerceToTGT), an Entra Connect server with MSOL_ / Sync_
//! accounts, AZUREADSSOACC, and an AzureHound file with synced users and a
//! synced group (SyncedTo*, SeamlessSSO, EntraConnectCredentials).

mod ldif;
pub use ldif::generate_ldif;

use anyhow::Result;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub const DOMAIN_SID: &str = "S-1-5-21-1000000001-2000000002-3000000003";
pub const DOMAIN_NAME: &str = "SYNTH.LOCAL";
/// Child domain in the same forest (parent-child trust).
pub const CHILD_SID: &str = "S-1-5-21-1000000001-2000000002-3000000004";
pub const CHILD_NAME: &str = "CHILD.SYNTH.LOCAL";
/// Entra ID tenant synchronised from SYNTH.LOCAL by Entra Connect on AADC01.
pub const TENANT_ID: &str = "5E7A0000-0000-4000-8000-000000000001";
/// Name of the Entra Connect server (a workstation-index computer).
pub const CONNECT_HOST: &str = "AADC01";
const PRIV: u32 = 10;

#[derive(Clone, Debug)]
pub struct SynthConfig {
    pub users: u32,
    pub computers: u32,
    pub groups: u32,
    pub seed: u64,
}

/// Optional extras for [`generate_with`]. The defaults reproduce [`generate`].
#[derive(Clone, Debug, Default)]
pub struct SynthOptions {
    /// Spread users and computers over this many `domain` property values
    /// (`SYNTH.LOCAL`, `D1.SYNTH.LOCAL`, ...). Structure (SIDs, groups) stays
    /// one domain; only the `domain` property and the name suffix change.
    pub domains: u32,
    /// Emit realistic collector properties (samaccountname, SPNs, logon
    /// timestamps, operating systems, descriptions, disabled accounts) for
    /// property-filter benchmarks.
    pub rich_props: bool,
}

const OPERATING_SYSTEMS: &[&str] = &[
    "Windows 10 Enterprise",
    "Windows 11 Enterprise",
    "Windows Server 2016 Standard",
    "Windows Server 2019 Datacenter",
    "Windows Server 2022 Datacenter",
    "Windows 7 Professional",
    "Ubuntu 22.04",
];
/// 2024-01-01T00:00:00Z; synthetic timestamps fall in the two years before.
const NOW: u64 = 1_704_067_200;

#[derive(Debug, Default)]
pub struct SynthSummary {
    pub files: Vec<PathBuf>,
    pub objects: u64,
    pub bytes: u64,
    /// Name of the service account that is granted DCSync rights.
    pub service_account: String,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u32) -> u32 {
        (((self.next() >> 32) * n as u64) >> 32) as u32
    }
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.below(hi - lo)
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

struct Layout {
    users: u32,
    groups: u32,
}
impl Layout {
    fn user(&self, i: u32) -> u64 {
        100_000 + i as u64
    }
    fn group(&self, j: u32) -> u64 {
        100_000 + self.users as u64 + j as u64
    }
    fn computer(&self, c: u32) -> u64 {
        100_000 + self.users as u64 + self.groups as u64 + c as u64
    }
}

/// AD Entra Connect sync account (user index `users - 2`).
const MSOL: &str = "MSOL_1A2B3C4D5E6F";
/// Synced users are those with `index % 10 == SYNC_MOD`; the first one holds
/// Global Administrator through its cloud identity.
const SYNC_MOD: u32 = 6;

const USER: u8 = 0;
const GROUP: u8 = 1;
fn ty(t: u8) -> &'static str {
    if t == USER {
        "User"
    } else {
        "Group"
    }
}

fn open(out: &Path, name: &str, files: &mut Vec<PathBuf>) -> Result<BufWriter<File>> {
    let p = out.join(name);
    files.push(p.clone());
    Ok(BufWriter::with_capacity(8 << 20, File::create(p)?))
}

pub fn generate(cfg: &SynthConfig, out: &Path) -> Result<SynthSummary> {
    generate_with(cfg, &SynthOptions::default(), out)
}

/// [`generate`] with [`SynthOptions`].
pub fn generate_with(cfg: &SynthConfig, opts: &SynthOptions, out: &Path) -> Result<SynthSummary> {
    std::fs::create_dir_all(out)?;
    let domains: Vec<String> = (0..opts.domains.max(1))
        .map(|k| if k == 0 { DOMAIN_NAME.to_string() } else { format!("D{k}.{DOMAIN_NAME}") })
        .collect();
    let dom = |i: u32, special: bool| -> &str {
        if special {
            DOMAIN_NAME
        } else {
            &domains[(i as usize) % domains.len()]
        }
    };
    let users = cfg.users.max(10);
    let groups = cfg.groups.max(PRIV + 10);
    let computers = cfg.computers.max(4);
    let l = Layout { users, groups };
    let mut rng = Rng(cfg.seed);
    let mut summary = SynthSummary::default();
    let regular = groups - PRIV;
    let svc = users - 1;
    let msol = users - 2;
    summary.service_account = format!("SVC_BACKUP@{DOMAIN_NAME}");

    // ---- membership model
    let mut members: Vec<Vec<(u64, u8)>> = vec![Vec::new(); groups as usize];
    let mut da: Vec<(u64, u8)> = (0..5).map(|i| (l.user(i), USER)).collect();
    da.extend((0..5).map(|j| (l.group(j), GROUP)));
    for g in members.iter_mut().take(PRIV as usize) {
        for _ in 0..3 {
            g.push((l.user(rng.below(users)), USER));
        }
    }
    for i in 0..users {
        for _ in 0..rng.range(1, 5) {
            members[(PRIV + rng.below(regular)) as usize].push((l.user(i), USER));
        }
    }
    for j in PRIV + 1..groups {
        if rng.chance(0.3) {
            let parent = rng.range(PRIV, j);
            members[parent as usize].push((l.group(j), GROUP));
        }
    }
    // Misconfiguration: a regular group nested into a privileged group.
    members[0].push((l.group(groups - 1), GROUP));

    // ---- users
    let mut w = open(out, "synth_users.json", &mut summary.files)?;
    w.write_all(b"{\"data\":[")?;
    for i in 0..users {
        if i > 0 {
            w.write_all(b",")?;
        }
        let rid = l.user(i);
        let name = if i == svc {
            "SVC_BACKUP".to_string()
        } else if i == msol {
            MSOL.to_string()
        } else {
            format!("USER{i}")
        };
        let desc = if i == msol {
            format!(",\"description\":\"Account created by Microsoft Azure Active Directory Connect with installation identifier 1a2b3c4d5e6f running on computer {CONNECT_HOST} configured to synchronize to tenant synth.onmicrosoft.com.\"")
        } else {
            String::new()
        };
        let adm = i < 5;
        let d = dom(i, adm || i == svc || !desc.is_empty());
        let mut extra = String::new();
        let mut enabled = true;
        if opts.rich_props {
            enabled = adm || i == svc || !rng.chance(0.12);
            let spn = i == svc || rng.chance(0.03);
            let lastlogon = NOW - rng.below(2 * 365 * 86_400) as u64;
            let pwdlastset = lastlogon - rng.below(365 * 86_400) as u64;
            let sam = name.to_ascii_lowercase();
            extra = format!(
                r#","samaccountname":"{sam}","hasspn":{spn},"lastlogon":{lastlogon},"pwdlastset":{pwdlastset},"dontreqpreauth":{},"sensitive":false"#,
                rng.chance(0.005)
            );
            if spn {
                extra.push_str(&format!(r#","serviceprincipalnames":["MSSQLSvc/sql{i}.{d}:1433","HTTP/app{i}.{d}"]"#));
            } else {
                extra.push_str(r#","serviceprincipalnames":[]"#);
            }
            if !desc.is_empty() {
                // Keep the Entra Connect description written above.
            } else if rng.chance(0.1) {
                extra.push_str(&format!(r#","description":"Service account for application {}""#, rng.below(5000)));
            } else {
                extra.push_str(r#","description":null"#);
            }
        }
        write!(
            w,
            r#"{{"ObjectIdentifier":"{DOMAIN_SID}-{rid}","Properties":{{"name":"{name}@{d}","domain":"{d}","enabled":{enabled},"admincount":{adm}{desc}{extra}}},"PrimaryGroupSID":"{DOMAIN_SID}-513","ContainedBy":{{"ObjectIdentifier":"{DOMAIN_SID}","ObjectType":"Domain"}},"AllowedToDelegate":[],"HasSIDHistory":[],"SPNTargets":[],"IsDeleted":false,"IsACLProtected":false,"Aces":[{{"PrincipalSID":"{DOMAIN_SID}-512","PrincipalType":"Group","RightName":"GenericAll","IsInherited":true}}"#
        )?;
        if rng.chance(0.01) {
            let g = l.group(PRIV + rng.below(regular));
            let right = if rng.chance(0.5) {
                "GenericWrite"
            } else {
                "ForceChangePassword"
            };
            write!(
                w,
                r#",{{"PrincipalSID":"{DOMAIN_SID}-{g}","PrincipalType":"Group","RightName":"{right}","IsInherited":false}}"#
            )?;
        }
        w.write_all(b"]}")?;
    }
    write!(
        w,
        r#"],"meta":{{"methods":0,"type":"users","count":{users},"version":6}}}}"#
    )?;
    w.flush()?;
    summary.objects += users as u64;

    // ---- groups
    let mut w = open(out, "synth_groups.json", &mut summary.files)?;
    w.write_all(b"{\"data\":[")?;
    let write_group = |w: &mut BufWriter<File>,
                       sid: &str,
                       name: &str,
                       ms: &[(u64, u8)],
                       aces: &str,
                       first: bool|
     -> Result<()> {
        if !first {
            w.write_all(b",")?;
        }
        write!(
            w,
            r#"{{"ObjectIdentifier":"{sid}","Properties":{{"name":"{name}@{DOMAIN_NAME}","domain":"{DOMAIN_NAME}"}},"Members":["#
        )?;
        for (k, (rid, t)) in ms.iter().enumerate() {
            if k > 0 {
                w.write_all(b",")?;
            }
            write!(
                w,
                r#"{{"ObjectIdentifier":"{DOMAIN_SID}-{rid}","ObjectType":"{}"}}"#,
                ty(*t)
            )?;
        }
        write!(w, r#"],"Aces":[{aces}],"IsDeleted":false}}"#)?;
        Ok(())
    };
    let ace_target = l.group(PRIV + rng.below(regular));
    for j in 0..groups {
        let name = if j < PRIV {
            format!("PRIVGROUP{j}")
        } else {
            format!("GROUP{j}")
        };
        let aces = if j == 1 {
            format!(
                r#"{{"PrincipalSID":"{DOMAIN_SID}-{ace_target}","PrincipalType":"Group","RightName":"AddMember","IsInherited":false}}"#
            )
        } else {
            String::new()
        };
        write_group(
            &mut w,
            &format!("{DOMAIN_SID}-{}", l.group(j)),
            &name,
            &members[j as usize],
            &aces,
            j == 0,
        )?;
    }
    for (rid, name, ms) in [
        (512, "DOMAIN ADMINS", da.clone()),
        (513, "DOMAIN USERS", vec![]),
        (515, "DOMAIN COMPUTERS", vec![]),
        (516, "DOMAIN CONTROLLERS", vec![]),
        (519, "ENTERPRISE ADMINS", vec![(l.user(0), USER)]),
    ] {
        write_group(&mut w, &format!("{DOMAIN_SID}-{rid}"), name, &ms, "", false)?;
    }
    write!(
        w,
        r#"],"meta":{{"methods":0,"type":"groups","count":{},"version":6}}}}"#,
        groups + 5
    )?;
    w.flush()?;
    summary.objects += groups as u64 + 5;

    // ---- computers
    let mut w = open(out, "synth_computers.json", &mut summary.files)?;
    w.write_all(b"{\"data\":[")?;
    for c in 0..computers {
        if c > 0 {
            w.write_all(b",")?;
        }
        let csid = format!("{DOMAIN_SID}-{}", l.computer(c));
        let dc = c < 2;
        let name = if dc {
            format!("DC{c}")
        } else if c == 2 {
            CONNECT_HOST.to_string()
        } else {
            format!("WS{c}")
        };
        let pg = if dc { 516 } else { 515 };
        let d = dom(c, dc || c % 50 == 0 || c < 20);
        let mut extra = String::new();
        let mut enabled = true;
        // DCs, plus a few legacy servers trusted for unconstrained delegation.
        let mut unconstrained = dc || c % 97 == 5;
        if opts.rich_props {
            enabled = dc || !rng.chance(0.05);
            unconstrained = unconstrained || rng.chance(0.002);
            let os = OPERATING_SYSTEMS[if dc { 4 } else { rng.below(OPERATING_SYSTEMS.len() as u32) as usize }];
            let ts = NOW - rng.below(400 * 86_400) as u64;
            extra = format!(
                r#","samaccountname":"{name}$","operatingsystem":"{os}","lastlogontimestamp":{ts},"haslaps":{}"#,
                rng.chance(0.6)
            );
        }
        write!(
            w,
            r#"{{"ObjectIdentifier":"{csid}","Properties":{{"name":"{name}.{d}","domain":"{d}","enabled":{enabled},"unconstraineddelegation":{unconstrained}{extra}}},"PrimaryGroupSID":"{DOMAIN_SID}-{pg}","ContainedBy":{{"ObjectIdentifier":"{DOMAIN_SID}","ObjectType":"Domain"}},"Aces":[],"AllowedToDelegate":[],"AllowedToAct":[],"Sessions":{{"Collected":true,"FailureReason":null,"Results":["#
        )?;
        let mut sess: Vec<u32> = (0..rng.below(3)).map(|_| rng.below(users)).collect();
        if !dc && c % 50 == 0 {
            sess.push(rng.below(5)); // a Domain Admin logged on to a workstation
        }
        for (k, u) in sess.iter().enumerate() {
            if k > 0 {
                w.write_all(b",")?;
            }
            write!(
                w,
                r#"{{"ComputerSID":"{csid}","UserSID":"{DOMAIN_SID}-{}"}}"#,
                l.user(*u)
            )?;
        }
        write!(
            w,
            r#"]}},"PrivilegedSessions":{{"Collected":true,"FailureReason":null,"Results":[]}},"RegistrySessions":{{"Collected":true,"FailureReason":null,"Results":[]}},"LocalGroups":[{{"ObjectIdentifier":"{csid}-544","Name":"ADMINISTRATORS@{name}.{DOMAIN_NAME}","Collected":true,"FailureReason":null,"Results":[{{"ObjectIdentifier":"{DOMAIN_SID}-512","ObjectType":"Group"}}"#
        )?;
        if !dc {
            let helpdesk = l.group(PRIV + c % regular);
            write!(
                w,
                r#",{{"ObjectIdentifier":"{DOMAIN_SID}-{helpdesk}","ObjectType":"Group"}}"#
            )?;
        }
        w.write_all(b"]}")?;
        if !dc && rng.chance(0.2) {
            let g = l.group(PRIV + rng.below(regular));
            write!(
                w,
                r#",{{"ObjectIdentifier":"{csid}-555","Name":"REMOTE DESKTOP USERS@{name}.{DOMAIN_NAME}","Collected":true,"FailureReason":null,"Results":[{{"ObjectIdentifier":"{DOMAIN_SID}-{g}","ObjectType":"Group"}}]}}"#
            )?;
        }
        w.write_all(b"],\"IsDeleted\":false}")?;
    }
    // Seamless SSO computer account (no host behind it).
    write!(
        w,
        r#",{{"ObjectIdentifier":"{DOMAIN_SID}-{}","Properties":{{"name":"AZUREADSSOACC.{DOMAIN_NAME}","domain":"{DOMAIN_NAME}","samaccountname":"AZUREADSSOACC$","enabled":true}},"PrimaryGroupSID":"{DOMAIN_SID}-515","ContainedBy":{{"ObjectIdentifier":"{DOMAIN_SID}","ObjectType":"Domain"}},"Aces":[],"IsDeleted":false}}"#,
        l.computer(computers)
    )?;
    write!(
        w,
        r#"],"meta":{{"methods":0,"type":"computers","count":{},"version":6}}}}"#,
        computers + 1
    )?;
    w.flush()?;
    summary.objects += computers as u64 + 1;

    // ---- domain (meta first, to exercise both layouts)
    let mut w = open(out, "synth_domains.json", &mut summary.files)?;
    let svc_sid = format!("{DOMAIN_SID}-{}", l.user(svc));
    let msol_sid = format!("{DOMAIN_SID}-{}", l.user(msol));
    let ace = |sid: &str, t: &str, right: &str| {
        format!(
            r#"{{"PrincipalSID":"{sid}","PrincipalType":"{t}","RightName":"{right}","IsInherited":false}}"#
        )
    };
    let aces = [
        ace(&format!("{DOMAIN_SID}-516"), "Group", "GetChanges"),
        ace(&format!("{DOMAIN_SID}-516"), "Group", "GetChangesAll"),
        ace(&format!("{DOMAIN_SID}-519"), "Group", "GenericAll"),
        ace(&svc_sid, "User", "GetChanges"),
        ace(&svc_sid, "User", "GetChangesAll"),
        ace(&msol_sid, "User", "GetChanges"),
        ace(&msol_sid, "User", "GetChangesAll"),
    ]
    .join(",");
    let trust = |sid: &str, name: &str, ty: &str, sidf: bool, tgt: bool| {
        format!(
            r#"{{"TargetDomainSid":"{sid}","TargetDomainName":"{name}","IsTransitive":true,"SidFilteringEnabled":{sidf},"TGTDelegationEnabled":{tgt},"TrustDirection":"Bidirectional","TrustType":"{ty}"}}"#
        )
    };
    let trusts = [
        trust("S-1-5-21-9-9-9", "PARTNER.LOCAL", "External", true, false),
        trust(CHILD_SID, CHILD_NAME, "ParentChild", false, false),
        // Misconfigured forest trust: SID history allowed, TGT delegation on.
        trust("S-1-5-21-8-8-8", "FABRIKAM.LOCAL", "Forest", false, true),
    ]
    .join(",");
    let child_trusts = trust(DOMAIN_SID, DOMAIN_NAME, "ParentChild", false, false);
    write!(
        w,
        r#"{{"meta":{{"methods":0,"type":"domains","count":2,"version":6}},"data":[{{"ObjectIdentifier":"{DOMAIN_SID}","Properties":{{"name":"{DOMAIN_NAME}","domain":"{DOMAIN_NAME}","functionallevel":"2016"}},"Aces":[{aces}],"ChildObjects":[],"Links":[],"Trusts":[{trusts}],"IsDeleted":false}},{{"ObjectIdentifier":"{CHILD_SID}","Properties":{{"name":"{CHILD_NAME}","domain":"{CHILD_NAME}","functionallevel":"2016"}},"Aces":[],"ChildObjects":[],"Links":[],"Trusts":[{child_trusts}],"IsDeleted":false}}]}}"#
    )?;
    w.flush()?;
    summary.objects += 2;

    // ---- AzureHound: tenant synchronised from SYNTH.LOCAL
    let mut w = open(out, "synth_azurehound.json", &mut summary.files)?;
    let t = TENANT_ID;
    let tn = "SYNTH";
    const GA: &str = "62e90394-69f5-4237-9190-012177145e10";
    const DIR_SYNC: &str = "d29b2b05-8046-44ba-8758-1e26182fcf32";
    const USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
    let mut items: Vec<String> = vec![format!(r#"{{"kind":"AZTenant","data":{{"tenantId":"{t}","displayName":"{tn}"}}}}"#)];
    let az_user = |id: &str, upn: &str, display: &str, extra: &str| {
        format!(
            r#"{{"kind":"AZUser","data":{{"id":"{id}","userPrincipalName":"{upn}","displayName":"{display}","accountEnabled":true,"tenantId":"{t}","tenantName":"{tn}"{extra}}}}}"#
        )
    };
    for i in (SYNC_MOD..users).step_by(10) {
        let sid = format!("{DOMAIN_SID}-{}", l.user(i));
        items.push(az_user(
            &format!("az-u-{i}"),
            &format!("user{i}@synth.onmicrosoft.com"),
            &format!("USER{i}"),
            &format!(r#","onPremisesSecurityIdentifier":"{sid}","onPremisesSyncEnabled":true"#),
        ));
    }
    items.push(az_user(
        "az-sync",
        &format!("Sync_{CONNECT_HOST}_1a2b3c4d5e6f@synth.onmicrosoft.com"),
        "On-Premises Directory Synchronization Service Account",
        "",
    ));
    items.push(az_user("az-admin", "admin@synth.onmicrosoft.com", "Cloud Admin", ""));
    let sync_group = l.group(PRIV);
    items.push(format!(
        r#"{{"kind":"AZGroup","data":{{"id":"az-g-sync","displayName":"GROUP{PRIV}","isAssignableToRole":true,"securityEnabled":true,"onPremisesSecurityIdentifier":"{DOMAIN_SID}-{sync_group}","onPremisesSyncEnabled":true,"tenantId":"{t}","tenantName":"{tn}"}}}}"#
    ));
    for (role, display, principals) in [
        (GA, "Global Administrator", vec!["az-admin".to_string(), format!("az-u-{SYNC_MOD}")]),
        (DIR_SYNC, "Directory Synchronization Accounts", vec!["az-sync".to_string()]),
        (USER_ADMIN, "User Administrator", vec!["az-g-sync".to_string()]),
    ] {
        items.push(format!(
            r#"{{"kind":"AZRole","data":{{"id":"{role}","templateId":"{role}","displayName":"{display}","tenantId":"{t}","tenantName":"{tn}"}}}}"#
        ));
        let assignments: Vec<String> = principals
            .iter()
            .map(|p| format!(r#"{{"principalId":"{p}","roleDefinitionId":"{role}","directoryScopeId":"/"}}"#))
            .collect();
        items.push(format!(
            r#"{{"kind":"AZRoleAssignment","data":{{"roleDefinitionId":"{role}","tenantId":"{t}","roleAssignments":[{}]}}}}"#,
            assignments.join(",")
        ));
    }
    write!(
        w,
        r#"{{"data":[{}],"meta":{{"methods":0,"type":"azure","count":{},"version":5}}}}"#,
        items.join(","),
        items.len()
    )?;
    w.flush()?;
    summary.objects += items.len() as u64;

    summary.bytes = summary
        .files
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    Ok(summary)
}
