//! Binary SIDs, GUIDs and self-relative security descriptors ([MS-DTYP]
//! 2.4.2.2 SID, 2.4.6 SECURITY_DESCRIPTOR, 2.4.5 ACL, 2.4.4 ACEs) and the
//! SharpHound ACE → edge mapping.
//!
//! The right mapping follows SharpHound CE `ACLProcessor.ProcessACL`
//! (SharpHoundCommon, `src/CommonLib/Processors/ACLProcessor.cs`): deny ACEs
//! and inherit-only ACEs are ignored, inherited ACEs restricted to another
//! object class are ignored, and each allowed ACE yields the rights below.

use ch_model::NodeKind;

pub type Guid = [u8; 16];

/// Parse `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` into the on-wire (mixed
/// endian) GUID byte layout, at compile time.
pub const fn guid(s: &str) -> Guid {
    const fn hex(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 36);
    // Byte i of the canonical text (hex pairs, dashes skipped).
    let mut canon = [0u8; 16];
    let mut i = 0;
    let mut j = 0;
    while i < 36 {
        if b[i] == b'-' {
            i += 1;
            continue;
        }
        canon[j] = hex(b[i]) << 4 | hex(b[i + 1]);
        j += 1;
        i += 2;
    }
    [
        canon[3], canon[2], canon[1], canon[0], canon[5], canon[4], canon[7], canon[6], canon[8], canon[9],
        canon[10], canon[11], canon[12], canon[13], canon[14], canon[15],
    ]
}

/// Wire GUID → uppercase canonical text (SharpHound object identifiers).
pub fn guid_string(g: &[u8]) -> Option<String> {
    if g.len() != 16 {
        return None;
    }
    Some(format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    ))
}

/// GUID attribute value: 16 raw bytes, or already text (some tools print it).
pub fn guid_value(v: &[u8]) -> Option<String> {
    if v.len() == 16 {
        return guid_string(v);
    }
    let s = std::str::from_utf8(v).ok()?.trim().trim_matches(['{', '}']);
    (s.len() == 36 && s.as_bytes()[8] == b'-').then(|| s.to_ascii_uppercase())
}

/// Length in bytes of the binary SID at the start of `b`.
pub fn sid_len(b: &[u8]) -> Option<usize> {
    let n = *b.get(1)? as usize;
    let len = 8 + 4 * n;
    (b.len() >= len && b[0] == 1 && n <= 15).then_some(len)
}

/// Binary SID → `S-1-5-21-…`.
pub fn sid_string(b: &[u8]) -> Option<String> {
    use std::fmt::Write;
    let len = sid_len(b)?;
    let mut auth: u64 = 0;
    for &x in &b[2..8] {
        auth = auth << 8 | x as u64;
    }
    let mut s = format!("S-1-{auth}");
    for i in 0..b[1] as usize {
        let o = 8 + 4 * i;
        let _ = write!(s, "-{}", u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]));
    }
    debug_assert!(len <= b.len());
    Some(s)
}

/// SID attribute value: binary, or already text (`S-1-…`).
pub fn sid_value(v: &[u8]) -> Option<String> {
    if v.starts_with(b"S-1-") || v.starts_with(b"s-1-") {
        return std::str::from_utf8(v).ok().map(|s| s.trim().to_ascii_uppercase());
    }
    sid_string(v)
}

/// Text SID → binary (tests and the snapshot writer).
pub fn sid_bytes(s: &str) -> Option<Vec<u8>> {
    let mut it = s.strip_prefix("S-")?.split('-');
    let rev: u8 = it.next()?.parse().ok()?;
    let auth: u64 = it.next()?.parse().ok()?;
    let subs: Vec<u32> = it.map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let mut v = vec![rev, subs.len() as u8];
    v.extend_from_slice(&auth.to_be_bytes()[2..]);
    for x in subs {
        v.extend_from_slice(&x.to_le_bytes());
    }
    Some(v)
}

pub const ACCESS_ALLOWED: u8 = 0x00;
pub const ACCESS_ALLOWED_OBJECT: u8 = 0x05;
pub const INHERIT_ONLY: u8 = 0x08;
pub const INHERITED: u8 = 0x10;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_PROTECTED: u16 = 0x1000;

#[derive(Debug, Clone)]
pub struct Ace<'a> {
    pub ty: u8,
    pub flags: u8,
    pub mask: u32,
    pub object_type: Option<Guid>,
    pub inherited_type: Option<Guid>,
    pub sid: &'a [u8],
}

#[derive(Debug, Default)]
pub struct Sd<'a> {
    pub control: u16,
    pub owner: Option<&'a [u8]>,
    pub dacl: Vec<Ace<'a>>,
}

impl Sd<'_> {
    pub fn protected(&self) -> bool {
        self.control & SE_DACL_PROTECTED != 0
    }
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn guid_at(b: &[u8], o: usize) -> Option<Guid> {
    b.get(o..o + 16)?.try_into().ok()
}

/// Parse a self-relative security descriptor. Malformed ACEs end the DACL
/// walk (everything parsed before them is kept).
pub fn parse(b: &[u8]) -> Option<Sd<'_>> {
    if b.len() < 20 || b[0] != 1 {
        return None;
    }
    let control = u16_at(b, 2)?;
    let owner_off = u32_at(b, 4)? as usize;
    let dacl_off = u32_at(b, 16)? as usize;
    let owner = (owner_off != 0).then(|| b.get(owner_off..)).flatten().filter(|s| sid_len(s).is_some());
    let mut dacl = Vec::new();
    if control & SE_DACL_PRESENT != 0 && dacl_off != 0 && dacl_off + 8 <= b.len() {
        let count = u16_at(b, dacl_off + 4)? as usize;
        let mut p = dacl_off + 8;
        for _ in 0..count {
            let (Some(&ty), Some(&flags), Some(size)) = (b.get(p), b.get(p + 1), u16_at(b, p + 2)) else { break };
            let size = size as usize;
            if size < 8 || p + size > b.len() {
                break;
            }
            let ace = &b[p..p + size];
            p += size;
            let Some(mask) = u32_at(ace, 4) else { break };
            let (object_type, inherited_type, sid_off) = match ty {
                ACCESS_ALLOWED => (None, None, 8),
                ACCESS_ALLOWED_OBJECT => {
                    let Some(of) = u32_at(ace, 8) else { break };
                    let mut o = 12;
                    let ot = if of & 1 != 0 {
                        o += 16;
                        guid_at(ace, o - 16)
                    } else {
                        None
                    };
                    let it = if of & 2 != 0 {
                        o += 16;
                        guid_at(ace, o - 16)
                    } else {
                        None
                    };
                    (ot, it, o)
                }
                _ => continue, // deny / audit / callback ACEs are not used
            };
            let Some(sid) = ace.get(sid_off..).filter(|s| sid_len(s).is_some()) else { continue };
            dacl.push(Ace { ty, flags, mask, object_type, inherited_type, sid });
        }
    }
    Some(Sd { control, owner, dacl })
}

// ---- access mask bits (ActiveDirectoryRights)
pub const RIGHT_DS_SELF: u32 = 0x8;
pub const RIGHT_DS_WRITE_PROPERTY: u32 = 0x20;
pub const RIGHT_DS_CONTROL_ACCESS: u32 = 0x100;
pub const WRITE_DAC: u32 = 0x40000;
pub const WRITE_OWNER: u32 = 0x80000;
/// `ActiveDirectoryRights.GenericAll` as stored (generic bits mapped).
pub const FULL_CONTROL: u32 = 0xF01FF;
/// `ActiveDirectoryRights.GenericWrite` = ReadControl | WriteProperty | Self.
pub const GENERIC_WRITE_AD: u32 = 0x20028;
const GENERIC_ALL_BIT: u32 = 0x1000_0000;
const GENERIC_WRITE_BIT: u32 = 0x4000_0000;

pub const ALL_GUID: Guid = [0; 16];
pub mod g {
    use super::{guid, Guid};
    pub const GET_CHANGES: Guid = guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
    pub const GET_CHANGES_ALL: Guid = guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
    pub const GET_CHANGES_FILTERED: Guid = guid("89e95b76-444d-4c62-991a-0facbeda640c");
    pub const FORCE_CHANGE_PASSWORD: Guid = guid("00299570-246d-11d0-a768-00aa006e0529");
    pub const MEMBER: Guid = guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
    pub const SPN: Guid = guid("f3a64788-5306-11d1-a9c5-0000f80367c1");
    pub const ALLOWED_TO_ACT: Guid = guid("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79");
    pub const USER_ACCOUNT_RESTRICTIONS: Guid = guid("4c164200-20c0-11d0-a768-00aa006e0529");
    pub const KEY_CREDENTIAL_LINK: Guid = guid("5b47d60f-6090-40b2-9f37-2a4de88f3063");
    pub const PKI_ENROLLMENT_FLAG: Guid = guid("d15ef7d8-f226-46db-ae79-b34e560bd12c");
    pub const PKI_NAME_FLAG: Guid = guid("ea1dddc4-60ff-416e-8cc0-17cee534bce7");
    pub const ENROLL: Guid = guid("0e10c968-78fb-11d2-90d4-00c04f79dc55");
    pub const GP_LINK: Guid = guid("f30e3bc1-9ff0-11d1-b603-0000f80367c1");

    // schemaIDGUIDs of the structural classes (for inherited object types)
    pub const C_USER: Guid = guid("bf967aba-0de6-11d0-a285-00aa003049e2");
    pub const C_INET_ORG_PERSON: Guid = guid("4828cc14-1437-45bc-9b07-ad6f015e5f28");
    pub const C_COMPUTER: Guid = guid("bf967a86-0de6-11d0-a285-00aa003049e2");
    pub const C_GROUP: Guid = guid("bf967a9c-0de6-11d0-a285-00aa003049e2");
    pub const C_DOMAIN: Guid = guid("19195a5b-6da0-11d0-afd3-00c04fd930c9");
    pub const C_GPO: Guid = guid("f30e3bc2-9ff0-11d1-b603-0000f80367c1");
    pub const C_OU: Guid = guid("bf967aa5-0de6-11d0-a285-00aa003049e2");
    pub const C_CONTAINER: Guid = guid("bf967a8b-0de6-11d0-a285-00aa003049e2");
    pub const C_GMSA: Guid = guid("7b8b558a-93a5-4af7-adca-c017e67f1057");
    pub const C_MSA: Guid = guid("ce206244-5827-4a86-ba1c-1c0c386c1b64");
    pub const C_CERT_TEMPLATE: Guid = guid("e5209ca2-3bba-11d2-90cc-00c04fd91ab1");
    pub const C_ENROLLMENT_SERVICE: Guid = guid("ee4aa692-3bba-11d2-90cc-00c04fd91ab1");
    pub const C_CERTIFICATION_AUTHORITY: Guid = guid("3fdfee50-47f4-11d1-a9c3-0000f80367c1");
    pub const C_ENTERPRISE_OID: Guid = guid("37cfd85c-6719-4ad8-8f9e-8678ba627563");
}

/// schemaIDGUID of the most specific structural class name, if well known.
pub fn class_guid(name: &str) -> Option<Guid> {
    let l = name.to_ascii_lowercase();
    Some(match l.as_str() {
        "user" => g::C_USER,
        "inetorgperson" => g::C_INET_ORG_PERSON,
        "computer" => g::C_COMPUTER,
        "group" => g::C_GROUP,
        "domaindns" => g::C_DOMAIN,
        "grouppolicycontainer" => g::C_GPO,
        "organizationalunit" => g::C_OU,
        "container" => g::C_CONTAINER,
        "msds-groupmanagedserviceaccount" => g::C_GMSA,
        "msds-managedserviceaccount" => g::C_MSA,
        "pkicertificatetemplate" => g::C_CERT_TEMPLATE,
        "pkienrollmentservice" => g::C_ENROLLMENT_SERVICE,
        "certificationauthority" => g::C_CERTIFICATION_AUTHORITY,
        "mspki-enterprise-oid" => g::C_ENTERPRISE_OID,
        _ => return None,
    })
}

/// Context of the object whose DACL is evaluated.
pub struct Target<'a> {
    pub kind: NodeKind,
    /// schemaIDGUID of the object's structural class.
    pub class: Option<Guid>,
    pub has_laps: bool,
    /// schemaIDGUIDs of the LAPS password attributes (forest specific).
    pub laps: &'a [Guid],
}

/// Rights an ACE grants on `t`, as SharpHound edge names. Empty when the ACE
/// does not apply to the object or grants nothing SharpHound models.
pub fn ace_rights(ace: &Ace, t: &Target, out: &mut Vec<&'static str>) {
    use NodeKind as K;
    if ace.flags & INHERIT_ONLY != 0 {
        return;
    }
    if let (Some(it), Some(cls)) = (ace.inherited_type, t.class) {
        if ace.flags & INHERITED != 0 && it != cls {
            return;
        }
    }
    let m = ace.mask;
    let ot = ace.object_type.unwrap_or(ALL_GUID);
    let all = ot == ALL_GUID;
    if m & FULL_CONTROL == FULL_CONTROL || m & GENERIC_ALL_BIT != 0 {
        if all {
            out.push("GenericAll");
        } else if t.kind == K::Computer && t.has_laps && t.laps.contains(&ot) {
            out.push("ReadLAPSPassword");
        }
        return;
    }
    if m & WRITE_DAC != 0 {
        out.push("WriteDacl");
    }
    if m & WRITE_OWNER != 0 {
        out.push("WriteOwner");
    }
    if m & RIGHT_DS_CONTROL_ACCESS != 0 {
        match t.kind {
            K::Domain => {
                if all {
                    out.push("AllExtendedRights");
                } else if ot == g::GET_CHANGES {
                    out.push("GetChanges");
                } else if ot == g::GET_CHANGES_ALL {
                    out.push("GetChangesAll");
                } else if ot == g::GET_CHANGES_FILTERED {
                    out.push("GetChangesInFilteredSet");
                }
            }
            K::User => {
                if all {
                    out.push("AllExtendedRights");
                } else if ot == g::FORCE_CHANGE_PASSWORD {
                    out.push("ForceChangePassword");
                }
            }
            K::Computer if t.has_laps => {
                if all {
                    out.push("AllExtendedRights");
                } else if t.laps.contains(&ot) {
                    out.push("ReadLAPSPassword");
                }
            }
            K::CertTemplate => {
                if all {
                    out.push("AllExtendedRights");
                } else if ot == g::ENROLL {
                    out.push("Enroll");
                }
            }
            K::EnterpriseCa if ot == g::ENROLL => out.push("Enroll"),
            _ => {}
        }
    }
    let gw = m & GENERIC_WRITE_AD == GENERIC_WRITE_AD || m & GENERIC_WRITE_BIT != 0;
    let wp = m & RIGHT_DS_WRITE_PROPERTY != 0;
    if gw || wp {
        if all {
            if t.kind != K::Container {
                out.push("GenericWrite");
            }
        } else {
            match t.kind {
                K::User if ot == g::SPN => out.push("WriteSPN"),
                K::User | K::Computer if ot == g::KEY_CREDENTIAL_LINK => out.push("AddKeyCredentialLink"),
                K::Computer if ot == g::ALLOWED_TO_ACT => out.push("AddAllowedToAct"),
                K::Computer if ot == g::USER_ACCOUNT_RESTRICTIONS => out.push("WriteAccountRestrictions"),
                K::Group if ot == g::MEMBER => out.push("AddMember"),
                K::CertTemplate if ot == g::PKI_ENROLLMENT_FLAG => out.push("WritePKIEnrollmentFlag"),
                K::CertTemplate if ot == g::PKI_NAME_FLAG => out.push("WritePKINameFlag"),
                K::Ou | K::Domain if ot == g::GP_LINK => out.push("WriteGPLink"),
                _ => {}
            }
        }
    } else if m & RIGHT_DS_SELF != 0 && t.kind == K::Group && ot == g::MEMBER {
        out.push("AddSelf");
    }
}

/// SIDs SharpHound never resolves to principals (`Helpers.IsSidFiltered`),
/// plus CREATOR OWNER and PRINCIPAL SELF, which only matter for inheritance.
pub fn sid_filtered(sid: &str) -> bool {
    const FILTERED: &[&str] = &[
        "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-2", "S-1-2-0", "S-1-5-18", "S-1-5-19",
        "S-1-5-20", "S-1-0-0", "S-1-0", "S-1-2-1", "S-1-3-0", "S-1-5-10",
    ];
    ["S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-"].iter().any(|p| sid.starts_with(p)) || FILTERED.contains(&sid)
}

/// Display name and kind of well-known SIDs that are not domain accounts.
pub fn well_known(sid: &str) -> Option<(&'static str, NodeKind)> {
    use NodeKind::{Group as G, User as U};
    Some(match sid {
        "S-1-1-0" => ("Everyone", G),
        "S-1-3-4" => ("Owner Rights", G),
        "S-1-5-1" => ("Dialup", G),
        "S-1-5-8" => ("Proxy", G),
        "S-1-5-9" => ("Enterprise Domain Controllers", G),
        "S-1-5-11" => ("Authenticated Users", G),
        "S-1-5-12" => ("Restricted Code", G),
        "S-1-5-13" => ("Terminal Server Users", G),
        "S-1-5-14" => ("Remote Interactive Logon", G),
        "S-1-5-15" => ("This Organization", G),
        "S-1-5-17" => ("IUSR", U),
        "S-1-5-113" => ("Local Account", U),
        "S-1-5-114" => ("Local Account and Member of Administrators Group", U),
        "S-1-5-1000" => ("Other Organization", G),
        "S-1-5-64-10" => ("NTLM Authentication", G),
        "S-1-5-64-14" => ("SChannel Authentication", G),
        "S-1-5-64-21" => ("Digest Authentication", G),
        "S-1-5-32-544" => ("Administrators", G),
        "S-1-5-32-545" => ("Users", G),
        "S-1-5-32-546" => ("Guests", G),
        "S-1-5-32-547" => ("Power Users", G),
        "S-1-5-32-548" => ("Account Operators", G),
        "S-1-5-32-549" => ("Server Operators", G),
        "S-1-5-32-550" => ("Print Operators", G),
        "S-1-5-32-551" => ("Backup Operators", G),
        "S-1-5-32-552" => ("Replicators", G),
        "S-1-5-32-554" => ("Pre-Windows 2000 Compatible Access", G),
        "S-1-5-32-555" => ("Remote Desktop Users", G),
        "S-1-5-32-556" => ("Network Configuration Operators", G),
        "S-1-5-32-557" => ("Incoming Forest Trust Builders", G),
        "S-1-5-32-558" => ("Performance Monitor Users", G),
        "S-1-5-32-559" => ("Performance Log Users", G),
        "S-1-5-32-560" => ("Windows Authorization Access Group", G),
        "S-1-5-32-561" => ("Terminal Server License Servers", G),
        "S-1-5-32-562" => ("Distributed COM Users", G),
        "S-1-5-32-568" => ("IIS_IUSRS", G),
        "S-1-5-32-569" => ("Cryptographic Operators", G),
        "S-1-5-32-573" => ("Event Log Readers", G),
        "S-1-5-32-574" => ("Certificate Service DCOM Access", G),
        "S-1-5-32-575" => ("RDS Remote Access Servers", G),
        "S-1-5-32-576" => ("RDS Endpoint Servers", G),
        "S-1-5-32-577" => ("RDS Management Servers", G),
        "S-1-5-32-578" => ("Hyper-V Administrators", G),
        "S-1-5-32-579" => ("Access Control Assistance Operators", G),
        "S-1-5-32-580" => ("Remote Management Users", G),
        "S-1-5-32-582" => ("Storage Replica Administrators", G),
        _ => return None,
    })
}

// ---- builders (tests and the snapshot writer)

/// Build a self-relative SD: owner + DACL of `(type, flags, mask, object type, sid)`.
pub fn build_sd(owner: &str, aces: &[(u8, u8, u32, Option<Guid>, &str)]) -> Vec<u8> {
    let owner = sid_bytes(owner).expect("owner sid");
    let mut acl = Vec::new();
    for (ty, flags, mask, ot, sid) in aces {
        let sid = sid_bytes(sid).expect("ace sid");
        let mut body = mask.to_le_bytes().to_vec();
        if *ty == ACCESS_ALLOWED_OBJECT {
            body.extend_from_slice(&(ot.is_some() as u32).to_le_bytes());
            if let Some(g) = ot {
                body.extend_from_slice(g);
            }
        }
        body.extend_from_slice(&sid);
        acl.push(*ty);
        acl.push(*flags);
        acl.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
        acl.extend_from_slice(&body);
    }
    let mut dacl = vec![2u8, 0];
    dacl.extend_from_slice(&((acl.len() + 8) as u16).to_le_bytes());
    dacl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    dacl.extend_from_slice(&[0, 0]);
    dacl.extend_from_slice(&acl);
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&(0x8004u16).to_le_bytes()); // self-relative, DACL present
    let owner_off = 20u32;
    let dacl_off = owner_off + owner.len() as u32;
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd.extend_from_slice(&dacl);
    sd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_roundtrip() {
        let s = "S-1-5-21-1004336348-1177238915-682003330-512";
        let b = sid_bytes(s).unwrap();
        assert_eq!(b.len(), 28);
        assert_eq!(sid_string(&b).unwrap(), s);
        assert_eq!(sid_string(&sid_bytes("S-1-5-32-544").unwrap()).unwrap(), "S-1-5-32-544");
        assert_eq!(sid_value(b"S-1-1-0").unwrap(), "S-1-1-0");
    }

    #[test]
    fn guid_layout() {
        let g = guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
        assert_eq!(g[0], 0xc0);
        assert_eq!(guid_string(&g).unwrap(), "BF9679C0-0DE6-11D0-A285-00AA003049E2");
    }

    #[test]
    fn sd_rights() {
        let d = "S-1-5-21-1-2-3";
        let sd = build_sd(
            &format!("{d}-512"),
            &[
                (ACCESS_ALLOWED, 0, FULL_CONTROL, None, &format!("{d}-1101")),
                (ACCESS_ALLOWED_OBJECT, 0, RIGHT_DS_WRITE_PROPERTY, Some(g::MEMBER), &format!("{d}-1102")),
                (ACCESS_ALLOWED, 0, WRITE_DAC | 0x20000, None, &format!("{d}-1103")),
                (ACCESS_ALLOWED, INHERIT_ONLY, FULL_CONTROL, None, &format!("{d}-1104")),
                (0x01, 0, FULL_CONTROL, None, &format!("{d}-1105")), // deny: ignored
            ],
        );
        let p = parse(&sd).unwrap();
        assert_eq!(sid_string(p.owner.unwrap()).unwrap(), format!("{d}-512"));
        assert_eq!(p.dacl.len(), 4);
        let t = Target { kind: NodeKind::Group, class: Some(g::C_GROUP), has_laps: false, laps: &[] };
        let rights: Vec<Vec<&str>> = p
            .dacl
            .iter()
            .map(|a| {
                let mut v = Vec::new();
                ace_rights(a, &t, &mut v);
                v
            })
            .collect();
        assert_eq!(rights, vec![vec!["GenericAll"], vec!["AddMember"], vec!["WriteDacl"], vec![]]);
    }
}
