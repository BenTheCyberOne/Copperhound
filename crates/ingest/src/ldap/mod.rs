//! Raw directory dumps: LDIF (`ldapsearch`, `ldifde`, RFC 2849) and
//! Sysinternals AD Explorer snapshots.
//!
//! Both readers turn their input into [`Entry`] values (DN + raw attribute
//! values) and share one extractor that produces the SharpHound-equivalent
//! graph: objects and properties, group membership, ACL edges decoded from
//! `nTSecurityDescriptor`, delegation, SID history, trusts, GPO links, LAPS,
//! gMSA readers and the ADCS objects of the Configuration NC.
//!
//! References between objects are DNs (`member`, `gPLink`, …), so ingest runs
//! two streaming passes over the memory-mapped inputs:
//!
//! 1. **index** (parallel): object identifier for every DN, kept as a
//!    64-bit DN hash → node id map (≈ 20 B per object), plus small side
//!    tables (domain SIDs, computer host names, certificate templates, CA
//!    certificates, LAPS schema GUIDs, forest partitions).
//! 2. **extract** (parallel): every object is parsed again and emitted with
//!    all references resolved through the index.
//!
//! Neither pass holds parsed objects; memory is the interner, the index and
//! the emitted edges, as for JSON collectors.

pub mod adexplorer;
pub mod cert;
mod extract;
pub mod ldif;
pub mod sd;

use crate::emit::{Emitted, Shared};
use crate::scan::InputKind;
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

macro_rules! attrs {
    ($($v:ident => $n:literal $(: $bin:ident)?),* $(,)?) => {
        /// LDAP attributes the extractor reads (everything else is skipped
        /// without decoding).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum A { $($v),* }

        impl A {
            pub const ALL: &'static [A] = &[$(A::$v),*];
            /// lDAPDisplayName.
            pub fn name(self) -> &'static str {
                match self { $(A::$v => $n),* }
            }
            /// Binary syntax (base64 in LDIF, octet string in snapshots).
            pub fn binary(self) -> bool {
                match self { $(A::$v => attrs!(@bin $($bin)?)),* }
            }
        }
    };
    (@bin bin) => { true };
    (@bin) => { false };
}

attrs! {
    ObjectClass => "objectClass",
    ObjectSid => "objectSid": bin,
    ObjectGuid => "objectGUID": bin,
    DistinguishedName => "distinguishedName",
    SamAccountName => "sAMAccountName",
    Name => "name",
    Cn => "cn",
    DisplayName => "displayName",
    Description => "description",
    DnsHostName => "dNSHostName",
    Uac => "userAccountControl",
    AdminCount => "adminCount",
    Spn => "servicePrincipalName",
    PrimaryGroupId => "primaryGroupID",
    Member => "member",
    Sd => "nTSecurityDescriptor": bin,
    AllowedToAct => "msDS-AllowedToActOnBehalfOfOtherIdentity": bin,
    AllowedToDelegateTo => "msDS-AllowedToDelegateTo",
    GmsaMembership => "msDS-GroupMSAMembership": bin,
    SidHistory => "sIDHistory": bin,
    WhenCreated => "whenCreated",
    WhenChanged => "whenChanged",
    LastLogon => "lastLogon",
    LastLogonTimestamp => "lastLogonTimestamp",
    PwdLastSet => "pwdLastSet",
    Mail => "mail",
    Title => "title",
    HomeDirectory => "homeDirectory",
    ScriptPath => "scriptPath",
    UserPassword => "userPassword",
    UnixUserPassword => "unixUserPassword",
    UnicodePwd => "unicodePwd",
    SfuPassword => "msSFU30Password",
    OperatingSystem => "operatingSystem",
    OsServicePack => "operatingSystemServicePack",
    LapsLegacyExpiry => "ms-Mcs-AdmPwdExpirationTime",
    LapsExpiry => "msLAPS-PasswordExpirationTime",
    GpLink => "gPLink",
    GpOptions => "gPOptions",
    GpcFileSysPath => "gPCFileSysPath",
    BehaviorVersion => "msDS-Behavior-Version",
    MachineAccountQuota => "ms-DS-MachineAccountQuota",
    TrustPartner => "trustPartner",
    TrustDirection => "trustDirection",
    TrustType => "trustType",
    TrustAttributes => "trustAttributes",
    SecurityIdentifier => "securityIdentifier": bin,
    Flags => "flags",
    TemplateOid => "msPKI-Cert-Template-OID",
    OidToGroupLink => "msDS-OIDToGroupLink",
    SchemaVersion => "msPKI-Template-Schema-Version",
    EnrollmentFlag => "msPKI-Enrollment-Flag",
    NameFlag => "msPKI-Certificate-Name-Flag",
    Eku => "pKIExtendedKeyUsage",
    AppPolicy => "msPKI-Certificate-Application-Policy",
    CertPolicy => "msPKI-Certificate-Policy",
    RaSignature => "msPKI-RA-Signature",
    RaAppPolicies => "msPKI-RA-Application-Policies",
    RaPolicies => "msPKI-RA-Policies",
    ExpirationPeriod => "pKIExpirationPeriod": bin,
    OverlapPeriod => "pKIOverlapPeriod": bin,
    CaCertificate => "cACertificate": bin,
    CertificateTemplates => "certificateTemplates",
    CrossCertificatePair => "crossCertificatePair": bin,
    IsDeleted => "isDeleted",
    LdapDisplayName => "lDAPDisplayName",
    SchemaIdGuid => "schemaIDGUID": bin,
    NcName => "nCName",
    NetbiosName => "nETBIOSName",
}

impl A {
    /// Case-insensitive lookup by lDAPDisplayName.
    pub fn lookup(name: &[u8]) -> Option<A> {
        use std::sync::OnceLock;
        static MAP: OnceLock<ahash::AHashMap<Vec<u8>, A>> = OnceLock::new();
        let map = MAP.get_or_init(|| A::ALL.iter().map(|a| (a.name().to_ascii_lowercase().into_bytes(), *a)).collect());
        if name.len() > 64 {
            return None;
        }
        let mut buf = [0u8; 64];
        let l = &mut buf[..name.len()];
        l.copy_from_slice(name);
        l.make_ascii_lowercase();
        map.get(&l[..]).copied()
    }
    #[inline]
    pub fn bit(self) -> Need {
        1u128 << self as u8
    }
}

/// Bit set of the attributes a pass decodes.
pub type Need = u128;
pub const NEED_ALL: Need = Need::MAX;

/// One directory object: DN plus raw values of the known attributes.
#[derive(Debug, Default)]
pub struct Entry<'a> {
    pub dn: Cow<'a, str>,
    pub vals: Vec<(A, Cow<'a, [u8]>)>,
    /// Some `member` values came from a later range of a ranged read
    /// (`member;range=1500-2999`): this entry continues a group whose first
    /// range is elsewhere.
    pub member_tail: bool,
    /// Some `member` values came from a plain `member` attribute or the first
    /// range (`member;range=0-1499`).
    pub member_head: bool,
}

impl<'a> Entry<'a> {
    pub fn all(&self, a: A) -> impl Iterator<Item = &[u8]> + '_ {
        self.vals.iter().filter(move |(x, _)| *x == a).map(|(_, v)| v.as_ref())
    }
    pub fn first(&self, a: A) -> Option<&[u8]> {
        self.all(a).next()
    }
    pub fn has(&self, a: A) -> bool {
        self.first(a).is_some()
    }
    pub fn texts(&self, a: A) -> impl Iterator<Item = &str> + '_ {
        self.all(a).filter_map(|v| std::str::from_utf8(v).ok()).map(str::trim).filter(|s| !s.is_empty())
    }
    pub fn text(&self, a: A) -> Option<&str> {
        self.texts(a).next()
    }
    pub fn int(&self, a: A) -> Option<i64> {
        self.text(a).and_then(|s| s.parse().ok())
    }
    pub fn has_class(&self, c: &str) -> bool {
        self.all(A::ObjectClass).any(|v| v.eq_ignore_ascii_case(c.as_bytes()))
    }
}

/// Entry callback: an object, or a per-record parse error.
pub type Sink<'s> = dyn FnMut(std::result::Result<Entry<'_>, String>) + 's;

enum Source {
    Ldif(ldif::LdifFile),
    Snapshot(adexplorer::Snapshot),
}

/// An opened LDIF file or AD Explorer snapshot, split into chunks that are
/// read independently in parallel.
pub struct Input {
    pub display: String,
    /// Ingest source index (see [`crate::SourceInfo`]).
    pub source: u32,
    src: Source,
}

impl Input {
    pub fn chunks(&self) -> usize {
        match &self.src {
            Source::Ldif(f) => f.chunks(),
            Source::Snapshot(s) => s.chunks(),
        }
    }
    pub fn len(&self) -> u64 {
        match &self.src {
            Source::Ldif(f) => f.len(),
            Source::Snapshot(s) => s.len(),
        }
    }
    /// Collection time recorded in the file itself (AD Explorer snapshot
    /// header), unix seconds.
    pub fn header_time(&self) -> Option<i64> {
        match &self.src {
            Source::Ldif(_) => None,
            Source::Snapshot(s) => s.time(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn read(&self, chunk: usize, need: Need, f: &mut Sink) {
        match &self.src {
            Source::Ldif(l) => l.read(chunk, need, f),
            Source::Snapshot(s) => s.read(chunk, need, f),
        }
    }
}

/// Open a detected LDIF / gzip / snapshot input. Gzip-compressed LDIF is
/// decompressed into `tmp` first so it can be memory-mapped like any other
/// input. Returns `None` for gzip files that are not LDIF.
pub fn open(path: &Path, kind: InputKind, tmp: &Path) -> Result<Option<Input>> {
    let display = path.display().to_string();
    let src = match kind {
        InputKind::Ldif => Source::Ldif(ldif::LdifFile::open(path)?),
        InputKind::AdExplorer => Source::Snapshot(adexplorer::Snapshot::open(path)?),
        InputKind::Gzip => {
            let Some(out) = gunzip_ldif(path, tmp)? else { return Ok(None) };
            Source::Ldif(ldif::LdifFile::open(&out)?)
        }
        InputKind::Json | InputKind::Zip => return Ok(None),
    };
    Ok(Some(Input { display, source: 0, src }))
}

fn gunzip_ldif(path: &Path, tmp: &Path) -> Result<Option<PathBuf>> {
    let open = || -> Result<_> { Ok(flate2::read::MultiGzDecoder::new(std::io::BufReader::new(File::open(path)?))) };
    let mut head = Vec::with_capacity(4096);
    open()?.take(4096).read_to_end(&mut head).with_context(|| format!("decompressing {}", path.display()))?;
    if !ldif::looks_like(&head) {
        return Ok(None);
    }
    let base = path.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let out = tmp.join(format!("gz{nanos}_{}", base.trim_end_matches(".gz")));
    let mut w = BufWriter::with_capacity(1 << 20, File::create(&out)?);
    let limit = crate::expansion_limit(std::fs::metadata(path)?.len());
    let res = crate::copy_limited(open()?, &mut w, limit, &path.display().to_string()).with_context(|| format!("decompressing {}", path.display()));
    if let Err(e) = res {
        drop(w);
        let _ = std::fs::remove_file(&out);
        return Err(e);
    }
    w.flush()?;
    Ok(Some(out))
}

/// Counters reported back into the ingest report.
#[derive(Debug, Default)]
pub struct Stats {
    pub records: u64,
    pub refs_resolved: u64,
    pub refs_unresolved: u64,
    pub index_secs: f64,
}

/// Run both passes over all inputs.
pub fn ingest(inputs: &[Input], sh: &Shared, progress: crate::Progress) -> (Vec<Emitted>, Stats) {
    extract::run(inputs, sh, progress)
}
