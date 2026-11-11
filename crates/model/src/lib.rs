//! Shared data model for CopperHound: node kinds, edge kinds, node flags and
//! a stable hash used by on-disk indexes.

use std::collections::HashMap;
use std::sync::OnceLock;

mod fix;
mod help;
pub use fix::{fix_command, FixEnd};
pub use help::{edge_help, EdgeHelp};

pub type NodeId = u32;
pub type EdgeKindId = u16;
pub const NO_NODE: NodeId = u32::MAX;

macro_rules! node_kinds {
    ($($variant:ident = $id:literal => $name:literal),* $(,)?) => {
        /// Node kind. Discriminants are persisted on disk; append only.
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum NodeKind { $($variant = $id),* }

        impl NodeKind {
            pub const ALL: &'static [NodeKind] = &[$(NodeKind::$variant),*];

            pub fn as_str(self) -> &'static str {
                match self { $(NodeKind::$variant => $name),* }
            }
        }
    };
}

node_kinds! {
    Unknown = 0 => "Unknown",
    User = 1 => "User",
    Group = 2 => "Group",
    Computer = 3 => "Computer",
    Domain = 4 => "Domain",
    Gpo = 5 => "GPO",
    Ou = 6 => "OU",
    Container = 7 => "Container",
    CertTemplate = 8 => "CertTemplate",
    EnterpriseCa = 9 => "EnterpriseCA",
    RootCa = 10 => "RootCA",
    AiaCa = 11 => "AIACA",
    NtAuthStore = 12 => "NTAuthStore",
    IssuancePolicy = 13 => "IssuancePolicy",
    AzTenant = 14 => "AZTenant",
    AzUser = 15 => "AZUser",
    AzGroup = 16 => "AZGroup",
    AzApp = 17 => "AZApp",
    AzServicePrincipal = 18 => "AZServicePrincipal",
    AzDevice = 19 => "AZDevice",
    AzRole = 20 => "AZRole",
    AzSubscription = 21 => "AZSubscription",
    AzResourceGroup = 22 => "AZResourceGroup",
    AzManagementGroup = 23 => "AZManagementGroup",
    AzKeyVault = 24 => "AZKeyVault",
    AzVm = 25 => "AZVM",
    AzAutomationAccount = 26 => "AZAutomationAccount",
    AzContainerRegistry = 27 => "AZContainerRegistry",
    AzFunctionApp = 28 => "AZFunctionApp",
    AzLogicApp = 29 => "AZLogicApp",
    AzManagedCluster = 30 => "AZManagedCluster",
    AzVmScaleSet = 31 => "AZVMScaleSet",
    AzWebApp = 32 => "AZWebApp",
}

/// First raw kind value used for custom (OpenGraph) node kinds; built-in
/// discriminants stay below it.
pub const CUSTOM_KIND_BASE: u8 = 64;
/// Most custom node kinds a graph can hold.
pub const MAX_CUSTOM_KINDS: usize = (u8::MAX - CUSTOM_KIND_BASE) as usize + 1;

impl NodeKind {
    pub const COUNT: usize = Self::ALL.len();

    pub fn from_u8(v: u8) -> Self {
        Self::ALL.get(v as usize).copied().unwrap_or(Self::Unknown)
    }

    pub fn is_azure(self) -> bool {
        (self as u8) >= NodeKind::AzTenant as u8
    }

    /// Parse a kind from a SharpHound `ObjectType`, a `meta.type`, an AzureHound
    /// kind, or a file-name suffix. Case-insensitive; accepts plurals.
    /// Unrecognised input → `Unknown`.
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "domains" | "policy" | "domaindns" => return Self::Domain,
            "organizationalunit" | "ous" => return Self::Ou,
            "issuancepolicies" => return Self::IssuancePolicy,
            "base" | "" => return Self::Unknown,
            _ => {}
        }
        let singular = lower.strip_suffix('s').unwrap_or(&lower);
        Self::ALL
            .iter()
            .copied()
            .find(|k| {
                let n = k.as_str();
                n.eq_ignore_ascii_case(&lower) || n.eq_ignore_ascii_case(singular)
            })
            .unwrap_or(Self::Unknown)
    }

    /// Infer the kind from a collector file name such as `20240101_users.json`
    /// (SharpHound / bloodhound-python) or `domain_users.json` (ldapdomaindump).
    pub fn from_file_name(path: &str) -> Option<Self> {
        let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
        let lower = base.to_ascii_lowercase();
        let stem = lower.strip_suffix(".json").unwrap_or(&lower);
        let tail = stem.rsplit('_').next().unwrap_or(stem);
        match Self::parse(tail) {
            Self::Unknown => None,
            k => Some(k),
        }
    }
}

/// Per-node bit flags.
pub mod flags {
    pub const ENABLED: u32 = 1 << 0;
    /// Tier Zero / high-value asset. Set by ingest rules or by the user.
    pub const TIER0: u32 = 1 << 1;
    /// Marked as compromised by the operator.
    pub const OWNED: u32 = 1 << 2;
    pub const ADMINCOUNT: u32 = 1 << 3;
    /// Legacy `highvalue` property from the collector.
    pub const HIGHVALUE: u32 = 1 << 4;
    /// TRUSTED_FOR_DELEGATION (unconstrained delegation).
    pub const UNCONSTRAINED_DELEGATION: u32 = 1 << 5;
    pub const DONT_REQ_PREAUTH: u32 = 1 << 6;
    pub const HAS_SPN: u32 = 1 << 7;
}

/// Ids of the built-in edge kinds. Must match [`BUILTIN_EDGE_KINDS`] order.
pub mod ek {
    pub const MEMBER_OF: u16 = 0;
    pub const ADMIN_TO: u16 = 1;
    pub const HAS_SESSION: u16 = 2;
    pub const CAN_RDP: u16 = 3;
    pub const CAN_PSREMOTE: u16 = 4;
    pub const EXECUTE_DCOM: u16 = 5;
    pub const ALLOWED_TO_DELEGATE: u16 = 6;
    pub const ALLOWED_TO_ACT: u16 = 7;
    pub const HAS_SID_HISTORY: u16 = 8;
    pub const CONTAINS: u16 = 9;
    pub const GP_LINK: u16 = 10;
    pub const TRUSTED_BY: u16 = 11;
    pub const DCSYNC: u16 = 12;
    pub const GET_CHANGES: u16 = 13;
    pub const GET_CHANGES_ALL: u16 = 14;
    pub const GET_CHANGES_IN_FILTERED_SET: u16 = 15;
    pub const GENERIC_ALL: u16 = 16;
}

/// `(name, traversable)` for every built-in edge kind. Collector right names
/// not listed here are registered dynamically at ingest and are traversable.
pub const BUILTIN_EDGE_KINDS: &[(&str, bool)] = &[
    ("MemberOf", true),
    ("AdminTo", true),
    ("HasSession", true),
    ("CanRDP", true),
    ("CanPSRemote", true),
    ("ExecuteDCOM", true),
    ("AllowedToDelegate", true),
    ("AllowedToAct", true),
    ("HasSIDHistory", true),
    ("Contains", true),
    ("GPLink", true),
    ("TrustedBy", false),
    ("DCSync", true),
    ("GetChanges", false),
    ("GetChangesAll", false),
    ("GetChangesInFilteredSet", false),
    ("GenericAll", true),
    ("GenericWrite", true),
    ("WriteOwner", true),
    ("WriteDacl", true),
    ("Owns", true),
    ("AddMember", true),
    ("ForceChangePassword", true),
    ("AllExtendedRights", true),
    ("AddKeyCredentialLink", true),
    ("AddAllowedToAct", true),
    ("ReadLAPSPassword", true),
    ("ReadGMSAPassword", true),
    ("WriteSPN", true),
    ("AddSelf", true),
    ("WriteAccountRestrictions", true),
    ("SyncLAPSPassword", true),
    ("OwnsLimitedRights", true),
    ("WriteOwnerLimitedRights", true),
    // ---- ADCS (see docs/research/adcs.md) ----
    ("Enroll", false),
    ("ManageCA", true),
    ("ManageCertificates", true),
    ("WritePKIEnrollmentFlag", false),
    ("WritePKINameFlag", false),
    ("PublishedTo", false),
    ("HostsCAService", false),
    ("DelegatedEnrollmentAgent", false),
    ("RootCAFor", false),
    ("NTAuthStoreFor", false),
    ("OIDGroupLink", false),
    ("TrustedForNTAuth", false),
    ("IssuedSignedBy", false),
    ("EnterpriseCAFor", false),
    ("ExtendedByPolicy", false),
    ("EnrollOnBehalfOf", false),
    ("GoldenCert", true),
    ("ADCSESC1", true),
    ("ADCSESC3", true),
    ("ADCSESC4", true),
    ("ADCSESC6a", true),
    ("ADCSESC6b", true),
    ("ADCSESC9a", true),
    ("ADCSESC9b", true),
    ("ADCSESC10a", true),
    ("ADCSESC10b", true),
    ("ADCSESC13", true),
    ("WritePublicInformation", false),
    // ---- Azure / Entra ID (see docs/research/azurehound.md) ----
    ("AZContains", true),
    ("AZMemberOf", true),
    ("AZOwns", true),
    ("AZHasRole", true),
    ("AZRunsAs", true),
    ("AZManagedIdentity", true),
    ("AZNodeResourceGroup", true),
    ("AZAuthenticatesTo", true),
    ("AZRoleEligible", false),
    ("AZRoleApprover", false),
    ("AZAppAdmin", true),
    ("AZCloudAppAdmin", true),
    ("AZOwner", true),
    ("AZContributor", true),
    ("AZUserAccessAdministrator", true),
    ("AZKeyVaultContributor", true),
    ("AZVMContributor", true),
    ("AZVMAdminLogin", true),
    ("AZAvereContributor", true),
    ("AZWebsiteContributor", true),
    ("AZLogicAppContributor", true),
    ("AZAutomationContributor", true),
    ("AZAKSContributor", true),
    ("AZGetKeys", true),
    ("AZGetSecrets", true),
    ("AZGetCertificates", true),
    ("AZMGApplication_ReadWrite_All", false),
    ("AZMGAppRoleAssignment_ReadWrite_All", false),
    ("AZMGDirectory_ReadWrite_All", false),
    ("AZMGGroup_ReadWrite_All", false),
    ("AZMGGroupMember_ReadWrite_All", false),
    ("AZMGRoleManagement_ReadWrite_Directory", false),
    ("AZMGServicePrincipalEndpoint_ReadWrite_All", false),
    ("AZMGAddSecret", true),
    ("AZMGAddOwner", true),
    ("AZMGAddMember", true),
    ("AZMGGrantAppRoles", true),
    ("AZMGGrantRole", true),
    ("AZGlobalAdmin", true),
    ("AZPrivilegedRoleAdmin", true),
    ("AZPrivilegedAuthAdmin", true),
    ("AZResetPassword", true),
    ("AZAddMembers", true),
    ("AZAddSecret", true),
    ("AZAddOwner", true),
    ("AZExecuteCommand", true),
    ("SyncedToEntraUser", true),
    ("SyncedToADUser", true),
    // ---- appended AD rights (ids are persisted: append only) ----
    ("WriteGPLink", true),
    ("CoerceToTGT", true),
    // ---- domain trusts (docs/EDGES.md, "Trusts") ----
    ("SameForestTrust", true),
    ("CrossForestTrust", false),
    ("SpoofSIDHistory", true),
    ("AbuseTGTDelegation", true),
    // ---- AD <-> Entra ID hybrid (docs/EDGES.md, "Hybrid") ----
    ("SyncedToEntraGroup", true),
    ("SyncedToADGroup", false),
    ("SeamlessSSO", true),
    ("EntraConnectCredentials", true),
    // ---- Entra ID scoped role assignments (docs/EDGES.md, "Entra ID roles") ----
    ("AZScopedTo", false),
    // ---- trust accounts (docs/EDGES.md, "Trusts") ----
    ("HasTrustKeys", true),
];

/// Edge kinds that link Active Directory and Entra ID objects. With unified
/// Tier Zero switched off, traversals do not cross between the two realms.
pub const HYBRID_EDGE_KINDS: &[&str] = &[
    "SyncedToEntraUser",
    "SyncedToADUser",
    "SyncedToEntraGroup",
    "SyncedToADGroup",
    "SeamlessSSO",
    "EntraConnectCredentials",
];

/// UI / API grouping of node and edge kinds.
pub fn edge_category(name: &str) -> &'static str {
    let first = |n: &str| builtin_edge_kind(n).unwrap_or(u16::MAX);
    if HYBRID_EDGE_KINDS.contains(&name) {
        return "Hybrid";
    }
    if matches!(name, "SameForestTrust" | "CrossForestTrust" | "SpoofSIDHistory" | "AbuseTGTDelegation" | "HasTrustKeys") {
        return "Active Directory";
    }
    match builtin_edge_kind(name) {
        Some(k) if (first("AZContains")..first("SyncedToEntraUser")).contains(&k) => "Azure",
        Some(k) if (first("Enroll")..first("AZContains")).contains(&k) => "ADCS",
        _ if name.starts_with("AZ") => "Azure",
        Some(_) => "Active Directory",
        // Collector rights not yet built in, and OpenGraph relationship kinds.
        None => "Custom",
    }
}

pub fn node_category(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::CertTemplate
        | NodeKind::EnterpriseCa
        | NodeKind::RootCa
        | NodeKind::AiaCa
        | NodeKind::NtAuthStore
        | NodeKind::IssuancePolicy => "ADCS",
        k if k.is_azure() => "Azure",
        NodeKind::Unknown => "Other",
        _ => "Active Directory",
    }
}

/// Edge kind id by name; panics if `name` is not a built-in (programming error).
pub fn ek_of(name: &str) -> u16 {
    builtin_edge_kind(name).unwrap_or_else(|| panic!("not a built-in edge kind: {name}"))
}

fn builtin_map() -> &'static HashMap<&'static str, u16> {
    static MAP: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    MAP.get_or_init(|| {
        BUILTIN_EDGE_KINDS
            .iter()
            .enumerate()
            .map(|(i, (n, _))| (*n, i as u16))
            .collect()
    })
}

/// Look up a built-in edge kind by its exact collector name.
#[inline]
pub fn builtin_edge_kind(name: &str) -> Option<u16> {
    builtin_map().get(name).copied()
}

/// Names and traversability of the built-in edge kinds, as owned tables.
pub fn builtin_kind_tables() -> (Vec<String>, Vec<bool>) {
    BUILTIN_EDGE_KINDS
        .iter()
        .map(|(n, t)| (n.to_string(), *t))
        .unzip()
}

/// Well-known SID suffixes that are Tier Zero in every domain.
const TIER0_SUFFIXES: &[&str] = &[
    "-512",         // Domain Admins
    "-516",         // Domain Controllers
    "-518",         // Schema Admins
    "-519",         // Enterprise Admins
    "-526",         // Key Admins
    "-527",         // Enterprise Key Admins
    "S-1-5-32-544", // BUILTIN\Administrators
    "S-1-5-32-548", // Account Operators
    "S-1-5-32-549", // Server Operators
    "S-1-5-32-550", // Print Operators
    "S-1-5-32-551", // Backup Operators
];

pub const DOMAIN_CONTROLLERS_SUFFIX: &str = "-516";

pub fn is_well_known_tier0(oid: &str) -> bool {
    TIER0_SUFFIXES.iter().any(|s| oid.ends_with(s))
}

/// Entra ID role template ids that are Tier Zero (Global Admin, Privileged
/// Role Admin, Privileged Authentication Admin, Partner Tier2 Support, Hybrid
/// Identity Admin, Directory Synchronization Accounts). The last two control
/// federation / sync configuration and can take over hybrid identities.
pub const AZURE_TIER0_ROLES: &[&str] = &[
    "62E90394-69F5-4237-9190-012177145E10",
    "E8611AB8-C189-46E8-94E1-60213AB1F814",
    "7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13",
    "E00E864A-17C5-4A4B-9C06-F5B95A8D5BD8",
    "8AC3FC64-6ECA-42EA-9E69-59F4C7B60EB2",
    "D29B2B05-8046-44BA-8758-1E26182FCF32",
];

/// Template id of the "Directory Synchronization Accounts" Entra role held by
/// the Entra Connect cloud sync account (`Sync_*`).
pub const AZURE_DIRECTORY_SYNC_ROLE: &str = "D29B2B05-8046-44BA-8758-1E26182FCF32";

/// Default Tier Zero rule by kind and (uppercase) object id, beyond the
/// well-known AD SIDs: domains, ADCS infrastructure, Cert Publishers, Azure
/// tenants and the Tier Zero Entra roles (role ids are `<template>@<tenant>`).
pub fn is_default_tier0(kind: NodeKind, oid: &str) -> bool {
    match kind {
        NodeKind::Domain
        | NodeKind::EnterpriseCa
        | NodeKind::RootCa
        | NodeKind::AiaCa
        | NodeKind::NtAuthStore
        | NodeKind::CertTemplate
        | NodeKind::AzTenant => true,
        NodeKind::AzRole => AZURE_TIER0_ROLES.iter().any(|r| oid.starts_with(r) && oid[r.len()..].starts_with('@')),
        NodeKind::Group => oid.ends_with("-517") || is_well_known_tier0(oid),
        _ => is_well_known_tier0(oid),
    }
}

/// FNV-1a 64-bit. Stable across platforms and versions; used for on-disk indexes.
#[inline]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_file_names() {
        assert_eq!(
            NodeKind::from_file_name("20240101_users.json"),
            Some(NodeKind::User)
        );
        assert_eq!(
            NodeKind::from_file_name("C:\\x\\domain_groups.json"),
            Some(NodeKind::Group)
        );
        assert_eq!(
            NodeKind::from_file_name("domain_policy.json"),
            Some(NodeKind::Domain)
        );
        assert_eq!(NodeKind::from_file_name("random.json"), None);
    }

    #[test]
    fn builtin_ids_match_constants() {
        assert_eq!(builtin_edge_kind("MemberOf"), Some(ek::MEMBER_OF));
        assert_eq!(builtin_edge_kind("DCSync"), Some(ek::DCSYNC));
        assert_eq!(
            builtin_edge_kind("GetChangesAll"),
            Some(ek::GET_CHANGES_ALL)
        );
        assert_eq!(builtin_edge_kind("GenericAll"), Some(ek::GENERIC_ALL));
        assert_eq!(builtin_edge_kind("TrustedBy"), Some(ek::TRUSTED_BY));
    }

    #[test]
    fn categories() {
        assert_eq!(edge_category("MemberOf"), "Active Directory");
        assert_eq!(edge_category("ADCSESC1"), "ADCS");
        assert_eq!(edge_category("WritePublicInformation"), "ADCS");
        assert_eq!(edge_category("AZOwns"), "Azure");
        assert_eq!(edge_category("SyncedToADUser"), "Hybrid");
        assert_eq!(edge_category("SomeCustomRight"), "Custom");
        assert_eq!(edge_category("WriteGPLink"), "Active Directory");
        assert_eq!(edge_category("SameForestTrust"), "Active Directory");
        assert_eq!(edge_category("SeamlessSSO"), "Hybrid");
        assert_eq!(edge_category("SyncedToEntraGroup"), "Hybrid");
        assert_eq!(node_category(NodeKind::AzVm), "Azure");
        assert_eq!(node_category(NodeKind::RootCa), "ADCS");
    }

    #[test]
    fn every_builtin_kind_has_help() {
        for (k, _) in BUILTIN_EDGE_KINDS {
            let h = edge_help(k).unwrap_or_else(|| panic!("no help for {k}"));
            for (field, text) in [("description", h.description), ("abuse", h.abuse), ("remediation", h.remediation)] {
                assert!(!text.trim().is_empty(), "{k}: empty {field}");
            }
        }
        for k in HYBRID_EDGE_KINDS {
            assert!(builtin_edge_kind(k).is_some(), "{k} not built in");
        }
        assert!(edge_help("SomeCustomRight").is_none());
        assert!(is_default_tier0(NodeKind::AzRole, &format!("{AZURE_DIRECTORY_SYNC_ROLE}@T")));
    }

    #[test]
    fn tier0_suffixes() {
        assert!(is_well_known_tier0("S-1-5-21-1-2-3-512"));
        assert!(is_well_known_tier0("CONTOSO.LOCAL-S-1-5-32-544"));
        assert!(!is_well_known_tier0("S-1-5-21-1-2-3-1512"));
    }
}
