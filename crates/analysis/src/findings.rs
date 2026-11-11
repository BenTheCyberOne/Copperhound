//! Attack-path findings: detections expressed in CHQL, enriched with
//! severity, remediation guidance, MITRE ATT&CK techniques and a measured
//! exposure impact ("fixing this removes N principals' paths to Tier Zero").

use crate::simulate::exposure_with;
use crate::{edge_key, edge_label, EdgeKey, Removal};
use ch_query::{run_capped, Cancel};

/// Items collected per finding (counts beyond this are reported as truncated).
pub const FINDING_ITEM_CAP: usize = 10_000_000;
use ch_store::Graph;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Edges,
    Nodes,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDef {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub kind: ItemKind,
    pub description: &'static str,
    pub impact: &'static str,
    pub remediation: &'static str,
    pub mitre: &'static [&'static str],
    /// CHQL; edge findings `RETURN r` (one relationship), node findings `RETURN n`.
    pub query: &'static str,
    /// Edges whose removal measures the impact, when they differ from the
    /// reported items (e.g. permissions whose risk lives in derived edges).
    pub impact_query: Option<&'static str>,
}

macro_rules! f {
    ($id:literal, $sev:ident, $cat:literal, $kind:ident, $title:literal, [$($m:literal),*], $q:literal,
     desc: $d:literal, impact: $i:literal, fix: $r:literal) => {
        FindingDef { id: $id, title: $title, severity: Severity::$sev, category: $cat, kind: ItemKind::$kind,
                     description: $d, impact: $i, remediation: $r, mitre: &[$($m),*], query: $q, impact_query: None }
    };
    ($id:literal, $sev:ident, $cat:literal, $kind:ident, $title:literal, [$($m:literal),*], $q:literal, measure: $iq:literal,
     desc: $d:literal, impact: $i:literal, fix: $r:literal) => {
        FindingDef { id: $id, title: $title, severity: Severity::$sev, category: $cat, kind: ItemKind::$kind,
                     description: $d, impact: $i, remediation: $r, mitre: &[$($m),*], query: $q, impact_query: Some($iq) }
    };
}

pub const CATALOG: &[FindingDef] = &[
    // ------------------------------------------------------------ AD critical
    f!("dcsync-non-tier0", Critical, "Active Directory", Edges, "Non-Tier Zero principals can DCSync", ["T1003.006"],
       "MATCH (p)-[r:DCSync]->(d:Domain) WHERE NOT p.tier0 RETURN r",
       desc: "These principals hold both replication rights (GetChanges + GetChangesAll) on a domain but are not Tier Zero.",
       impact: "Anyone controlling them can replicate every password hash in the domain, including krbtgt, and forge tickets for any account.",
       fix: "Remove the 'Replicating Directory Changes' and 'Replicating Directory Changes All' extended rights from the domain object for these principals. Only domain controllers and explicitly approved Tier Zero sync accounts should hold them."),
    f!("tier0-control", Critical, "Active Directory", Edges, "Non-Tier Zero principals control Tier Zero objects", ["T1098", "T1222.001"],
       "MATCH (p)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns|AllExtendedRights|AddMember|ForceChangePassword|AddKeyCredentialLink|AddAllowedToAct|WriteAccountRestrictions|WriteSPN|AdminTo]->(t {tier0:true}) WHERE NOT p.tier0 AND NOT t:Domain RETURN r",
       desc: "Objects outside Tier Zero have direct control rights (ACL rights, ownership or local admin) over Tier Zero objects.",
       impact: "Compromising any of these principals is equivalent to compromising Tier Zero: the attacker can reset passwords, add members, write shadow credentials or take ownership.",
       fix: "Remove the ACEs or ownership from the Tier Zero objects (reset owners to Domain Admins), and remove non-Tier-Zero local administrators from Tier Zero computers. If a principal genuinely needs the right, move it into Tier Zero and protect it accordingly."),
    f!("broad-group-rights", Critical, "Active Directory", Edges, "Rights granted to Domain Users, Domain Computers, Authenticated Users or Everyone", ["T1078.002"],
       "MATCH (g:Group)-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns|ForceChangePassword|AddMember|AllExtendedRights|AddKeyCredentialLink|AddAllowedToAct|ReadLAPSPassword]->(n) WHERE g.objectid ENDS WITH '-513' OR g.objectid ENDS WITH '-515' OR g.objectid ENDS WITH 'S-1-5-11' OR g.objectid ENDS WITH 'S-1-1-0' RETURN r",
       desc: "Very large built-in groups hold administrative or control rights.",
       impact: "Every authenticated account (or every computer) inherits these rights, so a single phished user is enough to use them.",
       fix: "Replace the broad group with a dedicated, minimal security group in the ACL / local Administrators / Remote Desktop Users membership, then remove the broad group."),
    f!("delegation-to-tier0", Critical, "Active Directory", Edges, "Delegation to Tier Zero systems", ["T1558"],
       "MATCH (p)-[r:AllowedToDelegate|AllowedToAct]->(t {tier0:true}) WHERE NOT p.tier0 RETURN r",
       desc: "Non-Tier-Zero principals are allowed to delegate (constrained delegation or RBCD) to Tier Zero services.",
       impact: "They can obtain service tickets as any user — including Domain Admins — to the Tier Zero system.",
       fix: "Remove the Tier Zero SPNs from msDS-AllowedToDelegateTo, clear msDS-AllowedToActOnBehalfOfOtherIdentity on Tier Zero computers, and mark privileged accounts as 'sensitive and cannot be delegated' / add them to Protected Users."),
    f!("trust-sid-filtering", Critical, "Active Directory", Edges, "Cross-forest trusts without SID filtering", ["T1134.005"],
       "MATCH (a:Domain)-[r:SpoofSIDHistory]->(b:Domain) RETURN r",
       desc: "A domain trusts another forest without SID filtering (quarantine), so SIDs in the SID history of tickets from that forest are honoured.",
       impact: "Whoever compromises the trusted forest can forge tickets carrying privileged SIDs of the trusting domain (RID >= 1000) and take it over: the forest boundary is not a security boundary.",
       fix: "Enable SID filtering on the trust (`netdom trust <trusting> /domain:<trusted> /quarantine:yes` for external trusts, `/enablesidhistory:no` for forest trusts)."),
    // ------------------------------------------------------------ AD high
    f!("trust-tgt-delegation", High, "Active Directory", Edges, "Cross-forest trusts with TGT delegation", ["T1558", "T1187"],
       "MATCH (a:Domain)-[r:AbuseTGTDelegation]->(b:Domain) RETURN r",
       desc: "A domain trusts another forest with TGT delegation enabled.",
       impact: "From the trusted forest an attacker can coerce a DC of the trusting domain to authenticate to an unconstrained delegation host (any DC qualifies) and capture its TGT.",
       fix: "Disable TGT delegation across the trust: `netdom trust <trusting> /domain:<trusted> /EnableTGTDelegation:no`."),
    f!("coerce-to-tgt", High, "Active Directory", Edges, "Unconstrained delegation outside Tier Zero", ["T1558", "T1187"],
       "MATCH (p)-[r:CoerceToTGT]->(d:Domain) WHERE NOT p.tier0 RETURN r",
       desc: "Enabled accounts trusted for unconstrained delegation that are not Tier Zero.",
       impact: "An attacker who controls one can coerce a domain controller to authenticate to it (e.g. via the print spooler or EFSRPC) and capture the DC's TGT, compromising the domain.",
       fix: "Replace unconstrained delegation with constrained or resource-based delegation, disable the Print Spooler on DCs, and add privileged accounts to Protected Users."),
    f!("kerberoastable-privileged", High, "Active Directory", Nodes, "Kerberoastable privileged accounts", ["T1558.003"],
       "MATCH (u:User {hasspn:true, enabled:true}) WHERE u.tier0 OR u.admincount RETURN u",
       desc: "Privileged user accounts that have a service principal name.",
       impact: "Any domain user can request a service ticket for these accounts and crack the password offline.",
       fix: "Remove SPNs from privileged accounts; run services as group Managed Service Accounts (gMSA). Where an SPN must stay, use a 30+ character random password and AES-only encryption."),
    f!("asrep-roastable", High, "Active Directory", Nodes, "Accounts without Kerberos pre-authentication", ["T1558.004"],
       "MATCH (u:User {dontreqpreauth:true, enabled:true}) RETURN u",
       desc: "Enabled users with 'Do not require Kerberos preauthentication'.",
       impact: "Anyone on the network can request an AS-REP for these accounts and crack it offline, without credentials.",
       fix: "Clear DONT_REQ_PREAUTH on these accounts. If an application requires it, give the account a long random password and monitor its logons."),
    f!("privileged-sessions", High, "Active Directory", Edges, "Privileged sessions on non-Tier Zero computers", ["T1003.001"],
       "MATCH (c:Computer)-[r:HasSession]->(u:User {admincount:true}) WHERE NOT c.tier0 RETURN r",
       desc: "Privileged users are logged on to computers outside Tier Zero.",
       impact: "Their credentials are in memory on lower-tier hosts; local administrators of those hosts can extract them.",
       fix: "Enforce tiered administration: privileged accounts log on only to Tier Zero hosts or PAWs. Use 'Deny log on' user rights via GPO and Authentication Policy Silos."),
    f!("gpo-control", High, "Active Directory", Edges, "Non-Tier Zero control of Group Policy objects", ["T1484.001"],
       "MATCH (p)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->(g:GPO) WHERE NOT p.tier0 RETURN r",
       desc: "Principals outside Tier Zero can modify GPOs.",
       impact: "A modified GPO executes code on every computer and user it applies to — including Tier Zero when linked at the domain or DC OU.",
       fix: "Restrict GPO edit rights to Tier Zero administrators (Group Policy Creator Owners and dedicated GPO admin groups); review GPO ownership."),
    f!("credential-readers", High, "Active Directory", Edges, "Non-Tier Zero readers of LAPS / gMSA passwords", ["T1555"],
       "MATCH (p)-[r:ReadLAPSPassword|SyncLAPSPassword|ReadGMSAPassword]->(t) WHERE NOT p.tier0 RETURN r",
       desc: "Principals that can read local administrator (LAPS) or gMSA passwords.",
       impact: "Readers can become local administrator of the computer or act as the service account.",
       fix: "Scope LAPS read permissions per OU to the support team for that tier only; limit PrincipalsAllowedToRetrieveManagedPassword to the hosts that run the service."),
    f!("azureadssoacc", High, "Hybrid", Nodes, "Seamless SSO account not in Tier Zero", ["T1606.002"],
       "MATCH (c:Computer) WHERE c.name STARTS WITH 'AZUREADSSOACC' AND NOT c.tier0 RETURN c",
       desc: "The AZUREADSSOACC computer account (Entra Seamless SSO) is not treated as Tier Zero.",
       impact: "Its Kerberos key lets an attacker forge sign-ins for any synced user to Entra ID.",
       fix: "Tag AZUREADSSOACC as Tier Zero, roll its Kerberos decryption key regularly, and restrict who can manage it."),
    // ------------------------------------------------------------ AD medium / low
    f!("write-gplink", Medium, "Active Directory", Edges, "Non-Tier Zero principals can link GPOs", ["T1484.001"],
       "MATCH (p)-[r:WriteGPLink]->(o) WHERE NOT p.tier0 RETURN r",
       desc: "Principals that can change which GPOs apply to an OU or domain.",
       impact: "Combined with control of any GPO, they can apply it to computers and users under that container.",
       fix: "Remove gPLink write permissions from non-administrative principals."),
    f!("sid-history", Medium, "Active Directory", Edges, "Principals carrying SID history", ["T1134.005"],
       "MATCH (p)-[r:HasSIDHistory]->(t) RETURN r",
       desc: "Accounts with SID history from earlier migrations.",
       impact: "SID history grants the access of the historical principal, often a privileged one, and is frequently overlooked in reviews.",
       fix: "Clear sIDHistory once migrations are complete; enable SID filtering on trusts."),
    f!("pw-not-required", Medium, "Active Directory", Nodes, "Accounts that may have an empty password", ["T1078.002"],
       "MATCH (u:User {enabled:true, passwordnotreqd:true}) RETURN u",
       desc: "Enabled accounts with PASSWD_NOTREQD set.",
       impact: "The password policy does not apply; the account may have a blank or trivially short password.",
       fix: "Clear PASSWD_NOTREQD (userAccountControl flag 0x20) and force a password reset."),
    f!("privileged-pw-never-expires", Medium, "Active Directory", Nodes, "Privileged passwords that never expire", ["T1078.002"],
       "MATCH (u:User {enabled:true, admincount:true, pwdneverexpires:true}) RETURN u",
       desc: "Privileged accounts exempt from password expiry.",
       impact: "Leaked or cracked passwords stay valid indefinitely.",
       fix: "Remove DONT_EXPIRE_PASSWORD from privileged accounts, or replace them with gMSAs / managed identities."),
    f!("stale-privileged", Medium, "Active Directory", Nodes, "Stale privileged accounts", ["T1078.002"],
       "MATCH (u:User {enabled:true, admincount:true}) WHERE u.lastlogontimestamp < days_ago(90) RETURN u",
       desc: "Enabled privileged accounts without a logon in 90 days.",
       impact: "Unused privileged accounts are rarely monitored and are attractive persistence targets.",
       fix: "Disable and later delete unused privileged accounts; review adminCount and group memberships."),
    f!("krbtgt-age", Medium, "Active Directory", Nodes, "krbtgt password older than 180 days", ["T1558.001"],
       "MATCH (u:User) WHERE u.objectid ENDS WITH '-502' AND u.pwdlastset < days_ago(180) RETURN u",
       desc: "The krbtgt password has not been rotated recently.",
       impact: "Golden tickets forged with a previously stolen krbtgt key keep working until the key is rotated twice.",
       fix: "Rotate the krbtgt password twice (with replication in between) on a regular schedule."),
    f!("legacy-os", Medium, "Active Directory", Nodes, "Unsupported operating systems", ["T1210"],
       "MATCH (c:Computer {enabled:true}) WHERE c.operatingsystem CONTAINS '2003' OR c.operatingsystem CONTAINS '2008' OR c.operatingsystem CONTAINS 'XP' OR c.operatingsystem CONTAINS 'WINDOWS 7' OR c.operatingsystem CONTAINS 'VISTA' RETURN c",
       desc: "Enabled computers running end-of-life Windows versions.",
       impact: "No security updates; exposed to known remote code execution vulnerabilities.",
       fix: "Upgrade or isolate these systems; remove privileged sessions and credentials from them."),
    f!("no-laps", Low, "Active Directory", Nodes, "Computers without LAPS", ["T1078.003"],
       "MATCH (c:Computer {enabled:true}) WHERE NOT c.haslaps AND NOT c.tier0 RETURN c",
       desc: "Enabled computers without a managed local administrator password.",
       impact: "Shared local administrator passwords allow lateral movement between machines.",
       fix: "Deploy Windows LAPS to all workstations and member servers."),
    // ------------------------------------------------------------ ADCS
    f!("adcs-escalation", Critical, "ADCS", Edges, "Certificate-based privilege escalation (ESC)", ["T1649"],
       "MATCH (p)-[r:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(d) WHERE NOT p.tier0 RETURN r",
       desc: "Principals that can obtain a certificate authenticating as a privileged user (or gain a linked group) through a vulnerable template or CA configuration.",
       impact: "Certificates remain valid after password resets, so this grants durable domain compromise.",
       fix: "Per ESC type: disable 'Supply in the request' on authentication templates (ESC1), require manager approval or authorized signatures, restrict enrollment rights to specific groups, remove write rights on templates (ESC4), disable EDITF_ATTRIBUTESUBJECTALTNAME2 on CAs (ESC6), enforce strong certificate binding on DCs (ESC9/10) and review issuance-policy group links (ESC13)."),
    f!("adcs-san-ca", High, "ADCS", Nodes, "CAs accepting requester-supplied SANs", ["T1649"],
       "MATCH (ca:EnterpriseCA {isuserspecifiessanenabled:true}) RETURN ca",
       desc: "Enterprise CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.",
       impact: "Any template a user can enroll in becomes an ESC1-style escalation.",
       fix: "Run `certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA and restart the certificate service."),
    f!("adcs-template-control", High, "ADCS", Edges, "Non-Tier Zero control of certificate templates", ["T1649"],
       "MATCH (p)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns|WritePKINameFlag|WritePKIEnrollmentFlag]->(t:CertTemplate) WHERE NOT p.tier0 RETURN r",
       desc: "Principals outside Tier Zero can modify certificate templates.",
       impact: "They can turn a template into an ESC1 escalation at will (ESC4).",
       fix: "Restrict template write permissions to PKI administrators in Tier Zero."),
    f!("adcs-pki-object-control", High, "ADCS", Edges, "Non-Tier Zero control of PKI objects (ESC5)", ["T1649"],
       "MATCH (p)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->(o:EnterpriseCA|RootCA|AIACA|NTAuthStore|IssuancePolicy) WHERE NOT p.tier0 RETURN r",
       desc: "Principals outside Tier Zero can modify an enterprise CA, root or intermediate CA, the NTAuth store or an issuance policy object in Active Directory.",
       impact: "Write access to the NTAuth store or a root CA object lets them make a CA they control trusted for logon (forging certificates for anyone); write access to an enterprise CA object lets them publish any template on it; write access to an issuance policy lets them link it to a privileged group (ESC13).",
       fix: "Restrict write access on the objects under CN=Public Key Services,CN=Services,CN=Configuration to Tier Zero PKI administrators."),
    f!("adcs-esc15", High, "ADCS", Edges, "Schema v1 templates with a supplied subject (ESC15 / EKUwu)", ["T1649"],
       "MATCH (p)-[r:Enroll|GenericAll|AllExtendedRights]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA) WHERE t.schemaversion = 1 AND t.enrolleesuppliessubject = true AND t.requiresmanagerapproval = false AND NOT p.tier0 RETURN r",
       desc: "Principals outside Tier Zero can enroll in a published version 1 template that lets the requester supply the subject (for example the default WebServer template).",
       impact: "On CAs without the November 2024 security update (CVE-2024-49019) the requester can add application policies of their choice, such as Client Authentication, and name any user in the subject: a certificate that logs on as a domain administrator.",
       fix: "Install the November 2024 (or later) update on every CA, then duplicate the template as a version 2+ template and unpublish the version 1 original, or remove 'Supply in the request' and restrict enrollment."),
    f!("adcs-any-purpose", Medium, "ADCS", Edges, "Any Purpose or no-EKU templates enrollable outside Tier Zero (ESC2)", ["T1649"],
       "MATCH (p)-[r:Enroll|GenericAll|AllExtendedRights]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA) WHERE (size(t.effectiveekus) = 0 OR '2.5.29.37.0' IN t.effectiveekus) AND t.requiresmanagerapproval = false AND (t.authorizedsignatures IS NULL OR t.authorizedsignatures = 0) AND NOT p.tier0 RETURN r",
       desc: "Principals outside Tier Zero can enroll in a published template whose certificates are valid for any purpose (Any Purpose EKU, or no EKU at all).",
       impact: "Such a certificate works for client authentication and as an enrollment agent certificate: it can request certificates on behalf of other users from version 1 templates (ESC3); with a supplied subject it is ESC1.",
       fix: "Give the template only the EKUs it needs, require manager approval, or restrict enrollment to the accounts that need it."),
    f!("adcs-ca-managers", Medium, "ADCS", Edges, "Non-Tier Zero CA managers", ["T1649"],
       "MATCH (p)-[r:ManageCA|ManageCertificates]->(ca:EnterpriseCA) WHERE NOT p.tier0 RETURN r",
       desc: "Principals with ManageCA or ManageCertificates outside Tier Zero.",
       impact: "They can change CA configuration or approve pending requests (ESC7).",
       fix: "Limit CA management roles to Tier Zero PKI administrators and enable role separation."),
    // ------------------------------------------------------------ Azure
    f!("az-graph-app-permissions", Critical, "Azure", Edges, "Service principals with tenant-takeover Graph permissions", ["T1098.003"],
       "MATCH (sp:AZServicePrincipal)-[r:AZMGApplication_ReadWrite_All|AZMGAppRoleAssignment_ReadWrite_All|AZMGDirectory_ReadWrite_All|AZMGGroup_ReadWrite_All|AZMGGroupMember_ReadWrite_All|AZMGRoleManagement_ReadWrite_Directory|AZMGServicePrincipalEndpoint_ReadWrite_All]->(g:AZServicePrincipal) RETURN r",
       measure: "MATCH (sp:AZServicePrincipal)-[r:AZMGAddSecret|AZMGAddOwner|AZMGAddMember|AZMGGrantAppRoles|AZMGGrantRole]->(t) RETURN r",
       desc: "Applications granted Microsoft Graph application permissions that allow privilege escalation.",
       impact: "Anyone who can authenticate as the application (secret, certificate, owner, or managed identity) can grant themselves Global Administrator or add members to privileged groups.",
       fix: "Remove the application permission or replace it with a least-privilege scope; protect the app's credentials and owners as Tier Zero."),
    f!("az-hybrid-tier0", Critical, "Hybrid", Edges, "Synced on-prem accounts holding Tier Zero Entra roles", ["T1078.004"],
       "MATCH (u:User)-[r:SyncedToEntraUser]->(a:AZUser)-[:AZHasRole]->(role:AZRole {tier0:true}) RETURN r",
       desc: "Entra Tier Zero roles are held by accounts synchronised from Active Directory.",
       impact: "Compromising the on-premises account (or AD itself) yields cloud Global Administrator.",
       fix: "Use cloud-only, MFA-enforced accounts for Entra privileged roles; keep synced accounts unprivileged."),
    f!("az-hybrid-group-roles", High, "Hybrid", Edges, "Synced on-prem groups holding Entra roles", ["T1098", "T1078.004"],
       "MATCH (g:Group)-[r:SyncedToEntraGroup]->(a:AZGroup)-[:AZHasRole]->(role:AZRole) RETURN r",
       desc: "Entra directory roles are assigned to groups synchronised from Active Directory.",
       impact: "Anyone who can change the AD group's membership (AddMember, GenericAll, account operators, ...) grants cloud roles after the next sync cycle.",
       fix: "Assign Entra roles to cloud-only, role-assignable groups managed through PIM; remove role assignments from synced groups."),
    f!("entra-connect-admins", Critical, "Hybrid", Edges, "Non-Tier Zero administrators of Entra Connect servers", ["T1003", "T1078.004"],
       "MATCH (p)-[r:AdminTo]->(c:Computer)-[:EntraConnectCredentials]->(a) WHERE NOT p.tier0 RETURN r",
       desc: "Principals outside Tier Zero are local administrators of a server that runs Entra Connect.",
       impact: "Local admins can decrypt the sync credentials: the MSOL_ account (usually DCSync rights on AD) and the Sync_ account (directory synchronisation in Entra ID), compromising both directories.",
       fix: "Manage the Entra Connect server as Tier Zero: remove non-Tier Zero local administrators and sessions, and restrict who can log on to it."),
    f!("az-assignable-group-owners", High, "Azure", Edges, "Owners of role-assignable groups", ["T1098"],
       "MATCH (p)-[r:AZOwns]->(g:AZGroup {isAssignableToRole:true}) RETURN r",
       desc: "Principals owning groups that can be assigned Entra roles.",
       impact: "Owners can add themselves to the group and inherit its directory roles.",
       fix: "Remove owners from role-assignable groups or treat them as holders of the group's roles; manage membership through PIM."),
    f!("az-guest-roles", High, "Azure", Edges, "Guest users holding directory roles", ["T1078.004"],
       "MATCH (u:AZUser)-[r:AZHasRole]->(role:AZRole) WHERE u.userType = 'Guest' RETURN r",
       desc: "External guest accounts have Entra directory roles.",
       impact: "The security of these roles depends on another organisation's identity controls.",
       fix: "Remove directory roles from guests; use dedicated member accounts for administration."),
    f!("az-sp-tenant-control", High, "Azure", Edges, "Service principals with tenant-level control", ["T1098.003"],
       "MATCH (sp:AZServicePrincipal)-[r:AZGlobalAdmin|AZPrivilegedRoleAdmin|AZPrivilegedAuthAdmin]->(t:AZTenant) RETURN r",
       desc: "Applications hold Global Administrator, Privileged Role Administrator or Privileged Authentication Administrator.",
       impact: "Application credentials (often long-lived secrets) are as powerful as a Global Administrator.",
       fix: "Remove Tier Zero roles from service principals; grant narrowly scoped Graph permissions instead and protect credentials."),
    f!("az-keyvault-readers", Medium, "Azure", Edges, "Non-Tier Zero Key Vault secret readers", ["T1555.006"],
       "MATCH (p)-[r:AZGetSecrets|AZGetKeys|AZGetCertificates]->(kv:AZKeyVault) WHERE NOT p.tier0 RETURN r",
       desc: "Principals that can read Key Vault secrets, keys or certificates.",
       impact: "Vault contents often include credentials for other systems and service principals.",
       fix: "Move vaults to Azure RBAC, grant secret access per application identity, and remove broad access policies."),
    f!("az-disabled-with-roles", Low, "Azure", Edges, "Disabled users still holding roles", ["T1078.004"],
       "MATCH (u:AZUser)-[r:AZHasRole]->(role:AZRole) WHERE NOT u.enabled RETURN r",
       desc: "Disabled accounts keep their directory role assignments.",
       impact: "Re-enabling the account (or a sync mistake) restores privileged access silently.",
       fix: "Remove role assignments when accounts are disabled; automate in the leaver process."),
];

#[derive(Debug, Clone, Serialize)]
pub struct Exposure {
    pub principals_cut: u64,
    pub percent_of_exposed: f64,
}

#[derive(Debug, Clone)]
pub enum Items {
    Edges(Vec<EdgeKey>),
    Nodes(Vec<u32>),
}

impl Items {
    pub fn len(&self) -> usize {
        match self {
            Items::Edges(v) => v.len(),
            Items::Nodes(v) => v.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone)]
pub struct FindingResult {
    pub def: &'static FindingDef,
    pub items: Items,
    pub truncated: bool,
    pub exposure: Option<Exposure>,
}

impl FindingResult {
    /// `(key, label)` per item, stable across snapshots.
    pub fn item_labels(&self, g: &Graph) -> Vec<(String, String)> {
        match &self.items {
            Items::Edges(es) => es.iter().map(|&e| (edge_key(g, e), edge_label(g, e))).collect(),
            Items::Nodes(ns) => ns.iter().map(|&n| (g.oid(n).to_string(), g.name(n).to_string())).collect(),
        }
    }
}

/// Exposed principals toward `tier0` with nothing removed.
pub fn baseline(g: &Graph, tier0: &[u32]) -> u64 {
    exposure_with(g, tier0, &Removal::default(), 0).exposed_principals
}

/// Evaluate one finding; `None` when it has no items (or the query failed).
pub fn evaluate_one(g: &Graph, def: &'static FindingDef, tier0: &[u32], baseline: u64, cancel: &Cancel) -> Option<FindingResult> {
    let res = run_capped(g, def.query, FINDING_ITEM_CAP, FINDING_ITEM_CAP, cancel).ok()?;
    let items = match def.kind {
        ItemKind::Edges => Items::Edges(res.edges.clone()),
        ItemKind::Nodes => Items::Nodes(res.nodes.clone()),
    };
    if items.is_empty() {
        return None;
    }
    // Impact edges: the finding's own items, or a dedicated measurement query.
    let measured: Option<Vec<EdgeKey>> = match def.impact_query {
        Some(q) => run_capped(g, q, FINDING_ITEM_CAP, FINDING_ITEM_CAP, cancel).ok().map(|r| r.edges),
        None => None,
    };
    let exposure = match (&items, measured) {
        (_, Some(es)) if baseline > 0 => {
            let removal = Removal { edges: es.into_iter().collect(), ..Default::default() };
            let after = exposure_with(g, tier0, &removal, 0).exposed_principals;
            let cut = baseline.saturating_sub(after);
            Some(Exposure { principals_cut: cut, percent_of_exposed: 100.0 * cut as f64 / baseline as f64 })
        }
        (Items::Edges(es), None) if baseline > 0 => {
            let removal = Removal { edges: es.iter().copied().collect(), ..Default::default() };
            let after = exposure_with(g, tier0, &removal, 0).exposed_principals;
            let cut = baseline.saturating_sub(after);
            Some(Exposure { principals_cut: cut, percent_of_exposed: 100.0 * cut as f64 / baseline as f64 })
        }
        _ => None,
    };
    Some(FindingResult { def, items, truncated: res.truncated, exposure })
}

/// Order by severity, then by exposure impact.
pub fn sort_results(out: &mut [FindingResult]) {
    out.sort_by(|a, b| {
        a.def.severity.cmp(&b.def.severity).then_with(|| {
            let ea = a.exposure.as_ref().map(|e| e.principals_cut).unwrap_or(0);
            let eb = b.exposure.as_ref().map(|e| e.principals_cut).unwrap_or(0);
            eb.cmp(&ea)
        })
    });
}

/// Run every finding. `progress(done, total)` is called after each one.
pub fn evaluate(g: &Graph, tier0: &[u32], cancel: &Cancel, progress: &dyn Fn(usize, usize)) -> Vec<FindingResult> {
    let base = baseline(g, tier0);
    let mut out = Vec::new();
    for (i, def) in CATALOG.iter().enumerate() {
        progress(i, CATALOG.len());
        if cancel.hit() {
            break;
        }
        out.extend(evaluate_one(g, def, tier0, base, cancel));
    }
    progress(CATALOG.len(), CATALOG.len());
    sort_results(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_well_formed() {
        let mut ids = std::collections::HashSet::new();
        for d in CATALOG {
            assert!(ids.insert(d.id), "duplicate {}", d.id);
            ch_query::parse(d.query).unwrap_or_else(|e| panic!("{}: {e}", d.id));
            if let Some(iq) = d.impact_query {
                ch_query::parse(iq).unwrap_or_else(|e| panic!("{} impact: {e}", d.id));
            }
            assert!(!d.mitre.is_empty() && !d.remediation.is_empty());
            let ret_ok = match d.kind {
                ItemKind::Edges => d.query.trim_end().ends_with("RETURN r"),
                ItemKind::Nodes => !d.query.trim_end().ends_with("RETURN r"),
            };
            assert!(ret_ok, "{} returns the wrong item kind", d.id);
        }
    }
}
