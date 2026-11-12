//! Curated help text for every built-in edge kind: what the relationship
//! means (and its direction), how it is abused, and how to remediate it.
//! Served by `GET /api/v1/edge-kinds` as `help`; `docs/EDGES.md` (reference
//! tables) and `web/src/mock/edgeHelp.ts` are generated from it (see the
//! `help_artifacts_in_sync` test).
//!
//! Descriptions follow CopperHound's semantics (ingest in `crates/ingest`,
//! derived edges in `crates/ingest/src/postprocess/`), not necessarily
//! BloodHound CE's.

/// Help text for an edge kind: what it means, how it is abused, how to fix it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeHelp {
    pub description: &'static str,
    pub abuse: &'static str,
    pub remediation: &'static str,
}

/// Help text for a built-in edge kind (served by `/edge-kinds`). `None` for
/// kinds registered dynamically at ingest (unknown collector rights).
pub fn edge_help(name: &str) -> Option<EdgeHelp> {
    let h = |description, abuse, remediation| Some(EdgeHelp { description, abuse, remediation });
    match name {
        // ------------------------------------------------------------------
        // Active Directory: membership, local rights, sessions, delegation
        // ------------------------------------------------------------------
        "MemberOf" => h(
            "The source principal is a member of the target group (direct membership or primary group). It holds every right and privilege granted to the group; nested groups chain further MemberOf edges.",
            "No action needed: any right held by the group can be used by its members. Long nesting chains often hide indirect routes into privileged groups.",
            "Remove unnecessary memberships, keep Tier Zero groups (Domain Admins, Administrators, Account/Server/Backup/Print Operators) small and audited, and never nest lower-tier groups into Tier Zero groups.",
        ),
        "AdminTo" => h(
            "The source principal is a member of the local Administrators group of the target computer (from local group collection).",
            "Execute code remotely as SYSTEM (service creation, scheduled tasks, WMI) and harvest the credentials of logged-on users from LSASS and the local SAM / LSA secrets.",
            "Remove the principal from the computer's local Administrators group (or the GPO / Restricted Groups setting that adds it); use Windows LAPS for local administrator passwords and tiered administration so that admins of one tier never administer another.",
        ),
        "HasSession" => h(
            "A session of the target user was observed on the source computer. Control of the computer exposes the user's credentials and tokens while the session lasts.",
            "With administrative control of the computer, take the user's credential material from memory (LSASS dumping, token impersonation) and act as the user.",
            "Keep privileged accounts off lower-tier hosts (logon restrictions, Authentication Policy Silos), add them to Protected Users, enable Credential Guard, and sign out idle or disconnected sessions.",
        ),
        "CanRDP" => h(
            "The source principal may log on to the target computer through Remote Desktop (Remote Desktop Users membership or the corresponding user right).",
            "Interactive logon to the host; combined with local privilege escalation or other users' sessions on it, this leads to credential theft.",
            "Remove the principal from Remote Desktop Users and limit 'Allow log on through Remote Desktop Services' to the administrators of that host's tier; require Network Level Authentication.",
        ),
        "CanPSRemote" => h(
            "The source principal may open a PowerShell Remoting (WinRM) session on the target computer (Remote Management Users membership).",
            "Run commands on the host remotely over WinRM; with an elevated session or local privilege escalation this yields control of the host.",
            "Remove the principal from Remote Management Users, restrict WinRM to administrative networks, and use Just Enough Administration (JEA) endpoints for delegated tasks.",
        ),
        "ExecuteDCOM" => h(
            "The source principal is a member of Distributed COM Users on the target computer and may launch and activate DCOM objects remotely.",
            "Instantiate DCOM applications that expose command execution (for example MMC20.Application or ShellWindows) on the host for lateral movement.",
            "Remove the principal from Distributed COM Users and tighten machine-wide DCOM launch and activation permissions.",
        ),
        "AllowedToDelegate" => h(
            "The source account is configured for Kerberos constrained delegation to services on the target computer (msDS-AllowedToDelegateTo).",
            "With the source account's credentials, use S4U2Self / S4U2Proxy to obtain service tickets to the target as any delegable user, such as a domain admin; the service name in the ticket is not protected, so any service on the host is reachable.",
            "Remove delegation that is not needed, scope what remains to the exact service, protect the source account at the target's tier, and mark privileged accounts 'sensitive and cannot be delegated' or add them to Protected Users.",
        ),
        "AllowedToAct" => h(
            "The source principal is listed in the target computer's msDS-AllowedToActOnBehalfOfOtherIdentity: resource-based constrained delegation (RBCD) to the target.",
            "As the source account (which needs an SPN, e.g. a computer account), use S4U2Self / S4U2Proxy to impersonate an administrator to the target computer.",
            "Clear unexpected entries from msDS-AllowedToActOnBehalfOfOtherIdentity, mark privileged accounts sensitive / Protected Users, and set ms-DS-MachineAccountQuota to 0 so users cannot create computer accounts.",
        ),
        "HasSIDHistory" => h(
            "The source account carries the SID of the target principal in its sIDHistory attribute, so the source's logon tokens include the target's SID and all its access.",
            "Authenticate as the source account and use every right of the target principal; injecting SID history is also a known persistence technique.",
            "Clear sIDHistory once migrations are complete, alert on changes to the attribute, and keep SID filtering enabled on trusts.",
        ),
        "Contains" => h(
            "The source domain, OU or container contains the target object. Inheritable ACEs and GPOs applied to the container flow down to the object.",
            "With control of the container, add an inheritable ACE (e.g. full control over descendant users or computers) or link a GPO, compromising every object below it.",
            "Treat OUs and containers that hold Tier Zero objects as Tier Zero: restrict who can change their DACL and gPLink, and keep Tier Zero objects in dedicated OUs with inheritance reviewed.",
        ),
        "GPLink" => h(
            "The source GPO is linked to the target domain or OU, so its settings apply to the users and computers in that scope.",
            "Whoever can edit the GPO can push scheduled tasks, startup scripts, local group changes or user rights assignments to every object in scope (GPO abuse).",
            "Limit edit rights on GPOs linked to Tier Zero scopes to Tier Zero administrators; review GPO delegation and SYSVOL file permissions.",
        ),
        "TrustedBy" => h(
            "The source domain is trusted by the target domain (the target trusts the source); the edge points from trusted to trusting. Informational and not traversable: SameForestTrust, SpoofSIDHistory and AbuseTGTDelegation model the exploitable trust configurations.",
            "None by itself. Principals of the source domain can be granted access to resources in the target domain.",
            "Informational. Remove obsolete trusts and keep SID filtering and selective authentication enabled on external and forest trusts.",
        ),
        "DCSync" => h(
            "The source principal holds both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the target domain, directly or through (nested) group membership, possibly through different groups. Derived after ingest; the edge starts at the first principal in the membership chain that holds both (its members reach it through MemberOf), and at every principal that holds both rights itself. A right held by Authenticated Users or Everyone counts for every principal.",
            "Use the directory replication protocol (MS-DRSR) to pull the password hashes of any account, including krbtgt (DCSync), then forge tickets or authenticate as anyone.",
            "Remove replication rights from everything except domain controllers and required directory sync accounts (protect those as Tier Zero); alert on replication requests (event 4662) from non-DC sources.",
        ),
        "GetChanges" => h(
            "The source principal holds DS-Replication-Get-Changes on the target domain. Not traversable alone: together with GetChangesAll it forms DCSync, and together with GetChangesInFilteredSet it allows reading LAPS passwords (SyncLAPSPassword).",
            "On its own it only replicates non-secret attributes; it becomes dangerous in combination with the other replication rights.",
            "Grant replication rights only to domain controllers and directory sync accounts; review the domain root ACL.",
        ),
        "GetChangesAll" => h(
            "The source principal holds DS-Replication-Get-Changes-All (replication of secret attributes) on the target domain. Not traversable alone: together with GetChanges it forms DCSync.",
            "Combined with GetChanges, possibly held through a different group, it allows DCSync of every password hash in the domain.",
            "Remove the right from every principal except domain controllers and required directory sync accounts.",
        ),
        "GetChangesInFilteredSet" => h(
            "The source principal holds DS-Replication-Get-Changes-In-Filtered-Set on the target domain. Not traversable alone: together with GetChanges it allows replicating confidential attributes such as LAPS passwords.",
            "Combined with GetChanges, read LAPS passwords and other confidential attributes through DirSync (see SyncLAPSPassword).",
            "Remove the right from every principal except domain controllers and required directory sync accounts.",
        ),
        // ------------------------------------------------------------------
        // Active Directory: ACL edges (collector ACEs)
        // ------------------------------------------------------------------
        "GenericAll" => h(
            "The source principal has full control of the target object.",
            "Depends on the target: reset a user's password, add shadow credentials or an SPN (targeted Kerberoasting), add group members, configure RBCD on or read the LAPS password of a computer, edit a GPO, replicate secrets from a domain (DCSync), or reconfigure a certificate template (ESC4).",
            "Remove the ACE from the target's DACL, or the inheritable ACE on its parent container; for protected accounts also check the AdminSDHolder DACL.",
        ),
        "GenericWrite" => h(
            "The source principal can write all non-protected attributes of the target object.",
            "On users: set an SPN (targeted Kerberoasting), add shadow credentials or change the logon script; on groups: add members; on computers: configure RBCD or shadow credentials; on GPOs: change policy; on certificate templates: reconfigure them (ESC4).",
            "Remove the write ACE from the target (or its parent's inheritable ACE); delegate narrowly scoped property writes instead of GenericWrite.",
        ),
        "WriteOwner" => h(
            "The source principal can change the owner of the target object.",
            "Make itself the owner, then use the owner's implicit right to rewrite the DACL and grant itself full control.",
            "Remove the WriteOwner ACE; where owners must exist outside Tier Zero, add an OWNER RIGHTS ACE that limits the owner's implicit rights.",
        ),
        "WriteDacl" => h(
            "The source principal can modify the DACL of the target object.",
            "Grant itself any right on the target (full control, or replication rights on a domain for DCSync) and abuse it.",
            "Remove the WriteDacl ACE; monitor DACL changes (event 5136) on Tier Zero objects.",
        ),
        "Owns" => h(
            "The source principal owns the target object. Owners implicitly hold read-control and write-DACL unless an OWNER RIGHTS ACE restricts them.",
            "Rewrite the DACL to grant itself full control, then abuse the target as with GenericAll.",
            "Set the owner of Tier Zero objects to a Tier Zero group (e.g. Domain Admins); objects created by delegated accounts keep their creator as owner, so review ownership regularly.",
        ),
        "AddMember" => h(
            "The source principal can add arbitrary members to the target group (write access to the member attribute, or a group manager allowed to update membership). Rights held by a group are reached through MemberOf, not copied to each member.",
            "Add a controlled account to the group and inherit the group's rights.",
            "Remove the write-member right or the manager's 'can update membership' setting; alert on membership changes of privileged groups (events 4728 / 4732 / 4756).",
        ),
        "ForceChangePassword" => h(
            "The source principal holds the User-Force-Change-Password extended right on the target user.",
            "Reset the user's password without knowing the current one and log on as the user (disruptive, so it may be noticed).",
            "Remove the extended right; scope helpdesk password-reset delegation to OUs without privileged accounts.",
        ),
        "AllExtendedRights" => h(
            "The source principal holds all extended rights on the target object.",
            "On a user: force a password reset; on a domain: replicate secrets (DCSync); on a computer with LAPS: read the local administrator password; on a certificate template: enroll.",
            "Remove the ACE; grant individual extended rights only where they are needed.",
        ),
        "AddKeyCredentialLink" => h(
            "The source principal can write msDS-KeyCredentialLink on the target user or computer.",
            "Add a key credential (Shadow Credentials) and authenticate as the target with PKINIT, obtaining its TGT and NT hash.",
            "Remove write access to msDS-KeyCredentialLink; treat Key Admins and Enterprise Key Admins as Tier Zero; alert on changes to the attribute.",
        ),
        "AddAllowedToAct" => h(
            "The source principal can write msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer.",
            "Configure resource-based constrained delegation from an account it controls and impersonate an administrator to the computer (RBCD).",
            "Remove the write right; set ms-DS-MachineAccountQuota to 0 and protect privileged accounts with Protected Users / 'sensitive and cannot be delegated'.",
        ),
        "ReadLAPSPassword" => h(
            "The source principal can read the target computer's LAPS-managed local administrator password (ms-Mcs-AdmPwd or msLAPS-Password).",
            "Read the password and log on to the computer as local administrator.",
            "Restrict read access to the LAPS password attributes to the administrators of that computer's tier, and audit who holds it (including through All Extended Rights).",
        ),
        "ReadGMSAPassword" => h(
            "The source principal may retrieve the managed password of the target group managed service account (listed in msDS-GroupMSAMembership).",
            "Read msDS-ManagedPassword, derive the account's NT hash and authenticate as the gMSA.",
            "Limit PrincipalsAllowedToRetrieveManagedPassword to the hosts that run the service, and protect those hosts at the gMSA's tier.",
        ),
        "WriteSPN" => h(
            "The source principal can write servicePrincipalName on the target user.",
            "Set an SPN on the user, request a service ticket for it and crack the password offline (targeted Kerberoasting).",
            "Remove the write right; use gMSAs or long random passwords for service accounts and disable RC4 for Kerberos.",
        ),
        "AddSelf" => h(
            "The source principal can add itself (and only itself) to the target group through the Self-Membership validated write.",
            "Add itself to the group and inherit the group's rights.",
            "Remove the Self-Membership right from the group's DACL; alert on membership changes of privileged groups.",
        ),
        "WriteAccountRestrictions" => h(
            "The source principal can write the User-Account-Restrictions property set of the target computer, which includes msDS-AllowedToActOnBehalfOfOtherIdentity.",
            "Configure resource-based constrained delegation on the computer and impersonate an administrator to it (RBCD).",
            "Remove the property-set write (often granted to the account that joined the computer); set ms-DS-MachineAccountQuota to 0.",
        ),
        "SyncLAPSPassword" => h(
            "The source principal holds GetChanges and GetChangesInFilteredSet on the domain of the target computer (directly or through group membership, emitted where the pair first completes, like DCSync), so it can obtain the computer's LAPS password through DirSync without explicit read access. Targets are the domain's computers with haslaps. Not emitted for principals that can also DCSync, which already yields the whole domain.",
            "Issue a DirSync LDAP query that returns the confidential LAPS password attribute, then log on as local administrator.",
            "Remove the replication rights from every principal except domain controllers and required directory sync accounts.",
        ),
        "OwnsLimitedRights" => h(
            "The source principal owns the target object, but an OWNER RIGHTS ACE replaces the owner's implicit rights; the edge exists because that ACE still grants the owner abusable permissions.",
            "Use whatever the OWNER RIGHTS ACE grants (for example write or full control) as with the equivalent ACL edge.",
            "Reduce the OWNER RIGHTS ACE to read-only rights, or change the owner to a Tier Zero group.",
        ),
        "WriteOwnerLimitedRights" => h(
            "The source principal can change the owner of the target object, and an OWNER RIGHTS ACE defines what the new owner gets; the edge exists because that ACE still grants abusable permissions.",
            "Take ownership and use the permissions the OWNER RIGHTS ACE grants to the owner.",
            "Remove the WriteOwner ACE, or reduce the OWNER RIGHTS ACE to read-only rights.",
        ),
        "WriteGPLink" => h(
            "The source principal can write the gPLink attribute of the target domain or OU.",
            "Link a GPO it controls to the scope and run code on, or change settings for, every user and computer in it (GPO abuse).",
            "Restrict write access to gPLink on scopes that contain Tier Zero objects to Tier Zero administrators; alert on gPLink changes.",
        ),
        // ------------------------------------------------------------------
        // ADCS (docs/research/adcs.md, postprocess/adcs.rs)
        // ------------------------------------------------------------------
        "Enroll" => h(
            "The source principal holds the Certificate-Enrollment right on the target certificate template or enterprise CA. Not traversable: it is an input to the ADCSESC edges, which require enrollment on both the template and the CA.",
            "Request certificates from the template; dangerous only when the template or CA is misconfigured (see the ADCSESC edges).",
            "Grant enrollment only to the principals that need the template; avoid Domain Users, Domain Computers or Authenticated Users on templates that allow authentication.",
        ),
        "ManageCA" => h(
            "The source principal holds the CA Administrator (Manage CA) permission on the target enterprise CA.",
            "ESC7: change the CA's configuration, for example grant itself Certificate Manager, enable the user-specified SAN flag (EDITF_ATTRIBUTESUBJECTALTNAME2) or enable the SubCA template and approve its own failed request, to obtain a certificate for any user.",
            "Restrict CA Administrator to Tier Zero administrators and treat every enterprise CA as Tier Zero; alert on CA configuration changes.",
        ),
        "ManageCertificates" => h(
            "The source principal holds the Certificate Manager (Issue and Manage Certificates) permission on the target enterprise CA.",
            "Approve pending certificate requests, which defeats manager approval on templates (part of ESC7).",
            "Restrict Certificate Manager to Tier Zero administrators; use certificate manager restrictions on the CA.",
        ),
        "WritePKIEnrollmentFlag" => h(
            "The source principal can write msPKI-Enrollment-Flag on the target certificate template. Not traversable: one of the rights combinations that make up ADCSESC4.",
            "Turn off manager approval or change enrollment behaviour so that, with enrollment rights, the template becomes exploitable (ESC4).",
            "Remove write access to certificate templates from every principal outside Tier Zero.",
        ),
        "WritePKINameFlag" => h(
            "The source principal can write msPKI-Certificate-Name-Flag on the target certificate template. Not traversable: one of the rights combinations that make up ADCSESC4.",
            "Set the 'enrollee supplies subject' flag so that, with enrollment rights, the template behaves like an ESC1 template (ESC4).",
            "Remove write access to certificate templates from every principal outside Tier Zero.",
        ),
        "PublishedTo" => h(
            "The source certificate template is published on (enabled for) the target enterprise CA, which issues certificates from it. Structural and not traversable.",
            "None by itself; the ADCSESC edges are evaluated per published template.",
            "Informational. Unpublish templates that are no longer used.",
        ),
        "HostsCAService" => h(
            "The source computer hosts the target enterprise CA service. Structural and not traversable; the host is tagged Tier Zero and is the source of GoldenCert.",
            "None by itself; see GoldenCert.",
            "Informational. Treat CA hosts as Tier Zero.",
        ),
        "DelegatedEnrollmentAgent" => h(
            "The CA's enrollment agent restrictions allow the source principal to enroll on behalf of others for the target certificate template. Not traversable; an input to ADCSESC3 when the CA enforces restrictions.",
            "None by itself; see ADCSESC3.",
            "Keep enrollment agent restrictions limited to the agents and templates that are actually required.",
        ),
        "RootCAFor" => h(
            "The source root CA object is trusted as a root by the target domain (Certification Authorities container). Structural and not traversable.",
            "None by itself; the ESC and GoldenCert edges require the issuing CA to chain to a root trusted by the domain.",
            "Informational. Remove stale root CA objects from the Configuration partition.",
        ),
        "NTAuthStoreFor" => h(
            "The source NTAuth store belongs to the target domain. CAs whose certificates are in it can issue certificates that domain controllers accept for logon. Structural and not traversable.",
            "None by itself; the ESC and GoldenCert edges require the issuing CA to be in the domain's NTAuth store.",
            "Informational. Keep only actively used issuing CAs in NTAuthCertificates.",
        ),
        "OIDGroupLink" => h(
            "The source issuance policy is linked to the target group (msDS-OIDToGroupLink): a logon with a certificate carrying the policy adds the group to the token. Structural and not traversable; used by ADCSESC13.",
            "None by itself; see ADCSESC13.",
            "Do not link issuance policies to privileged groups; remove links that are not required.",
        ),
        "TrustedForNTAuth" => h(
            "The source enterprise CA's certificate is in the target NTAuth store, so domain controllers accept its certificates for Kerberos (PKINIT) and Schannel logon. Structural and not traversable.",
            "None by itself; required by the ESC and GoldenCert edges.",
            "Informational. Remove CAs that do not need to issue logon certificates from NTAuthCertificates.",
        ),
        "IssuedSignedBy" => h(
            "The source CA's certificate was issued and signed by the target CA (matched by the next thumbprint in the source's certificate chain). Structural and not traversable.",
            "None by itself; used to validate chains to a trusted root.",
            "Informational.",
        ),
        "EnterpriseCAFor" => h(
            "The source enterprise CA uses the same certificate (thumbprint) as the target root CA or AIA CA object. Structural and not traversable.",
            "None by itself; used to validate chains to a trusted root.",
            "Informational.",
        ),
        "ExtendedByPolicy" => h(
            "The source certificate template carries the target issuance policy (a certificate policy OID of the same domain). Structural and not traversable; used by ADCSESC13.",
            "None by itself; see ADCSESC13.",
            "Informational. Review templates that carry policies linked to groups.",
        ),
        "EnrollOnBehalfOf" => h(
            "Certificates from the source template (Certificate Request Agent) can be used to enroll on behalf of other users in the target template, which accepts agent-signed requests. Structural and not traversable; an input to ADCSESC3.",
            "None by itself; see ADCSESC3.",
            "Restrict enrollment on enrollment agent templates and enable enrollment agent restrictions on the CA.",
        ),
        "GoldenCert" => h(
            "The source computer hosts an enterprise CA that the target domain trusts for authentication (it chains to a trusted root and is in the domain's NTAuth store).",
            "With control of the CA host, extract the CA's private key and forge certificates for any principal (Golden Certificate), then authenticate with PKINIT or Schannel.",
            "Treat CA hosts as Tier Zero: restrict local administrators, protect the CA private key with an HSM, and monitor CA key backup or export.",
        ),
        "ADCSESC1" => h(
            "The source principal can enroll (template and CA) in a template, published to a CA the target domain trusts, that lets the enrollee supply the subject, allows client authentication, needs no manager approval and no authorized signatures.",
            "Request a certificate with a privileged user's identity in the subject alternative name and authenticate as that user (ESC1).",
            "Remove 'enrollee supplies subject' from authentication templates, or require manager approval; restrict enrollment; enforce strong certificate mapping (KB5014754).",
        ),
        "ADCSESC3" => h(
            "The source principal can enroll in an enrollment agent template and in a target template that accepts agent-signed requests (no manager approval, authentication allowed), on CAs trusted by the target domain, within any enrollment agent restrictions.",
            "Obtain an enrollment agent certificate and use it to request an authentication certificate on behalf of a privileged user (ESC3).",
            "Restrict enrollment on enrollment agent templates, configure enrollment agent restrictions on the CA, and require manager approval on templates that accept agent requests.",
        ),
        "ADCSESC4" => h(
            "The source principal can enroll through a CA the target domain trusts and holds enough write or control rights on a published template to make it exploitable (control rights, GenericWrite plus enrollment, or the name / enrollment flag rights plus enrollment).",
            "Reconfigure the template into an ESC1-style template, enroll as a privileged user and authenticate as that user (ESC4).",
            "Remove owner, DACL and write rights on certificate templates from every principal outside Tier Zero.",
        ),
        "ADCSESC6a" => h(
            "The CA allows requester-specified SANs (EDITF_ATTRIBUTESUBJECTALTNAME2) and the source principal can enroll in a published template without manager approval that allows authentication and has no security extension. For templates that require a DNS name, only computers and (g)MSAs qualify.",
            "Request a certificate with a privileged user in the SAN; without the SID security extension the domain controller maps it by the SAN (ESC6).",
            "Remove EDITF_ATTRIBUTESUBJECTALTNAME2 from the CA's policy EditFlags and enforce strong certificate binding (StrongCertificateBindingEnforcement = 2).",
        ),
        "ADCSESC6b" => h(
            "The CA allows requester-specified SANs (EDITF_ATTRIBUTESUBJECTALTNAME2), the source principal can enroll in a published template without manager approval that allows Schannel authentication, and a domain controller in the forest has UPN mapping enabled for Schannel (CertificateMappingMethods 0x4).",
            "Request a certificate with a privileged user's UPN in the SAN and authenticate as that user over Schannel, e.g. LDAPS (ESC6).",
            "Remove EDITF_ATTRIBUTESUBJECTALTNAME2 from the CA and remove the UPN flag (0x4) from CertificateMappingMethods on domain controllers.",
        ),
        "ADCSESC9a" => h(
            "The source principal has write access (GenericAll, GenericWrite, Owns, WriteOwner, WriteDacl or WritePublicInformation) to a user that can enroll in a template with no security extension whose subject is built from the UPN, and a domain controller in the forest uses weak certificate binding (StrongCertificateBindingEnforcement 0 or 1).",
            "Change the victim's UPN to a privileged account's name, enroll as the victim, restore the UPN and authenticate with the certificate as the privileged account (ESC9).",
            "Set StrongCertificateBindingEnforcement = 2 on all domain controllers, remove the no-security-extension flag from templates, and remove write access to user objects.",
        ),
        "ADCSESC9b" => h(
            "The source principal has write access (GenericAll, GenericWrite, Owns, WriteOwner or WriteDacl) to a computer that can enroll in a template with no security extension whose subject is built from the DNS name, and a domain controller in the forest uses weak certificate binding.",
            "Change the victim computer's dNSHostName to that of a privileged computer (e.g. a DC), enroll as the victim and authenticate as the privileged computer (ESC9).",
            "Set StrongCertificateBindingEnforcement = 2 on all domain controllers, remove the no-security-extension flag from templates, and remove write access to computer objects.",
        ),
        "ADCSESC10a" => h(
            "The source principal has write access (GenericAll, GenericWrite, Owns, WriteOwner, WriteDacl or WritePublicInformation) to a user that can enroll in a Schannel-capable template whose subject is built from the UPN, and a domain controller in the forest maps certificates by UPN for Schannel (CertificateMappingMethods 0x4).",
            "Change the victim's UPN to a privileged account's name, enroll as the victim, restore the UPN and authenticate over Schannel as the privileged account (ESC10).",
            "Remove the UPN flag (0x4) from CertificateMappingMethods on domain controllers and remove write access to user objects.",
        ),
        "ADCSESC10b" => h(
            "The source principal has write access (GenericAll, GenericWrite, Owns, WriteOwner or WriteDacl) to a computer that can enroll in a Schannel-capable template whose subject is built from the DNS name, and a domain controller in the forest maps certificates by UPN for Schannel (CertificateMappingMethods 0x4).",
            "Change the victim computer's dNSHostName to that of a privileged computer, enroll as the victim and authenticate over Schannel as the privileged computer (ESC10).",
            "Remove the UPN flag (0x4) from CertificateMappingMethods on domain controllers and remove write access to computer objects.",
        ),
        "ADCSESC13" => h(
            "The source principal can enroll (template and CA) in a template without manager approval that allows authentication and carries an issuance policy linked to the target group (OIDGroupLink). Points to the group, not the domain.",
            "Enroll and authenticate with the certificate; the resulting logon token contains the linked group (ESC13).",
            "Remove the issuance policy's group link or restrict enrollment on the template; never link issuance policies to privileged groups.",
        ),
        "WritePublicInformation" => h(
            "The source principal can write the Public-Information property set of the target user or computer, which includes userPrincipalName. Not traversable; an attacker right for ADCSESC9a and ADCSESC10a.",
            "Rewrite the victim's UPN as part of ESC9 / ESC10.",
            "Remove write access to the Public-Information property set from principals that do not administer the account.",
        ),
        // ------------------------------------------------------------------
        // Azure / Entra ID (docs/research/azurehound.md, postprocess/azure.rs)
        // ------------------------------------------------------------------
        "AZContains" => h(
            "The source scope (tenant, management group, subscription or resource group) contains the target object. Rights granted on a scope apply to everything below it.",
            "Use rights held on the container against its children, e.g. Owner on a subscription controls every VM, key vault and automation account in it.",
            "Grant Azure RBAC at the narrowest scope; audit Owner, Contributor and User Access Administrator on management groups and subscriptions.",
        ),
        "AZMemberOf" => h(
            "The source principal is a member of the target Entra ID group and inherits its directory roles, Azure RBAC assignments and app access.",
            "No action needed: rights held by the group can be used by its members.",
            "Remove unnecessary memberships; assign privileged roles only to role-assignable groups and protect their owners.",
        ),
        "AZOwns" => h(
            "The source principal is an owner of the target Entra ID group, application or service principal.",
            "Group owners can add members; application and service principal owners can add client secrets or certificates and authenticate as the service principal.",
            "Remove owners that are not needed, keep privileged apps and role-assignable groups owned only by Tier Zero accounts, and restrict credential types with app management policies.",
        ),
        "AZHasRole" => h(
            "The source principal holds an active assignment of the target Entra ID directory role (directly, or through a role-assignable group). Tenant-wide assignments point to the tenant's role node; assignments scoped to an administrative unit, an application or a single object point to a separate scoped role node (\"<role> (scope: <name>)\") that grants only what the scope allows (see AZScopedTo).",
            "Use the role's permissions; the role's own outgoing edges (AZResetPassword, AZAddSecret, AZAddOwner, ...) show what it controls.",
            "Remove standing assignments; use PIM with approval and MFA for privileged roles, and prefer the least-privileged role.",
        ),
        "AZRunsAs" => h(
            "The source application registration is instantiated as the target service principal; credentials added to the app authenticate as the service principal.",
            "Whoever can add credentials to the app (owners, Application Administrators, Application.ReadWrite.All) can sign in as the service principal and use its roles and permissions.",
            "Protect applications whose service principals are privileged: restrict owners and alert on new application credentials.",
        ),
        "AZManagedIdentity" => h(
            "The source Azure resource (VM, scale set, web or function app, logic app, automation account, AKS cluster, ...) runs with the target service principal as its managed identity.",
            "With code execution on the resource, request tokens for the managed identity from the instance metadata endpoint and use its permissions.",
            "Give managed identities least privilege and restrict who can run code on, or reconfigure, the resource.",
        ),
        "AZNodeResourceGroup" => h(
            "The source AKS cluster places its node pool resources (VM scale sets and their identities) in the target node resource group.",
            "Control of the cluster gives control of the node resources, including the managed identities attached to them.",
            "Restrict cluster-level roles (AKS Contributor, cluster admin) and give the kubelet and node identities least privilege.",
        ),
        "AZAuthenticatesTo" => h(
            "The source federated identity credential (an external workload identity such as a CI pipeline or Kubernetes service account) can exchange its tokens for tokens of the target application.",
            "Control of the external identity (e.g. pushing to the trusted repository branch) yields tokens as the application (workload identity federation abuse).",
            "Scope federated credentials to exact subjects (branch, environment, service account), protect the external system at the app's privilege level, and remove unused credentials.",
        ),
        "AZRoleEligible" => h(
            "The source principal is eligible (PIM) for the target directory role at tenant scope and must activate it before use. Not traversable.",
            "Activate the role through PIM when the activation requirements (MFA, justification, approval) can be met.",
            "Require approval and MFA or an authentication context for activation of privileged roles; review eligible assignments regularly.",
        ),
        "AZRoleApprover" => h(
            "The source user or group is a PIM approver for activations of the target directory role (from AzureHound role management policies; only roles whose activation requires approval). When approval is required but no approver is listed, the Privileged Role Administrator and Global Administrator roles are the source. Not traversable: an approver cannot approve its own request.",
            "Approve an activation request of a compromised or colluding eligible principal.",
            "Limit approvers of privileged roles to Tier Zero administrators.",
        ),
        "AZAppAdmin" => h(
            "The source principal holds Application Administrator scoped to the target application.",
            "Add a client secret or certificate to the application and authenticate as its service principal.",
            "Remove the scoped role assignment, or make sure the application's service principal holds no privileges beyond the assignee's.",
        ),
        "AZCloudAppAdmin" => h(
            "The source principal holds Cloud Application Administrator scoped to the target application.",
            "Add a client secret or certificate to the application and authenticate as its service principal.",
            "Remove the scoped role assignment, or make sure the application's service principal holds no privileges beyond the assignee's.",
        ),
        "AZOwner" => h(
            "The source principal holds the Azure RBAC Owner role on the target scope or resource.",
            "Full control including role assignment: run commands on VMs, read key vault contents, take over managed identities, or grant itself any role.",
            "Remove the Owner assignment or narrow its scope; use PIM for Owner on management groups and subscriptions.",
        ),
        "AZContributor" => h(
            "The source principal holds the Azure RBAC Contributor role on the target scope or resource (manage everything except role assignments).",
            "Run commands on VMs, deploy code to web and function apps, edit runbooks, and act as the resources' managed identities.",
            "Remove the Contributor assignment or replace it with narrower roles; scope it to the resources that need it.",
        ),
        "AZUserAccessAdministrator" => h(
            "The source principal holds User Access Administrator on the target scope or resource and can manage its role assignments.",
            "Grant itself Owner (or any role) on the scope and abuse it.",
            "Remove the assignment; restrict role-assignment rights with PIM and Azure RBAC conditions.",
        ),
        "AZKeyVaultContributor" => h(
            "The source principal holds Key Vault Contributor on the target key vault: it manages the vault, including its access policies, but has no data-plane access by default.",
            "On vaults using access policies, add an access policy granting itself access to keys, secrets and certificates.",
            "Move vaults to the Azure RBAC permission model and remove the assignment where not needed.",
        ),
        "AZVMContributor" => h(
            "The source principal holds Virtual Machine Contributor on the target VM.",
            "Run commands on the VM as SYSTEM or root (Run Command, custom script extension) and use its managed identity.",
            "Remove the assignment; restrict who can run commands on VMs that hold privileged identities or credentials.",
        ),
        "AZVMAdminLogin" => h(
            "The source principal holds Virtual Machine Administrator Login on the target VM (Entra ID sign-in as local administrator).",
            "Sign in as administrator and harvest credentials and tokens on the VM, including its managed identity.",
            "Remove the assignment; grant Virtual Machine User Login where administrative access is not needed.",
        ),
        "AZAvereContributor" => h(
            "The source principal holds Avere Contributor on the target VM, which includes VM management permissions.",
            "Run commands on the VM as with Virtual Machine Contributor and use its managed identity.",
            "Remove the assignment where Avere vFXT management is not required.",
        ),
        "AZWebsiteContributor" => h(
            "The source principal holds Website Contributor on the target web or function app.",
            "Deploy code or use the SCM (Kudu) console to execute code in the app, read its settings and use its managed identity.",
            "Remove the assignment; disable basic SCM publishing credentials and limit deployment rights on apps with privileged identities.",
        ),
        "AZLogicAppContributor" => h(
            "The source principal holds Logic App Contributor on the target logic app.",
            "Edit the workflow so that it acts with the logic app's managed identity or API connections.",
            "Remove the assignment; give logic app identities and connections least privilege.",
        ),
        "AZAutomationContributor" => h(
            "The source principal holds Automation Contributor on the target automation account.",
            "Create or edit runbooks that run as the account's managed identity and read its stored credentials and variables.",
            "Remove the assignment; give automation identities least privilege and avoid stored credentials.",
        ),
        "AZAKSContributor" => h(
            "The source principal holds Azure Kubernetes Service Contributor on the target cluster.",
            "Reconfigure the cluster or run commands in it to reach its workloads, secrets and identities.",
            "Remove the assignment; use Entra ID integration with Kubernetes RBAC and restrict cluster-level roles.",
        ),
        "AZGetKeys" => h(
            "The source principal has Get permission on the keys of the target key vault (access policy).",
            "Use or read the vault's keys, for example to decrypt data protected by them.",
            "Remove the access policy entry or move the vault to the Azure RBAC permission model with least privilege.",
        ),
        "AZGetSecrets" => h(
            "The source principal has Get permission on the secrets of the target key vault (access policy).",
            "Read stored secrets such as passwords, connection strings and client secrets, and use them to authenticate elsewhere.",
            "Remove the access policy entry or move the vault to the Azure RBAC permission model with least privilege.",
        ),
        "AZGetCertificates" => h(
            "The source principal has Get permission on the certificates of the target key vault (access policy).",
            "Retrieve certificates, including exportable private keys, and authenticate as the identities they belong to (e.g. service principals).",
            "Remove the access policy entry or move the vault to the Azure RBAC permission model with least privilege.",
        ),
        "AZMGApplication_ReadWrite_All" => h(
            "The source service principal holds the Microsoft Graph application permission Application.ReadWrite.All (the target is the Microsoft Graph service principal). Not traversable; the azure pass derives AZMGAddSecret and AZMGAddOwner over every application and service principal of the tenant.",
            "See AZMGAddSecret: add credentials to any application or service principal and authenticate as it.",
            "Revoke the permission unless strictly required; treat its holders as Tier Zero and protect their credentials.",
        ),
        "AZMGAppRoleAssignment_ReadWrite_All" => h(
            "The source service principal holds the Microsoft Graph application permission AppRoleAssignment.ReadWrite.All (the target is the Microsoft Graph service principal). Not traversable; derives AZMGGrantAppRoles to the tenant.",
            "See AZMGGrantAppRoles: grant itself any application permission, including RoleManagement.ReadWrite.Directory.",
            "Revoke the permission unless strictly required; treat its holders as Tier Zero.",
        ),
        "AZMGDirectory_ReadWrite_All" => h(
            "The source service principal holds the Microsoft Graph application permission Directory.ReadWrite.All (the target is the Microsoft Graph service principal). Not traversable; derives AZMGAddMember and AZMGAddOwner over non-role-assignable groups.",
            "See AZMGAddMember: add principals to groups and inherit their access.",
            "Revoke the permission or replace it with narrower Graph permissions.",
        ),
        "AZMGGroup_ReadWrite_All" => h(
            "The source service principal holds the Microsoft Graph application permission Group.ReadWrite.All (the target is the Microsoft Graph service principal). Not traversable; derives AZMGAddMember and AZMGAddOwner over non-role-assignable groups.",
            "See AZMGAddMember and AZMGAddOwner.",
            "Revoke the permission or replace it with narrower Graph permissions; assign privileged access only to role-assignable groups.",
        ),
        "AZMGGroupMember_ReadWrite_All" => h(
            "The source service principal holds the Microsoft Graph application permission GroupMember.ReadWrite.All (the target is the Microsoft Graph service principal). Not traversable; derives AZMGAddMember over non-role-assignable groups.",
            "See AZMGAddMember.",
            "Revoke the permission or scope the application's use; assign privileged access only to role-assignable groups.",
        ),
        "AZMGRoleManagement_ReadWrite_Directory" => h(
            "The source service principal holds the Microsoft Graph application permission RoleManagement.ReadWrite.Directory (the target is the Microsoft Graph service principal). Not traversable; derives AZMGGrantRole over every directory role.",
            "See AZMGGrantRole: assign any directory role, including Global Administrator.",
            "Revoke the permission; treat its holders as Tier Zero.",
        ),
        "AZMGServicePrincipalEndpoint_ReadWrite_All" => h(
            "The source service principal holds the Microsoft Graph application permission ServicePrincipalEndpoint.ReadWrite.All (the target is the Microsoft Graph service principal). Not traversable; like BloodHound CE, the azure pass derives AZMGAddOwner over every service principal from it.",
            "See AZMGAddOwner.",
            "Revoke the permission unless strictly required.",
        ),
        "AZMGAddSecret" => h(
            "The source service principal (Application.ReadWrite.All) can add credentials to the target application or service principal.",
            "Add a client secret or certificate and authenticate as the target service principal, using its roles and permissions.",
            "Revoke Application.ReadWrite.All from the source; alert on credential additions to privileged applications.",
        ),
        "AZMGAddOwner" => h(
            "The source service principal can add owners to the target application, service principal or non-role-assignable group (from Application.ReadWrite.All, Directory.ReadWrite.All, Group.ReadWrite.All or ServicePrincipalEndpoint.ReadWrite.All).",
            "Make a controlled principal owner of the target, then add credentials (apps, service principals) or members (groups).",
            "Revoke the underlying Graph permission from the source; alert on owner changes of privileged objects.",
        ),
        "AZMGAddMember" => h(
            "The source service principal can add members to the target non-role-assignable group (from Directory.ReadWrite.All, Group.ReadWrite.All or GroupMember.ReadWrite.All).",
            "Add a controlled principal to the group and inherit its Azure RBAC and application access.",
            "Revoke the underlying Graph permission; assign privileged access only to role-assignable groups.",
        ),
        "AZMGGrantAppRoles" => h(
            "The source service principal holds AppRoleAssignment.ReadWrite.All and can grant any application permission in the target tenant.",
            "Grant itself a dangerous Microsoft Graph permission (e.g. RoleManagement.ReadWrite.Directory) and use it to become Global Administrator.",
            "Revoke AppRoleAssignment.ReadWrite.All; treat its holders as Tier Zero.",
        ),
        "AZMGGrantRole" => h(
            "The source service principal holds RoleManagement.ReadWrite.Directory and can assign the target directory role to any principal.",
            "Assign Global Administrator (or another privileged role) to a principal it controls.",
            "Revoke RoleManagement.ReadWrite.Directory; treat its holders as Tier Zero.",
        ),
        "AZGlobalAdmin" => h(
            "The source principal holds Global Administrator in the target tenant (directly or through a role-assignable group).",
            "Full control of Entra ID; Global Administrators can also elevate themselves to User Access Administrator over every Azure subscription.",
            "Keep Global Administrators to a few cloud-only, phishing-resistant-MFA accounts activated through PIM.",
        ),
        "AZPrivilegedRoleAdmin" => h(
            "The source principal holds Privileged Role Administrator in the target tenant.",
            "Assign any directory role, including Global Administrator, to itself or another principal.",
            "Treat the role as Tier Zero: few cloud-only accounts, PIM with approval, phishing-resistant MFA.",
        ),
        "AZPrivilegedAuthAdmin" => h(
            "The source principal holds Privileged Authentication Administrator in the target tenant.",
            "Reset the password and authentication methods of any user, including Global Administrators, and sign in as them.",
            "Treat the role as Tier Zero: few cloud-only accounts, PIM with approval, phishing-resistant MFA.",
        ),
        "AZResetPassword" => h(
            "The source directory role can reset the password of the target user. Global and Privileged Authentication Administrators (and Partner Tier2 Support) reach every user; User, Helpdesk, Authentication and Password Administrators only users without roles or with lesser roles (roles held at any scope count), outside role-assignable groups. Also emitted from Directory Synchronization Accounts to every synced user. A role assigned at a single-user scope reaches only that user; administrative-unit scopes grant no edges because AU membership is not collected. Holders reach the role through AZHasRole.",
            "Reset the user's password (and, where the role allows, authentication methods) and sign in as the user.",
            "Remove standing assignments of password-reset roles, use PIM, scope helpdesk roles with administrative units, and protect privileged users with role-assignable groups.",
        ),
        "AZAddMembers" => h(
            "The source principal can add members to the target group: Global and Privileged Role Administrators to any group; Groups, User, Intune, Knowledge and Identity Governance Administrators, Knowledge Managers and Directory Writers to non-role-assignable groups. For a role assigned at a single-group scope the source is the scoped role node and the target only that group.",
            "Add a controlled principal to the group and inherit its roles, Azure RBAC and application access.",
            "Remove standing assignments of these roles; grant privileged access only through role-assignable groups.",
        ),
        "AZAddSecret" => h(
            "The source directory role (Application Administrator or Cloud Application Administrator, tenant-wide, or scoped to the target service principal) can add credentials to the target application or service principal. Holders reach the role through AZHasRole. Assignments scoped to one application are AZAppAdmin / AZCloudAppAdmin instead.",
            "Add a client secret or certificate to the target and authenticate as its service principal.",
            "Use PIM for application administration roles; keep privileged service principals few and monitor credential additions.",
        ),
        "AZAddOwner" => h(
            "The source directory role (Hybrid Identity Administrator, Partner Tier1 / Tier2 Support or Directory Synchronization Accounts) can add owners to the target application or service principal. Holders reach the role through AZHasRole.",
            "Make a controlled principal owner of the target, add credentials and authenticate as its service principal.",
            "Remove standing assignments of these roles; alert on owner changes of privileged applications.",
        ),
        "AZExecuteCommand" => h(
            "The source principal holds Intune Administrator and the target is a Windows device in the same tenant (or the source is an Intune Administrator role scoped to that device).",
            "Deploy a script or application through Intune that runs as SYSTEM on the device, and harvest credentials of its users.",
            "Treat Intune Administrator as highly privileged: PIM, multi-admin approval for script deployment, and separate devices for Tier Zero administrators.",
        ),
        // ------------------------------------------------------------------
        // Derived AD edges, trusts and hybrid (docs/EDGES.md)
        // ------------------------------------------------------------------
        "CoerceToTGT" => h(
            "The source account is enabled and trusted for unconstrained delegation. Any principal of the target domain that authenticates to it forwards a TGT. Within a forest (and across trusts with TGT delegation enabled) every domain whose DCs can be coerced is a target.",
            "Coerce a domain controller of the target domain (PrinterBug / PetitPotam / DFSCoerce) to authenticate to the host, extract the DC's TGT from memory and DCSync.",
            "Replace unconstrained delegation with constrained or resource-based delegation; disable the Print Spooler on DCs; add privileged accounts to Protected Users.",
        ),
        "SameForestTrust" => h(
            "The source domain trusts the target domain, and both are in the same forest (parent-child, tree-root or shortcut trust). The forest, not the domain, is the security boundary: SID filtering does not apply inside a forest.",
            "Control of any domain in the forest yields the forest: forge a ticket with the Enterprise Admins SID in its SID history (ExtraSids) or coerce a DC of the other domain to an unconstrained delegation host.",
            "Not removable. Treat every domain in the forest as one Tier Zero; split security boundaries into separate forests.",
        ),
        "CrossForestTrust" => h(
            "The source domain trusts the target domain across a forest (forest or external trust). Principals of the target domain can access resources in the source domain. Not traversable by itself.",
            "No direct abuse; see SpoofSIDHistory and AbuseTGTDelegation for the configurations that make a cross-forest trust exploitable.",
            "Keep SID filtering (quarantine) and selective authentication enabled; disable TGT delegation across the trust.",
        ),
        "SpoofSIDHistory" => h(
            "The target domain trusts the source domain across a forest without SID filtering, so SIDs in a ticket's SID history are honoured. (Inside a forest there is no SID filtering at all; SameForestTrust covers that case.)",
            "With control of the source domain, forge a referral ticket whose SID history carries a privileged SID of the target domain (across forests: RID >= 1000 only).",
            "Enable SID filtering on the trust: `netdom trust <trusting> /domain:<trusted> /quarantine:yes` (external) or `/enablesidhistory:no` (forest).",
        ),
        "AbuseTGTDelegation" => h(
            "The target domain trusts the source domain across a forest with TGT delegation enabled, so its principals forward TGTs to unconstrained delegation hosts in the source domain.",
            "From the source domain, coerce a DC of the target domain to authenticate to an unconstrained delegation host (every DC qualifies) and capture its TGT.",
            "Disable TGT delegation on the trust: `netdom trust <trusting> /domain:<trusted> /EnableTGTDelegation:no`.",
        ),
        "HasTrustKeys" => h(
            "The source domain trusts the domain of the target user, which is the trust account the trusted domain keeps for that trust (named after the source domain's NetBIOS name, e.g. CORP$). The trusting domain stores the same key (the trust key) in its trusted domain object.",
            "With administrative access to a DC of the source domain, dump the trust key (mimikatz lsadump::trust /patch, the [ Out ] key) and request a TGT as the trust account in the target domain with its RC4 key. This gives an authenticated foothold in the trusted domain (Kerberos network logons only).",
            "Treat every domain that trusts another as able to authenticate into it; protect DCs of trusting domains as Tier Zero, rotate trust keys after compromise (netdom trust /resetOneSide) and alert on logons by trust accounts (event 4768 / 4624).",
        ),
        "SyncedToEntraUser" => h(
            "The AD user is synchronised by Entra Connect to the target Entra ID user (matched by onPremisesSecurityIdentifier or onPremisesImmutableId).",
            "With password hash sync or pass-through authentication the on-premises password is the cloud password: control of the AD user is control of the Entra user.",
            "Keep privileged Entra roles on cloud-only accounts; protect synced accounts with MFA and Conditional Access.",
        ),
        "SyncedToADUser" => h(
            "The Entra ID user is the synchronised copy of the target AD user.",
            "With password writeback enabled, a cloud password reset changes the on-premises password.",
            "Disable password writeback for privileged accounts and keep privileged AD accounts out of sync scope.",
        ),
        "SyncedToEntraGroup" => h(
            "The AD group is synchronised to the target Entra ID group. Its members are members of the cloud group.",
            "Add a principal to the AD group (AddMember, GenericAll, ...) and it inherits the cloud group's roles and resource access after the next sync cycle.",
            "Do not grant Entra roles or privileged Azure RBAC to synced groups; use cloud-only role-assignable groups.",
        ),
        "SyncedToADGroup" => h(
            "The Entra ID group is the synchronised copy of the target AD group. Membership is mastered on-premises, so this is informational and not traversable.",
            "None by itself.",
            "Informational.",
        ),
        "SeamlessSSO" => h(
            "The AZUREADSSOACC computer account holds the Kerberos key Entra ID uses for Seamless SSO. The edge points to every synced Entra user of the account's AD domain.",
            "With the account's NT hash or AES key (DCSync, or control of the object), forge a Kerberos service ticket for any synced user and exchange it at Entra ID for a sign-in as that user.",
            "Treat AZUREADSSOACC as Tier Zero, roll its Kerberos decryption key regularly (Update-AzureADSSOForest), and disable Seamless SSO where it is not required.",
        ),
        "EntraConnectCredentials" => h(
            "The source computer runs Entra Connect (AAD Connect) and stores the credentials of the target sync account: MSOL_* in AD (replication rights) or Sync_* in Entra ID (Directory Synchronization Accounts).",
            "As local administrator of the server, decrypt the ADSync configuration (e.g. AADInternals Get-AADIntSyncCredentials) to obtain both accounts' passwords.",
            "Treat the Entra Connect server as Tier Zero: restrict local administrators, keep it on a Tier Zero network segment, and monitor the ADSync database.",
        ),
        "AZScopedTo" => h(
            "The source is a scoped role node (a directory role assigned at an administrative unit, application or single-object scope) and the target is its scope. Informational and not traversable: the rights the scope allows are separate edges from the scoped role node; administrative units appear as untyped nodes because their membership is not collected.",
            "None by itself. Holders of the scoped role (AZHasRole to the source) act on the scope's objects; for an administrative unit, on its members (not modelled).",
            "Review scoped assignments like tenant-wide ones; keep privileged users out of administrative units managed by lower-tier administrators, or use restricted management administrative units.",
        ),
        "CanProgram" => h(
            "The source can change the logic, configuration or firmware of the target controller (PLC, RTU, safety controller, drive): typically an engineering workstation running the vendor's programming software, or an account with programming rights in it. Not collected from AD; supplied as OpenGraph from an OT asset inventory (docs/OT.md).",
            "Control of the source (local admin or a logon on the engineering workstation, or the programming account) lets an attacker download modified logic or firmware to the controller, change setpoints or stop the process (MITRE ATT&CK for ICS: Modify Controller Tasking, Program Download).",
            "Limit which workstations and accounts can program each controller; keep engineering workstations out of IT administration (no IT admin groups as local admins, no IT admin logons), require the controller's key switch or password for downloads, and monitor program changes.",
        ),
        _ => None,
    }
}

/// Generators for the files derived from [`edge_help`]. The test
/// `help_artifacts_in_sync` checks them; run it with `CH_BLESS=1` to rewrite.
#[cfg(test)]
mod generated {
    use super::edge_help;
    use crate::{edge_category, BUILTIN_EDGE_KINDS};
    use std::fmt::Write;
    use std::path::PathBuf;

    pub const CATEGORIES: &[&str] = &["Active Directory", "ADCS", "Azure", "Hybrid", "OT"];
    pub const MD_BEGIN: &str = "<!-- BEGIN GENERATED edge reference: edit crates/model/src/help.rs, then run `CH_BLESS=1 cargo test -p ch-model` -->";
    pub const MD_END: &str = "<!-- END GENERATED edge reference -->";

    fn cell(s: &str) -> String {
        s.replace('|', r"\|")
    }

    /// Reference tables for docs/EDGES.md, one per category.
    pub fn markdown() -> String {
        let mut out = String::new();
        for cat in CATEGORIES {
            let _ = write!(out, "\n### {cat}\n\n| Edge | Traversable | Meaning | Abuse | Remediation |\n|---|---|---|---|---|\n");
            for (name, trav) in BUILTIN_EDGE_KINDS.iter().filter(|(n, _)| edge_category(n) == *cat) {
                let h = edge_help(name).expect("covered by every_builtin_kind_has_help");
                let _ = writeln!(
                    out,
                    "| `{name}` | {} | {} | {} | {} |",
                    if *trav { "yes" } else { "**no**" },
                    cell(h.description),
                    cell(h.abuse),
                    cell(h.remediation)
                );
            }
        }
        out
    }

    fn ts_str(s: &str) -> String {
        let mut o = String::from('"');
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str(r"\\"),
                _ => o.push(c),
            }
        }
        o.push('"');
        o
    }

    /// web/src/mock/edgeHelp.ts
    pub fn typescript() -> String {
        let mut out = String::from(
            "// Help text for every built-in edge kind, as served by GET /edge-kinds.\n\
             // GENERATED from ch_model::edge_help (crates/model/src/help.rs); do not edit.\n\
             // Regenerate with `CH_BLESS=1 cargo test -p ch-model`.\n\n\
             import type { EdgeHelp } from \"../api/types\";\n\n\
             export const EDGE_HELP: Record<string, EdgeHelp> = {\n",
        );
        for (name, _) in BUILTIN_EDGE_KINDS {
            let h = edge_help(name).expect("covered by every_builtin_kind_has_help");
            let _ = write!(
                out,
                "  {name}: {{\n    description: {},\n    abuse: {},\n    remediation: {},\n  }},\n",
                ts_str(h.description),
                ts_str(h.abuse),
                ts_str(h.remediation)
            );
        }
        out.push_str("};\n");
        out
    }

    pub fn repo_file(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
    }
}

#[cfg(test)]
mod tests {
    use super::generated::*;
    use crate::BUILTIN_EDGE_KINDS;

    fn read(rel: &str) -> String {
        std::fs::read_to_string(repo_file(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")).replace("\r\n", "\n")
    }

    /// docs/EDGES.md's reference section and the web mock are generated from
    /// `edge_help`. `CH_BLESS=1` rewrites them instead of failing.
    #[test]
    fn help_artifacts_in_sync() {
        let bless = std::env::var_os("CH_BLESS").is_some();

        let md = read("docs/EDGES.md");
        let (Some(a), Some(b)) = (md.find(MD_BEGIN), md.find(MD_END)) else {
            panic!("docs/EDGES.md lacks the generated-section markers");
        };
        let want = format!("{}{MD_BEGIN}\n{}\n{}", &md[..a], markdown(), &md[b..]);
        if bless {
            std::fs::write(repo_file("docs/EDGES.md"), &want).unwrap();
        } else {
            assert!(md == want, "docs/EDGES.md edge reference is stale: run `CH_BLESS=1 cargo test -p ch-model`");
        }

        let ts = typescript();
        if bless {
            std::fs::write(repo_file("web/src/mock/edgeHelp.ts"), &ts).unwrap();
        } else {
            assert!(read("web/src/mock/edgeHelp.ts") == ts, "web/src/mock/edgeHelp.ts is stale: run `CH_BLESS=1 cargo test -p ch-model`");
        }
    }

    #[test]
    fn edges_md_mentions_every_kind() {
        if std::env::var_os("CH_BLESS").is_some() {
            return; // help_artifacts_in_sync may be rewriting the file concurrently
        }
        let md = read("docs/EDGES.md");
        for (k, _) in BUILTIN_EDGE_KINDS {
            assert!(md.contains(&format!("`{k}`")), "docs/EDGES.md does not mention `{k}`");
        }
    }

    #[test]
    fn every_kind_has_a_category_table() {
        for (k, _) in BUILTIN_EDGE_KINDS {
            assert!(CATEGORIES.contains(&crate::edge_category(k)), "{k}");
        }
    }
}
