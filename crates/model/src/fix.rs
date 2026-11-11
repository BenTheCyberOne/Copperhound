//! Suggested remediation commands for a single attack edge.
//!
//! Each command is a PowerShell snippet that removes the specific
//! relationship the edge stands for (a group membership, an ACE, a delegation
//! entry, a role assignment) between the two objects, identified by object id
//! (SID, GUID, Entra object id or Azure resource id) so names that changed
//! since collection do not matter. They are suggestions for the person fixing
//! the issue: review them, and expect to adapt them when the right comes from
//! a GPO, an inherited ACE or a higher Azure scope. Edges with no single
//! scripted fix (derived edges, structural ones, CA-side permissions) return
//! `None`; their [`crate::edge_help`] remediation text still applies.
//!
//! Requirements: the ActiveDirectory module (RSAT) for AD, Microsoft.Graph
//! for Entra ID, Az.Resources for Azure RBAC.

/// One end of an edge.
#[derive(Debug, Clone, Copy)]
pub struct FixEnd<'a> {
    pub oid: &'a str,
    pub name: &'a str,
    /// Node kind label (`User`, `Computer`, `AZApp`, …).
    pub kind: &'a str,
}

/// PowerShell single-quoted string literal.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The SID in a node object id: `S-1-…`, or a domain-prefixed well-known SID
/// (`CORP.LOCAL-S-1-5-32-544`).
fn sid(oid: &str) -> Option<&str> {
    let s = oid.trim();
    let s = if s.len() > 4 && s.is_char_boundary(4) && s[..4].eq_ignore_ascii_case("S-1-") {
        s
    } else {
        let i = s.to_ascii_uppercase().find("-S-1-")?;
        &s[i + 1..]
    };
    // Only digits and dashes after the prefix: object ids are collected data.
    s[4..].bytes().all(|c| c.is_ascii_digit() || c == b'-').then_some(s)
}

fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// PowerShell expression yielding the AD object of `oid`.
fn ad_object(oid: &str) -> Option<String> {
    if let Some(s) = sid(oid) {
        Some(format!("Get-ADObject -Filter \"objectSid -eq '{}'\"", s.replace('\'', "")))
    } else if is_guid(oid) {
        Some(format!("Get-ADObject -Identity {}", q(oid)))
    } else {
        None
    }
}

/// DNS host name of a computer node (`WS01.CORP.LOCAL`).
fn host(c: &FixEnd) -> String {
    c.name.to_string()
}

const HEADER_AD: &str = "Import-Module ActiveDirectory";

/// Remove explicit Allow ACEs that grant `src` the edge's right on `dst`.
/// `rights` is an ActiveDirectoryRights name; `exact` requires all its bits
/// (GenericAll), otherwise any overlap counts. `types`: ObjectType GUIDs the
/// ACE must apply to (the all-zero GUID — every property / right — always
/// counts); empty means any.
fn ace_removal(src: &FixEnd, dst: &FixEnd, what: &str, rights: &str, exact: bool, types: &[&str]) -> Option<String> {
    let s = sid(src.oid)?;
    let obj = ad_object(dst.oid)?;
    let rights_test = if exact {
        "(($_.ActiveDirectoryRights -band $r) -eq $r)".to_string()
    } else {
        "($_.ActiveDirectoryRights -band $r)".to_string()
    };
    let type_test = if types.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = std::iter::once("00000000-0000-0000-0000-000000000000").chain(types.iter().copied()).map(q).collect();
        format!(" -and (@({}) -contains $_.ObjectType.ToString())", list.join(", "))
    };
    Some(format!(
        "{HEADER_AD}
# Remove {what} granted to {src_name} on {dst_name}
$target = {obj}
$path = \"AD:$($target.DistinguishedName)\"
$acl = Get-Acl -Path $path
$r = [System.DirectoryServices.ActiveDirectoryRights]{rights}
function Get-AceSid($ref) {{ try {{ $ref.Translate([System.Security.Principal.SecurityIdentifier]).Value }} catch {{ $ref.Value }} }}
$aces = @($acl.Access | Where-Object {{ $_.AccessControlType -eq 'Allow' -and -not $_.IsInherited -and (Get-AceSid $_.IdentityReference) -eq {sid} -and {rights_test}{type_test} }})
$aces | ForEach-Object {{ [void]$acl.RemoveAccessRule($_) }}
Set-Acl -Path $path -AclObject $acl
\"Removed $($aces.Count) ACE(s)\"
# Nothing removed? The right may be inherited (fix it on the parent container) or come from a group.",
        src_name = src.name,
        dst_name = dst.name,
        rights = q(rights),
        sid = q(s),
    ))
}

fn local_group(src: &FixEnd, dst: &FixEnd, group_sid: &str, group: &str) -> Option<String> {
    let s = sid(src.oid)?;
    Some(format!(
        "# Remove {src_name} from {group} on {host}
Invoke-Command -ComputerName {h} -ScriptBlock {{ Remove-LocalGroupMember -SID {g} -Member {m} }}
# If a GPO (Restricted Groups / Group Policy Preferences) adds it, fix the GPO or it returns.",
        src_name = src.name,
        host = host(dst),
        h = q(&host(dst)),
        g = q(group_sid),
        m = q(s),
    ))
}

fn azure_rbac(src: &FixEnd, dst: &FixEnd, role: &str) -> Option<String> {
    if !dst.oid.starts_with('/') {
        return None;
    }
    Some(format!(
        "Import-Module Az.Resources
# Remove the {role} assignment of {src_name} on {dst_name}
Remove-AzRoleAssignment -ObjectId {o} -Scope {s} -RoleDefinitionName {r}
# Fails if the assignment is inherited: remove it at the parent scope (Get-AzRoleAssignment -ObjectId {o} shows where).",
        src_name = src.name,
        dst_name = dst.name,
        o = q(&src.oid.to_ascii_lowercase()),
        s = q(dst.oid),
        r = q(role),
    ))
}

fn graph_app_role(src: &FixEnd, dst: &FixEnd, permission: &str, app_role_id: &str) -> Option<String> {
    if !is_guid(src.oid) {
        return None;
    }
    Some(format!(
        "Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All'
# Remove the Microsoft Graph application permission {permission} from {src_name} (it reaches {dst_name} through it)
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId {sp} -All | Where-Object {{ $_.AppRoleId -eq {role} }} | ForEach-Object {{
  Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId {sp} -AppRoleAssignmentId $_.Id
}}",
        src_name = src.name,
        dst_name = dst.name,
        sp = q(&src.oid.to_ascii_lowercase()),
        role = q(app_role_id),
    ))
}

const MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
const SPN: &str = "f3a64788-5306-11d1-a9c5-0000f8031498";
const KEY_CREDENTIAL_LINK: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
const ALLOWED_TO_ACT: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
const ACCOUNT_RESTRICTIONS: &str = "4c164200-20c0-11d0-a768-00aa006e0529";
const GP_LINK: &str = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
const FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
const GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
const GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
const GET_CHANGES_FILTERED: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
const CERT_ENROLL: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";

/// Suggested PowerShell that removes the edge `src -[kind]-> dst`, or `None`
/// when there is no single scripted fix.
pub fn fix_command(kind: &str, src: FixEnd, dst: FixEnd) -> Option<String> {
    // Names come from collected data and end up in comments and quoted
    // strings: keep them on one line.
    let clean = |n: &str| n.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>();
    let (sn, dn) = (clean(src.name), clean(dst.name));
    let (src, dst) = (FixEnd { name: &sn, ..src }, FixEnd { name: &dn, ..dst });
    let (src, dst) = (&src, &dst);
    match kind {
        "MemberOf" if dst.kind == "Group" => {
            let (s, d) = (sid(src.oid)?, sid(dst.oid)?);
            Some(format!(
                "{HEADER_AD}
# Remove {} from {}
Remove-ADGroupMember -Identity {} -Members {} -Confirm:$false
# A primary group membership cannot be removed this way: change the member's primaryGroupID first.",
                src.name,
                dst.name,
                q(d),
                q(s)
            ))
        }
        "AdminTo" => local_group(src, dst, "S-1-5-32-544", "the local Administrators group"),
        "CanRDP" => local_group(src, dst, "S-1-5-32-555", "Remote Desktop Users"),
        "CanPSRemote" => local_group(src, dst, "S-1-5-32-580", "Remote Management Users"),
        "ExecuteDCOM" => local_group(src, dst, "S-1-5-32-562", "Distributed COM Users"),
        "HasSession" => Some(format!(
            "# {} has a session on {}: list sessions, then sign it out
query user /server:{}
# logoff <SESSIONID> /server:{}
# Then keep the account off this tier: logon restrictions, Protected Users, Authentication Policy Silos.",
            dst.name,
            src.name,
            q(&host(src)),
            q(&host(src))
        )),
        "AllowedToDelegate" => {
            let obj = ad_object(src.oid)?;
            let short = dst.name.split('.').next().unwrap_or(dst.name);
            Some(format!(
                "{HEADER_AD}
# Remove constrained delegation from {} to services on {}
$o = {obj} -Properties 'msDS-AllowedToDelegateTo'
$spns = @($o.'msDS-AllowedToDelegateTo' | Where-Object {{ $_ -match ('/' + [regex]::Escape({}) + '([.:/]|$)') }})
$spns
if ($spns.Count) {{ Set-ADObject -Identity $o.DistinguishedName -Remove @{{'msDS-AllowedToDelegateTo' = [string[]]$spns}} }}",
                src.name,
                dst.name,
                q(short)
            ))
        }
        "AllowedToAct" => {
            let (s, d) = (sid(src.oid)?, sid(dst.oid)?);
            Some(format!(
                "{HEADER_AD}
# Remove {} from resource-based constrained delegation on {}
$c = Get-ADComputer -Identity {} -Properties PrincipalsAllowedToDelegateToAccount
$keep = @($c.PrincipalsAllowedToDelegateToAccount | Where-Object {{ (Get-ADObject -Identity $_ -Properties objectSid).objectSid.Value -ne {} }})
if ($keep.Count) {{ Set-ADComputer -Identity $c -PrincipalsAllowedToDelegateToAccount $keep }} else {{ Set-ADComputer -Identity $c -PrincipalsAllowedToDelegateToAccount $null }}",
                src.name,
                dst.name,
                q(d),
                q(s)
            ))
        }
        "HasSIDHistory" => {
            let obj = ad_object(src.oid)?;
            let d = sid(dst.oid)?;
            Some(format!(
                "{HEADER_AD}
# Remove the SID history entry of {} from {}
$o = {obj}
Set-ADObject -Identity $o.DistinguishedName -Remove @{{sIDHistory = {}}}",
                dst.name,
                src.name,
                q(d)
            ))
        }
        "ReadGMSAPassword" => {
            let (s, d) = (sid(src.oid)?, sid(dst.oid)?);
            Some(format!(
                "{HEADER_AD}
# Stop {} from retrieving the managed password of {}
$sa = Get-ADServiceAccount -Identity {} -Properties PrincipalsAllowedToRetrieveManagedPassword
$keep = @($sa.PrincipalsAllowedToRetrieveManagedPassword | Where-Object {{ (Get-ADObject -Identity $_ -Properties objectSid).objectSid.Value -ne {} }})
$keep  # the hosts that keep using this gMSA must stay in the list
Set-ADServiceAccount -Identity $sa -PrincipalsAllowedToRetrieveManagedPassword $keep",
                src.name,
                dst.name,
                q(d),
                q(s)
            ))
        }
        "GPLink" => {
            let gpo = ad_object(src.oid)?;
            let target = ad_object(dst.oid)?;
            Some(format!(
                "Import-Module GroupPolicy, ActiveDirectory
# Unlink GPO {} from {}
$gpo = {gpo} -Properties cn
$target = {target}
Remove-GPLink -Guid $gpo.cn.Trim('{{}}') -Target $target.DistinguishedName",
                src.name, dst.name
            ))
        }
        "Owns" => {
            let obj = ad_object(dst.oid)?;
            Some(format!(
                "{HEADER_AD}
# {} owns {}: hand ownership to Domain Admins
$target = {obj}
$path = \"AD:$($target.DistinguishedName)\"
$acl = Get-Acl -Path $path
$acl.SetOwner([System.Security.Principal.SecurityIdentifier]((Get-ADDomain).DomainSID.Value + '-512'))
Set-Acl -Path $path -AclObject $acl",
                src.name, dst.name
            ))
        }
        "GenericAll" => ace_removal(src, dst, "full control (GenericAll)", "GenericAll", true, &[]),
        "GenericWrite" => ace_removal(src, dst, "write access to all properties (GenericWrite)", "WriteProperty", false, &["00000000-0000-0000-0000-000000000000"]),
        "WriteDacl" => ace_removal(src, dst, "WriteDacl", "WriteDacl", false, &[]),
        "WriteOwner" => ace_removal(src, dst, "WriteOwner", "WriteOwner", false, &[]),
        "AllExtendedRights" => ace_removal(src, dst, "all extended rights", "ExtendedRight", false, &["00000000-0000-0000-0000-000000000000"]),
        "ForceChangePassword" => ace_removal(src, dst, "the Reset Password right", "ExtendedRight", false, &[FORCE_CHANGE_PASSWORD]),
        "AddMember" => ace_removal(src, dst, "write access to group membership", "WriteProperty", false, &[MEMBER]),
        "AddSelf" => ace_removal(src, dst, "the right to add itself to the group", "Self", false, &[MEMBER]),
        "WriteSPN" => ace_removal(src, dst, "write access to servicePrincipalName", "WriteProperty", false, &[SPN]),
        "AddKeyCredentialLink" => ace_removal(src, dst, "write access to msDS-KeyCredentialLink", "WriteProperty", false, &[KEY_CREDENTIAL_LINK]),
        "AddAllowedToAct" => ace_removal(src, dst, "write access to msDS-AllowedToActOnBehalfOfOtherIdentity", "WriteProperty", false, &[ALLOWED_TO_ACT]),
        "WriteAccountRestrictions" => ace_removal(src, dst, "write access to account restrictions", "WriteProperty", false, &[ACCOUNT_RESTRICTIONS]),
        "WriteGPLink" => ace_removal(src, dst, "write access to gPLink", "WriteProperty", false, &[GP_LINK]),
        "GetChanges" => ace_removal(src, dst, "Replicating Directory Changes", "ExtendedRight", false, &[GET_CHANGES]),
        "GetChangesAll" => ace_removal(src, dst, "Replicating Directory Changes All", "ExtendedRight", false, &[GET_CHANGES_ALL]),
        "GetChangesInFilteredSet" => ace_removal(src, dst, "Replicating Directory Changes In Filtered Set", "ExtendedRight", false, &[GET_CHANGES_FILTERED]),
        "DCSync" => ace_removal(src, dst, "directory replication rights (DCSync)", "ExtendedRight", false, &[GET_CHANGES, GET_CHANGES_ALL]),
        "Enroll" if dst.kind == "CertTemplate" => ace_removal(src, dst, "the Enroll right", "ExtendedRight", false, &[CERT_ENROLL]),

        // ---------------------------------------------------------- Entra ID
        "AZMemberOf" if is_guid(dst.oid) && is_guid(src.oid) => Some(format!(
            "Connect-MgGraph -Scopes 'GroupMember.ReadWrite.All'
# Remove {} from group {}
Remove-MgGroupMemberByRef -GroupId {} -DirectoryObjectId {}
# Dynamic groups: change the membership rule instead. Role-assignable groups need RoleManagement.ReadWrite.Directory.",
            src.name,
            dst.name,
            q(&dst.oid.to_ascii_lowercase()),
            q(&src.oid.to_ascii_lowercase())
        )),
        "AZHasRole" | "AZRoleEligible" => {
            if !is_guid(src.oid) {
                return None;
            }
            let role = dst.oid.split('@').next().unwrap_or(dst.oid).to_ascii_lowercase();
            if !is_guid(&role) {
                return None;
            }
            let (p, r) = (q(&src.oid.to_ascii_lowercase()), q(&role));
            Some(if kind == "AZHasRole" {
                format!(
                    "Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory'
# Remove the {} role from {}
Get-MgRoleManagementDirectoryRoleAssignment -Filter \"principalId eq {p} and roleDefinitionId eq {r}\" -All | ForEach-Object {{
  Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $_.Id
}}
# Active PIM assignments are removed with New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -Action adminRemove.",
                    dst.name, src.name
                )
            } else {
                format!(
                    "Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory'
# Remove the PIM eligibility of {} for {}
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter \"principalId eq {p} and roleDefinitionId eq {r}\" -All | ForEach-Object {{
  New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter @{{ action = 'adminRemove'; principalId = $_.PrincipalId; roleDefinitionId = $_.RoleDefinitionId; directoryScopeId = $_.DirectoryScopeId }}
}}",
                    src.name, dst.name
                )
            })
        }
        "AZOwns" if is_guid(src.oid) && is_guid(dst.oid) => {
            let (o, t) = (q(&src.oid.to_ascii_lowercase()), q(&dst.oid.to_ascii_lowercase()));
            let body = match dst.kind {
                "AZApp" => format!("$app = Get-MgApplication -Filter \"appId eq {t}\"\nRemove-MgApplicationOwnerByRef -ApplicationId $app.Id -DirectoryObjectId {o}"),
                "AZServicePrincipal" => format!("Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId {t} -DirectoryObjectId {o}"),
                "AZGroup" => format!("Remove-MgGroupOwnerByRef -GroupId {t} -DirectoryObjectId {o}"),
                _ => return None,
            };
            Some(format!("Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Group.ReadWrite.All'\n# Remove {} as an owner of {}\n{body}", src.name, dst.name))
        }
        "AZMGGrantRole" => graph_app_role(src, dst, "RoleManagement.ReadWrite.Directory", "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"),
        "AZMGGrantAppRoles" => graph_app_role(src, dst, "AppRoleAssignment.ReadWrite.All", "06b708a9-e830-4db3-a914-8e69da51d44f"),

        // ------------------------------------------------------- Azure RBAC
        "AZOwner" => azure_rbac(src, dst, "Owner"),
        "AZContributor" => azure_rbac(src, dst, "Contributor"),
        "AZUserAccessAdministrator" => azure_rbac(src, dst, "User Access Administrator"),
        "AZKeyVaultContributor" => azure_rbac(src, dst, "Key Vault Contributor"),
        "AZVMContributor" => azure_rbac(src, dst, "Virtual Machine Contributor"),
        "AZVMAdminLogin" => azure_rbac(src, dst, "Virtual Machine Administrator Login"),
        "AZAvereContributor" => azure_rbac(src, dst, "Avere Contributor"),
        "AZWebsiteContributor" => azure_rbac(src, dst, "Website Contributor"),
        "AZLogicAppContributor" => azure_rbac(src, dst, "Logic App Contributor"),
        "AZAutomationContributor" => azure_rbac(src, dst, "Automation Contributor"),
        "AZAKSContributor" => azure_rbac(src, dst, "Azure Kubernetes Service Contributor Role"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn end<'a>(oid: &'a str, name: &'a str, kind: &'a str) -> FixEnd<'a> {
        FixEnd { oid, name, kind }
    }

    #[test]
    fn sids_and_guids() {
        assert_eq!(sid("S-1-5-21-1-2-3-1105"), Some("S-1-5-21-1-2-3-1105"));
        assert_eq!(sid("CORP.LOCAL-S-1-5-32-544"), Some("S-1-5-32-544"));
        assert_eq!(sid("2b3c0e5e-0000-0000-0000-000000000001"), None);
        assert!(is_guid("2B3C0E5E-0000-0000-0000-000000000001"));
        assert!(!is_guid("/subscriptions/x"));
        assert_eq!(q("O'Brien"), "'O''Brien'");
        assert_eq!(sid("S-1-5-21-1'; rm -rf"), None, "only digits and dashes");
        let evil = end("S-1-5-21-1-2-3-1105", "X\nRemove-Item C:\\ -Recurse", "User");
        let c = fix_command("MemberOf", evil, end("S-1-5-21-1-2-3-512", "G", "Group")).unwrap();
        assert!(c.lines().all(|l| !l.starts_with("Remove-Item")), "{c}");
    }

    #[test]
    fn ad_commands_name_both_objects() {
        let u = end("S-1-5-21-1-2-3-1105", "BOB@CORP.LOCAL", "User");
        let g = end("S-1-5-21-1-2-3-512", "DOMAIN ADMINS@CORP.LOCAL", "Group");
        let c = end("S-1-5-21-1-2-3-1201", "WS01.CORP.LOCAL", "Computer");
        let m = fix_command("MemberOf", u, g).unwrap();
        assert!(m.contains("Remove-ADGroupMember -Identity 'S-1-5-21-1-2-3-512' -Members 'S-1-5-21-1-2-3-1105'"), "{m}");
        let a = fix_command("AdminTo", u, c).unwrap();
        assert!(a.contains("-ComputerName 'WS01.CORP.LOCAL'") && a.contains("-SID 'S-1-5-32-544' -Member 'S-1-5-21-1-2-3-1105'"), "{a}");
        let ga = fix_command("GenericAll", u, g).unwrap();
        assert!(ga.contains("objectSid -eq 'S-1-5-21-1-2-3-512'") && ga.contains("-eq 'S-1-5-21-1-2-3-1105'") && ga.contains("-eq $r)"), "{ga}");
        let am = fix_command("AddMember", u, g).unwrap();
        assert!(am.contains(MEMBER) && am.contains("'WriteProperty'"), "{am}");
        let ou = end("6A1B2C3D-0000-0000-0000-00000000000A", "SERVERS@CORP.LOCAL", "OU");
        assert!(fix_command("WriteDacl", u, ou).unwrap().contains("Get-ADObject -Identity '6A1B2C3D-0000-0000-0000-00000000000A'"));
        let s = fix_command("HasSession", c, u).unwrap();
        assert!(s.contains("query user /server:'WS01.CORP.LOCAL'"), "{s}");
        // Structural / derived edges have no single command.
        assert!(fix_command("Contains", ou, u).is_none());
        assert!(fix_command("ADCSESC1", u, g).is_none());
        // A member of an Entra group is not an AD membership.
        assert!(fix_command("MemberOf", u, end("x", "y", "AZGroup")).is_none());
    }

    #[test]
    fn azure_commands() {
        let u = end("4E7F0000-0000-0000-0000-000000000001", "ALICE@CONTOSO", "AZUser");
        let r = end("62E90394-69F5-4237-9190-012177145E10@6C12B0B0-0000-0000-0000-000000000000", "GLOBAL ADMINISTRATOR@CONTOSO", "AZRole");
        let h = fix_command("AZHasRole", u, r).unwrap();
        assert!(h.contains("principalId eq '4e7f0000-0000-0000-0000-000000000001' and roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'"), "{h}");
        let sub = end("/SUBSCRIPTIONS/0B1F0000-0000-0000-0000-000000000000", "PROD", "AZSubscription");
        let o = fix_command("AZOwner", u, sub).unwrap();
        assert!(o.contains("-Scope '/SUBSCRIPTIONS/0B1F0000-0000-0000-0000-000000000000' -RoleDefinitionName 'Owner'"), "{o}");
        let app = end("1A2B0000-0000-0000-0000-000000000000", "APP", "AZApp");
        assert!(fix_command("AZOwns", u, app).unwrap().contains("appId eq '1a2b0000-0000-0000-0000-000000000000'"));
        assert!(fix_command("AZOwns", u, end("1A2B0000-0000-0000-0000-000000000000", "VM", "AZVM")).is_none());
    }

    const SCRIPTED: &[&str] = &[
        "MemberOf", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession", "AllowedToDelegate", "AllowedToAct", "HasSIDHistory", "ReadGMSAPassword", "GPLink", "Owns",
        "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf", "WriteSPN", "AddKeyCredentialLink",
        "AddAllowedToAct", "WriteAccountRestrictions", "WriteGPLink", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync", "Enroll", "AZMemberOf", "AZHasRole",
        "AZRoleEligible", "AZOwns", "AZMGGrantRole", "AZMGGrantAppRoles", "AZOwner", "AZContributor", "AZUserAccessAdministrator", "AZKeyVaultContributor", "AZVMContributor",
        "AZVMAdminLogin", "AZAvereContributor", "AZWebsiteContributor", "AZLogicAppContributor", "AZAutomationContributor", "AZAKSContributor",
    ];

    /// Sample ends that make every scripted kind produce a command.
    fn sample(kind: &str) -> (FixEnd<'static>, FixEnd<'static>) {
        let user = end("S-1-5-21-1-2-3-1105", "O'BRIEN@CORP.LOCAL", "User");
        let comp = end("S-1-5-21-1-2-3-1201", "WS01.CORP.LOCAL", "Computer");
        let az = end("4E7F0000-0000-0000-0000-000000000001", "ALICE@CONTOSO", "AZUser");
        match kind {
            "MemberOf" | "AddMember" | "AddSelf" | "GenericAll" | "GenericWrite" | "WriteDacl" | "WriteOwner" | "Owns" | "AllExtendedRights" | "ForceChangePassword" | "WriteSPN"
            | "AddKeyCredentialLink" | "WriteAccountRestrictions" | "HasSIDHistory" => (user, end("S-1-5-21-1-2-3-512", "DOMAIN ADMINS@CORP.LOCAL", "Group")),
            "HasSession" => (comp, user),
            "GPLink" => (end("31B2F340-016D-11D2-945F-00C04FB984F9", "DEFAULT DOMAIN POLICY@CORP.LOCAL", "GPO"), end("6A1B2C3D-0000-0000-0000-00000000000A", "SERVERS@CORP.LOCAL", "OU")),
            "GetChanges" | "GetChangesAll" | "GetChangesInFilteredSet" | "DCSync" | "WriteGPLink" => (user, end("S-1-5-21-1-2-3", "CORP.LOCAL", "Domain")),
            "ReadGMSAPassword" => (comp, end("S-1-5-21-1-2-3-1300", "GMSA_SQL$@CORP.LOCAL", "User")),
            "Enroll" => (user, end("6A1B2C3D-0000-0000-0000-00000000000B", "USERTEMPLATE@CORP.LOCAL", "CertTemplate")),
            "AZMemberOf" => (az, end("5A5A0000-0000-0000-0000-000000000002", "ADMINS@CONTOSO", "AZGroup")),
            "AZHasRole" | "AZRoleEligible" => (az, end("62E90394-69F5-4237-9190-012177145E10@6C12B0B0-0000-0000-0000-000000000000", "GLOBAL ADMINISTRATOR@CONTOSO", "AZRole")),
            "AZOwns" => (az, end("1A2B0000-0000-0000-0000-000000000000", "APP@CONTOSO", "AZApp")),
            "AZMGGrantRole" | "AZMGGrantAppRoles" => (end("7C7C0000-0000-0000-0000-000000000003", "SP@CONTOSO", "AZServicePrincipal"), end("6C12B0B0-0000-0000-0000-000000000000", "CONTOSO", "AZTenant")),
            k if k.starts_with("AZ") => (az, end("/SUBSCRIPTIONS/0B1F0000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG1", "RG1", "AZResourceGroup")),
            _ => (user, comp),
        }
    }

    #[test]
    fn every_scripted_kind_produces_a_command() {
        for k in SCRIPTED {
            let (s, d) = sample(k);
            let c = fix_command(k, s, d).unwrap_or_else(|| panic!("{k}"));
            // Optional: CH_FIX_DUMP=<dir> writes each command for an external syntax check.
            if let Ok(dir) = std::env::var("CH_FIX_DUMP") {
                std::fs::write(std::path::Path::new(&dir).join(format!("{k}.ps1")), &c).unwrap();
            }
        }
    }

    #[test]
    fn every_scripted_kind_has_help() {
        for k in SCRIPTED {
            assert!(crate::edge_help(k).is_some(), "{k}");
        }
    }

}
