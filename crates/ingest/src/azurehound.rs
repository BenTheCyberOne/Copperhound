//! AzureHound output: `{"data":[{"kind":"AZUser","data":{...}}, ...],
//! "meta":{"type":"azure",...}}` with all kinds mixed in one file.
//!
//! Node ids and edges follow BloodHound CE's conversion (see
//! docs/research/azurehound.md). Ids are uppercased by the emitter, so every
//! GUID / ARM id / scope comparison is case-insensitive — this also avoids the
//! v3 casing issues noted in the research.

use crate::emit::Emitter;
use crate::merge::cat;
use ch_model::{ek_of, flags, NodeKind};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;

#[derive(Deserialize)]
pub struct Record {
    pub kind: String,
    pub data: Box<RawValue>,
}

const MS_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
const APP_ADMIN: &str = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";
const CLOUD_APP_ADMIN: &str = "158c047a-c907-4556-b7ef-446551a6b5f7";
const GLOBAL_ADMIN: &str = "62E90394-69F5-4237-9190-012177145E10";
const PRIV_ROLE_ADMIN: &str = "E8611AB8-C189-46E8-94E1-60213AB1F814";

/// Display names of built-in roles that can be assigned at a restricted scope
/// (administrative unit or object); used to name scoped role nodes, since a
/// role assignment record does not carry the role's name.
fn builtin_role_name(template: &str) -> Option<&'static str> {
    Some(match template.to_ascii_lowercase().as_str() {
        "fe930be7-5e62-47db-91af-98c3a49a38b1" => "User Administrator",
        "729827e3-9c14-49f7-bb1b-9608f156bbb8" => "Helpdesk Administrator",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f" => "Authentication Administrator",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" => "Privileged Authentication Administrator",
        "966707d0-3269-4727-9be2-8c3a10f19b9d" => "Password Administrator",
        "fdd7a751-b60b-444a-984c-02652fe8fa1c" => "Groups Administrator",
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a" => "License Administrator",
        "7698a772-787b-4ac8-901f-60d6b08affd2" => "Cloud Device Administrator",
        "3a2c62db-5318-420d-8d74-23affee5d9d5" => "Intune Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" => "Application Administrator",
        "158c047a-c907-4556-b7ef-446551a6b5f7" => "Cloud Application Administrator",
        "cf1c38e5-3621-4004-a7cb-879624dced7c" => "Application Developer",
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" => "Hybrid Identity Administrator",
        "9360feb5-f418-4baa-8175-e2a00bac4301" => "Directory Writers",
        "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" => "Identity Governance Administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de" => "Exchange Administrator",
        "31392ffb-586c-42d1-9346-e59415a2cc4e" => "Exchange Recipient Administrator",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" => "SharePoint Administrator",
        "69091246-20e8-4a56-aa4d-066075b2a7a8" => "Teams Administrator",
        "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f" => "Printer Administrator",
        _ => return None,
    })
}

/// Where a directory role assignment applies.
#[derive(Debug, PartialEq, Eq)]
enum RoleScope<'a> {
    Tenant,
    /// App registration, by appId (the AZApp node id).
    App { app_id: &'a str, name: Option<&'a str> },
    /// Administrative unit or a single directory object. `kind` is `Unknown`
    /// for administrative units (AzureHound collects no AU objects).
    Object { id: &'a str, kind: NodeKind, ty: &'static str, name: Option<&'a str> },
}

/// Scope of one `roleAssignments[]` entry. AzureHound rewrites any
/// `directoryScopeId` other than `/` to `/<directoryScope.appId>`, which turns
/// administrative-unit scopes (no appId) into `/`; the expanded
/// `directoryScope` object it also writes still identifies them.
fn role_scope<'a>(ra: &'a Value, tenant: &str) -> RoleScope<'a> {
    let dsid = gs(ra, &["directoryScopeId"]).unwrap_or("/");
    let ds = ra.get("directoryScope").filter(|v| v.is_object());
    let ds_id = ds.and_then(|d| gs(d, &["id"]));
    let ds_app = ds.and_then(|d| gs(d, &["appId"]));
    let ds_name = ds.and_then(|d| gs(d, &["displayName"]));
    let ds_type = ds.and_then(|d| gs(d, &["@odata.type"])).map(str::to_ascii_lowercase);
    if let Some(app_id) = ds_app {
        return RoleScope::App { app_id, name: ds_name };
    }
    match ds_id {
        Some(id) if !id.eq_ignore_ascii_case(tenant) && ds_type.as_deref() != Some("#microsoft.graph.organization") => {
            let (kind, ty) = match ds_type.as_deref().unwrap_or("") {
                "#microsoft.graph.administrativeunit" => (NodeKind::Unknown, "administrativeUnit"),
                "#microsoft.graph.user" => (NodeKind::AzUser, "user"),
                "#microsoft.graph.group" => (NodeKind::AzGroup, "group"),
                "#microsoft.graph.serviceprincipal" => (NodeKind::AzServicePrincipal, "servicePrincipal"),
                "#microsoft.graph.device" => (NodeKind::AzDevice, "device"),
                _ if dsid.to_ascii_lowercase().starts_with("/administrativeunits/") => (NodeKind::Unknown, "administrativeUnit"),
                // Application objects without appId, or an unknown type.
                _ => (NodeKind::Unknown, "directoryObject"),
            };
            return RoleScope::Object { id, kind, ty, name: ds_name };
        }
        _ => {}
    }
    if dsid == "/" {
        return RoleScope::Tenant;
    }
    let rest = dsid.trim_start_matches('/');
    match rest.split_once('/') {
        Some((head, id)) if head.eq_ignore_ascii_case("administrativeUnits") && !id.is_empty() => {
            RoleScope::Object { id, kind: NodeKind::Unknown, ty: "administrativeUnit", name: None }
        }
        // `/<appId>` as written by AzureHound (BloodHound reads it the same way).
        _ => RoleScope::App { app_id: rest, name: None },
    }
}

fn gs<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str().filter(|s| !s.is_empty())
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn odata_kind(obj: &Value) -> Option<NodeKind> {
    match gs(obj, &["@odata.type"])? {
        "#microsoft.graph.user" => Some(NodeKind::AzUser),
        "#microsoft.graph.group" => Some(NodeKind::AzGroup),
        "#microsoft.graph.servicePrincipal" => Some(NodeKind::AzServicePrincipal),
        "#microsoft.graph.device" => Some(NodeKind::AzDevice),
        _ => None,
    }
}

fn at(name: Option<&str>, suffix: Option<&str>) -> Option<String> {
    match (name, suffix) {
        (Some(n), Some(s)) => Some(format!("{n}@{s}")),
        (Some(n), None) => Some(n.to_string()),
        _ => None,
    }
}

/// Azure RBAC role definition GUID → edge kind.
fn rbac_edge(role_guid: &str) -> Option<&'static str> {
    Some(match role_guid.to_ascii_lowercase().as_str() {
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" => "AZOwner",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" => "AZUserAccessAdministrator",
        "b24988ac-6180-42a0-ab88-20f7382dd24c" => "AZContributor",
        "de139f84-1756-47ae-9be6-808fbbe84772" => "AZWebsiteContributor",
        "f353d9bd-d4a6-484e-a77a-8050b599b867" => "AZAutomationContributor",
        "87a39d53-fc1b-424a-814c-f7e04687dc9e" => "AZLogicAppContributor",
        "9980e02c-c2be-4d73-94e8-173b1dc7cf3c" => "AZVMContributor",
        "ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8" => "AZAKSContributor",
        _ => return None,
    })
}

/// MS Graph application permission (app role id) → ingest edge kind.
fn graph_perm_edge(app_role: &str) -> Option<&'static str> {
    Some(match app_role.to_ascii_lowercase().as_str() {
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" => "AZMGApplication_ReadWrite_All",
        "06b708a9-e830-4db3-a914-8e69da51d44f" => "AZMGAppRoleAssignment_ReadWrite_All",
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" => "AZMGDirectory_ReadWrite_All",
        "62a82d76-70ea-41e2-9197-370581804d09" => "AZMGGroup_ReadWrite_All",
        "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" => "AZMGGroupMember_ReadWrite_All",
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" => "AZMGRoleManagement_ReadWrite_Directory",
        "89c8469c-83ad-45f7-8ff2-6e3d4285709e" => "AZMGServicePrincipalEndpoint_ReadWrite_All",
        _ => return None,
    })
}

/// Resource kinds that live in a resource group and may carry managed identities.
fn resource_kind(kind: &str) -> Option<NodeKind> {
    Some(match kind {
        "AZVM" => NodeKind::AzVm,
        "AZVMScaleSet" => NodeKind::AzVmScaleSet,
        "AZWebApp" => NodeKind::AzWebApp,
        "AZFunctionApp" => NodeKind::AzFunctionApp,
        "AZLogicApp" => NodeKind::AzLogicApp,
        "AZAutomationAccount" => NodeKind::AzAutomationAccount,
        "AZContainerRegistry" => NodeKind::AzContainerRegistry,
        "AZManagedCluster" => NodeKind::AzManagedCluster,
        _ => return None,
    })
}

/// Role-filter kinds: (kind, parent id key, array key, element key, edge, target kind).
const ROLE_FILTERS: &[(&str, &str, &str, &str, &str, NodeKind)] = &[
    ("AZKeyVaultOwner", "keyVaultId", "owners", "owner", "AZOwner", NodeKind::AzKeyVault),
    ("AZKeyVaultContributor", "keyVaultId", "contributors", "contributor", "AZContributor", NodeKind::AzKeyVault),
    ("AZKeyVaultKVContributor", "keyVaultId", "kvContributors", "kvContributor", "AZKeyVaultContributor", NodeKind::AzKeyVault),
    ("AZKeyVaultUserAccessAdmin", "keyVaultId", "userAccessAdmins", "userAccessAdmin", "AZUserAccessAdministrator", NodeKind::AzKeyVault),
    ("AZManagementGroupOwner", "managementGroupId", "owners", "owner", "AZOwner", NodeKind::AzManagementGroup),
    ("AZManagementGroupContributor", "managementGroupId", "contributors", "contributor", "AZContributor", NodeKind::AzManagementGroup),
    ("AZManagementGroupUserAccessAdmin", "managementGroupId", "userAccessAdmins", "userAccessAdmin", "AZUserAccessAdministrator", NodeKind::AzManagementGroup),
    ("AZSubscriptionOwner", "subscriptionId", "owners", "owner", "AZOwner", NodeKind::AzSubscription),
    ("AZSubscriptionContributor", "subscriptionId", "contributors", "contributor", "AZContributor", NodeKind::AzSubscription),
    ("AZSubscriptionUserAccessAdmin", "subscriptionId", "userAccessAdmins", "userAccessAdmin", "AZUserAccessAdministrator", NodeKind::AzSubscription),
    ("AZResourceGroupOwner", "resourceGroupId", "owners", "owner", "AZOwner", NodeKind::AzResourceGroup),
    ("AZResourceGroupContributor", "resourceGroupId", "contributors", "contributor", "AZContributor", NodeKind::AzResourceGroup),
    ("AZResourceGroupUserAccessAdmin", "resourceGroupId", "userAccessAdmins", "userAccessAdmin", "AZUserAccessAdministrator", NodeKind::AzResourceGroup),
    ("AZVMOwner", "virtualMachineId", "owners", "owner", "AZOwner", NodeKind::AzVm),
    ("AZVMContributor", "virtualMachineId", "contributors", "contributor", "AZContributor", NodeKind::AzVm),
    ("AZVMAvereContributor", "virtualMachineId", "avereContributors", "avereContributor", "AZAvereContributor", NodeKind::AzVm),
    ("AZVMVMContributor", "virtualMachineId", "vmContributors", "vmContributor", "AZVMContributor", NodeKind::AzVm),
    ("AZVMAdminLogin", "virtualMachineId", "adminLogins", "adminLogin", "AZVMAdminLogin", NodeKind::AzVm),
    ("AZVMUserAccessAdmin", "virtualMachineId", "userAccessAdmins", "userAccessAdmin", "AZUserAccessAdministrator", NodeKind::AzVm),
];

/// Assignment at the resource itself, or (VMs) at an enclosing scope such as
/// the resource group — the latter is what BloodHound's regex intends.
fn in_scope(resource: &str, scope: &str, allow_parent: bool) -> bool {
    let (r, s) = (resource.to_ascii_uppercase(), scope.to_ascii_uppercase());
    r == s || (allow_parent && r.starts_with(&format!("{}/", s.trim_end_matches('/'))))
}

pub fn extract(rec: Record, em: &mut Emitter) {
    let d: Value = match serde_json::from_str(rec.data.get()) {
        Ok(v) => v,
        Err(e) => {
            em.error(|| format!("{}: {e}", rec.kind));
            return;
        }
    };
    let k = ek_of;
    if let Some(t) = gs(&d, &["tenantId"]) {
        em.note_domain(t);
    }
    let props = || Some(Box::<str>::from(rec.data.get()));
    let tenant_name = gs(&d, &["tenantName"]);
    let contains_from_tenant = |em: &mut Emitter, child: u32| {
        if let Some(t) = gs(&d, &["tenantId"]).and_then(|t| em.hint(t, Some(NodeKind::AzTenant))) {
            em.edge(t, child, k("AZContains"));
        }
    };
    let enabled = |key: &str| if d.get(key).and_then(Value::as_bool) == Some(true) { flags::ENABLED } else { 0 };

    match rec.kind.as_str() {
        "AZTenant" => {
            if let Some(t) = gs(&d, &["tenantId"]) {
                em.own(t, Some(NodeKind::AzTenant), gs(&d, &["displayName"]).or(gs(&d, &["defaultDomain"])), 0, props());
            }
        }
        "AZUser" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            let name = gs(&d, &["userPrincipalName"]).or(gs(&d, &["displayName"]));
            if let Some(me) = em.own(id, Some(NodeKind::AzUser), name, enabled("accountEnabled"), props()) {
                em.scope(me, cat::AZ_NODE, true);
                contains_from_tenant(em, me);
            }
        }
        "AZGroup" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            let name = at(gs(&d, &["displayName"]), tenant_name);
            if let Some(me) = em.own(id, Some(NodeKind::AzGroup), name.as_deref(), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                contains_from_tenant(em, me);
            }
        }
        "AZServicePrincipal" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            let name = at(gs(&d, &["displayName"]), tenant_name);
            let Some(me) = em.own(id, Some(NodeKind::AzServicePrincipal), name.as_deref(), enabled("accountEnabled"), props()) else {
                return;
            };
            em.scope(me, cat::AZ_NODE, true);
            contains_from_tenant(em, me);
            if let Some(app) = gs(&d, &["appId"]).and_then(|a| em.hint_named(a, NodeKind::AzApp, gs(&d, &["appDisplayName"]))) {
                em.edge(app, me, k("AZRunsAs"));
            }
        }
        "AZApp" => {
            let Some(app_id) = gs(&d, &["appId"]) else { return };
            let name = at(gs(&d, &["displayName"]), gs(&d, &["publisherDomain"]));
            if let Some(me) = em.own(app_id, Some(NodeKind::AzApp), name.as_deref(), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                contains_from_tenant(em, me);
            }
        }
        "AZDevice" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            let name = at(gs(&d, &["displayName"]), tenant_name);
            if let Some(me) = em.own(id, Some(NodeKind::AzDevice), name.as_deref(), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                contains_from_tenant(em, me);
            }
        }
        "AZRole" => {
            let (Some(id), Some(t)) = (gs(&d, &["id"]), gs(&d, &["tenantId"])) else { return };
            let name = at(gs(&d, &["displayName"]), tenant_name);
            if let Some(me) = em.own(&format!("{id}@{t}"), Some(NodeKind::AzRole), name.as_deref(), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                contains_from_tenant(em, me);
            }
        }
        "AZSubscription" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            if let Some(me) = em.own(id, Some(NodeKind::AzSubscription), gs(&d, &["displayName"]), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                contains_from_tenant(em, me);
            }
        }
        "AZManagementGroup" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            let name = at(gs(&d, &["properties", "displayName"]), tenant_name);
            if let Some(me) = em.own(id, Some(NodeKind::AzManagementGroup), name.as_deref(), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                if let Some(t) = gs(&d, &["properties", "tenantId"]).or(gs(&d, &["tenantId"])).and_then(|t| em.hint(t, Some(NodeKind::AzTenant))) {
                    em.edge(t, me, k("AZContains"));
                }
            }
        }
        "AZManagementGroupDescendant" => {
            let (Some(id), Some(parent)) = (gs(&d, &["id"]), gs(&d, &["properties", "parent", "id"])) else { return };
            let child_kind = if gs(&d, &["type"]).is_some_and(|t| t.to_ascii_lowercase().ends_with("/subscriptions")) {
                NodeKind::AzSubscription
            } else {
                NodeKind::AzManagementGroup
            };
            if let (Some(p), Some(c)) = (em.hint(parent, Some(NodeKind::AzManagementGroup)), em.hint(id, Some(child_kind))) {
                // A child has one parent: the record owns the child's parent link.
                em.scope(c, cat::AZ_PARENT, true);
                em.edge(p, c, k("AZContains"));
            }
        }
        "AZResourceGroup" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            if let Some(me) = em.own(id, Some(NodeKind::AzResourceGroup), gs(&d, &["name"]), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                if let Some(s) = gs(&d, &["subscriptionId"]).and_then(|s| em.hint(&sub_id(s), Some(NodeKind::AzSubscription))) {
                    em.edge(s, me, k("AZContains"));
                }
            }
        }
        "AZKeyVault" => {
            let Some(id) = gs(&d, &["id"]) else { return };
            if let Some(me) = em.own(id, Some(NodeKind::AzKeyVault), gs(&d, &["name"]), 0, props()) {
                em.scope(me, cat::AZ_NODE, true);
                if let Some(rg) = gs(&d, &["resourceGroup"]).and_then(|r| em.hint(r, Some(NodeKind::AzResourceGroup))) {
                    em.edge(rg, me, k("AZContains"));
                }
            }
        }
        kind if resource_kind(kind).is_some() => {
            let nk = resource_kind(kind).expect("checked");
            let Some(id) = gs(&d, &["id"]) else { return };
            let Some(me) = em.own(id, Some(nk), gs(&d, &["name"]), 0, props()) else { return };
            em.scope(me, cat::AZ_NODE, true);
            if let Some(rg) = gs(&d, &["resourceGroupId"]).and_then(|r| em.hint(r, Some(NodeKind::AzResourceGroup))) {
                em.edge(rg, me, k("AZContains"));
            }
            if let Some(sp) = gs(&d, &["identity", "principalId"]).and_then(|p| em.hint(p, Some(NodeKind::AzServicePrincipal))) {
                em.edge(me, sp, k("AZManagedIdentity"));
            }
            if nk == NodeKind::AzManagedCluster {
                if let (Some(sub), Some(nrg)) = (gs(&d, &["subscriptionId"]), gs(&d, &["properties", "nodeResourceGroup"])) {
                    let rg = format!("{}/resourcegroups/{nrg}", sub_id(sub));
                    if let Some(rg) = em.hint(&rg, Some(NodeKind::AzResourceGroup)) {
                        em.edge(me, rg, k("AZNodeResourceGroup"));
                    }
                }
            } else if let Some(uai) = d.get("identity").and_then(|i| i.get("userAssignedIdentities")).and_then(Value::as_object) {
                for v in uai.values() {
                    if gs(v, &["clientId"]).is_some() {
                        if let Some(sp) = gs(v, &["principalId"]).and_then(|p| em.hint(p, Some(NodeKind::AzServicePrincipal))) {
                            em.edge(me, sp, k("AZManagedIdentity"));
                        }
                    }
                }
            }
        }
        "AZGroupMember" => {
            let Some(g) = gs(&d, &["groupId"]).and_then(|g| em.hint(g, Some(NodeKind::AzGroup))) else { return };
            em.scope(g, cat::AZ_MEMBERS, d.get("members").is_some_and(Value::is_array));
            for m in arr(&d, "members") {
                let Some(obj) = m.get("member") else { continue };
                if let (Some(kind), Some(id)) = (odata_kind(obj), gs(obj, &["id"])) {
                    if let Some(x) = em.hint(id, Some(kind)) {
                        em.edge(x, g, k("AZMemberOf"));
                    }
                }
            }
        }
        "AZGroupOwner" | "AZServicePrincipalOwner" | "AZAppOwner" => {
            let (key, nk) = match rec.kind.as_str() {
                "AZGroupOwner" => ("groupId", NodeKind::AzGroup),
                "AZServicePrincipalOwner" => ("servicePrincipalId", NodeKind::AzServicePrincipal),
                _ => ("appId", NodeKind::AzApp),
            };
            let Some(target) = gs(&d, &[key]).and_then(|t| em.hint(t, Some(nk))) else { return };
            em.scope(target, cat::AZ_OWNERS, d.get("owners").is_some_and(Value::is_array));
            for o in arr(&d, "owners") {
                let Some(obj) = o.get("owner") else { continue };
                if let (Some(kind), Some(id)) = (odata_kind(obj), gs(obj, &["id"])) {
                    if let Some(x) = em.hint(id, Some(kind)) {
                        em.edge(x, target, k("AZOwns"));
                    }
                }
            }
        }
        "AZFederatedIdentityCredential" => {
            let Some(app) = gs(&d, &["appId"]).and_then(|a| em.hint(a, Some(NodeKind::AzApp))) else { return };
            em.scope(app, cat::AZ_FIC, d.get("fics").is_some_and(Value::is_array));
            for f in arr(&d, "fics") {
                let Some(fic) = f.get("fic") else { continue };
                if let Some(id) = gs(fic, &["id"]) {
                    let name = at(gs(fic, &["name"]), tenant_name);
                    if let Some(x) = em.hint_named(id, NodeKind::Unknown, name.as_deref()) {
                        em.edge(x, app, k("AZAuthenticatesTo"));
                    }
                }
            }
        }
        "AZRoleAssignment" => {
            let (Some(role_def), Some(t)) = (gs(&d, &["roleDefinitionId"]), gs(&d, &["tenantId"])) else { return };
            let Some(role) = em.hint(&format!("{role_def}@{t}"), Some(NodeKind::AzRole)) else { return };
            // One record lists every assignment of the role. Only the
            // tenant-scope `principal → role` edges have the role as an
            // endpoint; app-admin and scoped-role edges stay unowned.
            em.scope(role, cat::AZ_ROLE_ASSIGN, d.get("roleAssignments").is_some_and(Value::is_array));
            for ra in arr(&d, "roleAssignments") {
                let Some(p) = gs(ra, &["principalId"]).and_then(|p| em.hint(p, None)) else { continue };
                let rd = gs(ra, &["roleDefinitionId"]).unwrap_or(role_def);
                let special = if rd.eq_ignore_ascii_case(APP_ADMIN) {
                    Some("AZAppAdmin")
                } else if rd.eq_ignore_ascii_case(CLOUD_APP_ADMIN) {
                    Some("AZCloudAppAdmin")
                } else {
                    None
                };
                match (special, role_scope(ra, t)) {
                    (_, RoleScope::Tenant) => em.edge(p, role, k("AZHasRole")),
                    (Some(edge), RoleScope::App { app_id, .. }) => {
                        if let Some(app) = em.hint(app_id, Some(NodeKind::AzApp)) {
                            em.edge(p, app, k(edge));
                        }
                    }
                    (_, RoleScope::App { app_id, name }) => {
                        scoped_role(em, p, rd, t, Scope { id: app_id, kind: NodeKind::AzApp, ty: "application", name });
                    }
                    (_, RoleScope::Object { id, kind, ty, name }) => scoped_role(em, p, rd, t, Scope { id, kind, ty, name }),
                }
            }
        }
        "AZRoleEligibilityScheduleInstance" => {
            if gs(&d, &["directoryScopeId"]).unwrap_or("/") != "/" {
                return;
            }
            let (Some(rd), Some(t), Some(p)) = (gs(&d, &["roleDefinitionId"]), gs(&d, &["tenantId"]), gs(&d, &["principalId"])) else {
                return;
            };
            if let (Some(p), Some(role)) = (em.hint(p, None), em.hint(&format!("{rd}@{t}"), Some(NodeKind::AzRole))) {
                em.edge(p, role, k("AZRoleEligible"));
            }
        }
        "AZRoleManagementPolicyAssignment" => {
            // PIM policy of a tenant-scope role (AzureHound lists only
            // `scopeId eq '/'`). Approvers exist only when activation requires
            // approval; with no approvers listed, Privileged Role and Global
            // Administrators approve (BloodHound CE
            // `ConvertAzureRoleManagementPolicyAssignment`).
            if d.get("endUserAssignmentRequiresApproval").and_then(Value::as_bool) != Some(true) {
                return;
            }
            let (Some(rd), Some(t)) = (gs(&d, &["roleDefinitionId"]), gs(&d, &["tenantId"])) else { return };
            let Some(role) = em.hint(&format!("{rd}@{t}"), Some(NodeKind::AzRole)) else { return };
            // The policy lists all approvers of the role. (A policy that no
            // longer requires approval is skipped above and claims nothing.)
            em.scope(role, cat::AZ_ROLE_APPROVERS, true);
            let ids = |key: &str| -> Vec<&str> { arr(&d, key).iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).collect() };
            let (users, groups) = (ids("endUserAssignmentUserApprovers"), ids("endUserAssignmentGroupApprovers"));
            for (list, nk) in [(&users, NodeKind::AzUser), (&groups, NodeKind::AzGroup)] {
                for a in list.iter() {
                    if let Some(x) = em.hint(a, Some(nk)) {
                        em.edge(x, role, k("AZRoleApprover"));
                    }
                }
            }
            if users.is_empty() && groups.is_empty() {
                for tpl in [PRIV_ROLE_ADMIN, GLOBAL_ADMIN] {
                    if let Some(x) = em.hint(&format!("{tpl}@{t}"), Some(NodeKind::AzRole)) {
                        em.edge(x, role, k("AZRoleApprover"));
                    }
                }
            }
        }
        "AZAppRoleAssignment" => {
            if !gs(&d, &["appId"]).is_some_and(|a| a.eq_ignore_ascii_case(MS_GRAPH_APP_ID))
                || gs(&d, &["principalType"]) != Some("ServicePrincipal")
            {
                return;
            }
            let Some(edge) = gs(&d, &["appRoleId"]).and_then(graph_perm_edge) else { return };
            let sp = gs(&d, &["principalId"]).and_then(|p| em.hint(p, Some(NodeKind::AzServicePrincipal)));
            let res = gs(&d, &["resourceId"]).and_then(|r| em.hint(r, Some(NodeKind::AzServicePrincipal)));
            if let (Some(sp), Some(res)) = (sp, res) {
                em.edge(sp, res, k(edge));
            }
        }
        "AZKeyVaultAccessPolicy" => {
            let (Some(kv), Some(obj)) = (gs(&d, &["keyVaultId"]), gs(&d, &["objectId"])) else { return };
            let (Some(kv), Some(obj)) = (em.hint(kv, Some(NodeKind::AzKeyVault)), em.hint(obj, None)) else { return };
            for (cat, edge) in [("keys", "AZGetKeys"), ("secrets", "AZGetSecrets"), ("certificates", "AZGetCertificates")] {
                let has_get = d
                    .get("permissions")
                    .and_then(|p| p.get(cat))
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|x| x.as_str() == Some("Get")));
                if has_get {
                    em.edge(obj, kv, k(edge));
                }
            }
        }
        kind => {
            if let Some(&(_, parent_key, arr_key, elem_key, edge, nk)) = ROLE_FILTERS.iter().find(|f| f.0 == kind) {
                let Some(parent) = gs(&d, &[parent_key]) else { return };
                let Some(target) = em.hint(parent, Some(nk)) else { return };
                if let Some(i) = crate::merge::RBAC_LISTS.iter().position(|l| *l == arr_key) {
                    em.scope(target, cat::AZ_RBAC_LIST + i as u8, d.get(arr_key).is_some_and(Value::is_array));
                }
                for e in arr(&d, arr_key) {
                    let Some(ra) = e.get(elem_key) else { continue };
                    let Some(p) = gs(ra, &["properties", "principalId"]) else { continue };
                    let scope = gs(ra, &["properties", "scope"]).unwrap_or("");
                    if !in_scope(parent, scope, nk == NodeKind::AzVm) {
                        continue;
                    }
                    if let Some(p) = em.hint(p, None) {
                        em.edge(p, target, k(edge));
                    }
                }
            } else if let Some(res_kind) = kind.strip_suffix("RoleAssignment").and_then(resource_kind) {
                let Some(obj) = gs(&d, &["objectId"]) else { return };
                let Some(target) = em.hint(obj, Some(res_kind)) else { return };
                em.scope(target, cat::AZ_RES_RBAC, d.get("assignees").is_some_and(Value::is_array));
                for a in arr(&d, "assignees") {
                    let role = gs(a, &["roleDefinitionId"]).map(|r| r.rsplit('/').next().unwrap_or(r));
                    let Some(edge) = role.and_then(rbac_edge) else { continue };
                    let Some(p) = gs(a, &["assignee", "properties", "principalId"]) else { continue };
                    let scope = gs(a, &["assignee", "properties", "scope"]).unwrap_or(obj);
                    if !in_scope(obj, scope, false) {
                        continue;
                    }
                    if let Some(p) = em.hint(p, None) {
                        em.edge(p, target, k(edge));
                    }
                }
            }
            // Other kinds (storage accounts, policy assignments, …) are ignored, as in BloodHound.
        }
    }
}

/// Scope object of a scoped role assignment.
struct Scope<'a> {
    id: &'a str,
    kind: NodeKind,
    ty: &'a str,
    name: Option<&'a str>,
}

/// A directory role assigned at a restricted scope. The principal gets
/// `AZHasRole` to a per-scope role node (`<roleDefinitionId>/<scopeId>@<tenant>`)
/// instead of the tenant-wide role: that node is not contained by the tenant,
/// so the tenant-wide role rules (AZResetPassword over all users, Tier Zero
/// roles, ...) do not apply to it. It points to the scope with `AZScopedTo`;
/// post-processing derives the role's rights over that one object (see
/// `postprocess/azure.rs`). The id deliberately does not start with
/// `<template>@`, which is what the default Tier Zero role rule matches.
fn scoped_role(em: &mut Emitter, p: u32, rd: &str, t: &str, sc: Scope) {
    let role_name = builtin_role_name(rd).map(str::to_string).unwrap_or_else(|| format!("Role {rd}"));
    let name = format!("{role_name} (scope: {})", sc.name.unwrap_or(sc.id));
    let props = em.keep_props().then(|| {
        serde_json::json!({
            "displayName": name,
            "roleDefinitionId": rd.to_ascii_uppercase(),
            "tenantId": t.to_ascii_uppercase(),
            "scoped": true,
            "scopeId": sc.id.to_ascii_uppercase(),
            "scopeType": sc.ty,
            "scopeName": sc.name,
        })
        .to_string()
        .into_boxed_str()
    });
    let Some(sr) = em.own(&format!("{rd}/{}@{t}", sc.id), Some(NodeKind::AzRole), Some(&name), 0, props) else { return };
    em.edge(p, sr, ek_of("AZHasRole"));
    let target = if sc.kind == NodeKind::Unknown { em.hint_named(sc.id, sc.kind, sc.name) } else { em.hint(sc.id, Some(sc.kind)) };
    if let Some(x) = target {
        em.edge(sr, x, ek_of("AZScopedTo"));
    }
}

/// Normalise a subscription reference to its ARM id `/subscriptions/<guid>`.
fn sub_id(s: &str) -> String {
    if s.to_ascii_lowercase().starts_with("/subscriptions/") {
        s.to_string()
    } else {
        format!("/subscriptions/{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scope_checks() {
        assert!(in_scope("/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG/PROVIDERS/X/VM1", "/subscriptions/s/resourceGroups/rg", true));
        assert!(!in_scope("/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG2/VM1", "/subscriptions/s/resourceGroups/rg", true));
        assert!(!in_scope("/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG/VM1", "/subscriptions/s/resourceGroups/rg", false));
        assert_eq!(rbac_edge("8E3AF657-A8FF-443C-A75C-2FE8C4BCB635"), Some("AZOwner"));
        assert_eq!(sub_id("abc"), "/subscriptions/abc");
    }

    #[test]
    fn role_scopes() {
        let t = "t-1";
        let sc = |v: Value| -> String { format!("{:?}", role_scope(&v, t)) };
        // Tenant-wide, with and without the empty expanded scope AzureHound writes.
        assert_eq!(sc(json!({"directoryScopeId": "/"})), "Tenant");
        assert_eq!(sc(json!({"directoryScopeId": "/", "directoryScope": {"id": ""}})), "Tenant");
        assert_eq!(sc(json!({"directoryScopeId": "/", "directoryScope": {"id": "T-1", "@odata.type": "#microsoft.graph.organization"}})), "Tenant");
        // AzureHound: app scope rewritten to /<appId>.
        let v = json!({"directoryScopeId": "/app-1", "directoryScope": {"id": "obj-1", "appId": "app-1", "displayName": "Web"}});
        assert_eq!(role_scope(&v, t), RoleScope::App { app_id: "app-1", name: Some("Web") });
        let v = json!({"directoryScopeId": "/app-1"});
        assert_eq!(role_scope(&v, t), RoleScope::App { app_id: "app-1", name: None });
        // AzureHound: AU scope rewritten to "/", recognised from the expanded scope.
        let v = json!({"directoryScopeId": "/", "directoryScope": {"id": "au-1", "@odata.type": "#microsoft.graph.administrativeUnit", "displayName": "Sales"}});
        assert_eq!(role_scope(&v, t), RoleScope::Object { id: "au-1", kind: NodeKind::Unknown, ty: "administrativeUnit", name: Some("Sales") });
        // Raw Graph form.
        let v = json!({"directoryScopeId": "/administrativeUnits/au-2"});
        assert_eq!(role_scope(&v, t), RoleScope::Object { id: "au-2", kind: NodeKind::Unknown, ty: "administrativeUnit", name: None });
        let v = json!({"directoryScopeId": "/", "directoryScope": {"id": "u-9", "@odata.type": "#microsoft.graph.user"}});
        assert_eq!(role_scope(&v, t), RoleScope::Object { id: "u-9", kind: NodeKind::AzUser, ty: "user", name: None });
    }
}
