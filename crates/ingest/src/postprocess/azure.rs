//! Azure / Entra ID post-processing (docs/research/azurehound.md §4):
//! role-based edges and MS Graph app-permission edges (hybrid links: hybrid.rs).

use ahash::{AHashMap, AHashSet};
use ch_model::{ek_of, NodeKind};
use ch_store::{Edge, Graph};
use serde_json::{Map, Value};

pub(crate) mod role {
    pub const GLOBAL_ADMIN: &str = "62E90394-69F5-4237-9190-012177145E10";
    pub const PRIV_ROLE_ADMIN: &str = "E8611AB8-C189-46E8-94E1-60213AB1F814";
    pub const PRIV_AUTH_ADMIN: &str = "7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13";
    pub const PARTNER_TIER1: &str = "4BA39CA4-527C-499A-B93D-D9B492C50246";
    pub const PARTNER_TIER2: &str = "E00E864A-17C5-4A4B-9C06-F5B95A8D5BD8";
    pub const USER_ADMIN: &str = "FE930BE7-5E62-47DB-91AF-98C3A49A38B1";
    pub const HELPDESK_ADMIN: &str = "729827E3-9C14-49F7-BB1B-9608F156BBB8";
    pub const AUTH_ADMIN: &str = "C4E39BD9-1100-46D3-8C65-FB160DA0071F";
    pub const PASSWORD_ADMIN: &str = "966707D0-3269-4727-9BE2-8C3A10F19B9D";
    pub const REPORTS_READER: &str = "4A5D8F65-41DA-4DE4-8968-E035B65339CF";
    pub const MSG_CENTER_READER: &str = "790C1FB9-7F7D-4F88-86A1-EF1F95C05C1B";
    pub const GUEST_INVITER: &str = "95E79109-95C0-4D8E-AEE3-D01ACCF2D47B";
    pub const DIRECTORY_READERS: &str = "88D8E3E3-8F55-4A1E-953A-9B9898B8876B";
    pub const USAGE_REPORTS_READER: &str = "75934031-6C7E-415A-99D7-48DBD49E875E";
    pub const GROUPS_ADMIN: &str = "FDD7A751-B60B-444A-984C-02652FE8FA1C";
    pub const DIRECTORY_WRITERS: &str = "9360FEB5-F418-4BAA-8175-E2A00BAC4301";
    pub const IDENTITY_GOV_ADMIN: &str = "45D8D3C5-C802-45C6-B32A-1D70B5E1E86E";
    pub const INTUNE_ADMIN: &str = "3A2C62DB-5318-420D-8D74-23AFFEE5D9D5";
    pub const KNOWLEDGE_ADMIN: &str = "B5A8DCF3-09D5-43A9-A639-8E29EF291470";
    pub const KNOWLEDGE_MANAGER: &str = "744EC460-397E-42AD-A462-8B3F9747A02C";
    pub const APP_ADMIN: &str = "9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3";
    pub const CLOUD_APP_ADMIN: &str = "158C047A-C907-4556-B7EF-446551A6B5F7";
    pub const HYBRID_IDENTITY_ADMIN: &str = "8AC3FC64-6ECA-42EA-9E69-59F4C7B60EB2";
    pub const DIRECTORY_SYNC: &str = "D29B2B05-8046-44BA-8758-1E26182FCF32";

    /// Roles that add members to any group (`AZAddMembers`).
    pub const ADD_MEMBERS_ANY: &[&str] = &[GLOBAL_ADMIN, PRIV_ROLE_ADMIN];
    /// Roles that add members to groups that are not role-assignable.
    pub const ADD_MEMBERS_NON_ASSIGNABLE: &[&str] =
        &[GROUPS_ADMIN, DIRECTORY_WRITERS, IDENTITY_GOV_ADMIN, USER_ADMIN, INTUNE_ADMIN, KNOWLEDGE_ADMIN, KNOWLEDGE_MANAGER];
    /// Roles that add secrets to applications and service principals (`AZAddSecret`).
    pub const ADD_SECRET: &[&str] = &[APP_ADMIN, CLOUD_APP_ADMIN];
    /// Roles that add owners to applications and service principals (`AZAddOwner`).
    pub const ADD_OWNER: &[&str] = &[HYBRID_IDENTITY_ADMIN, PARTNER_TIER1, PARTNER_TIER2, DIRECTORY_SYNC];
    /// Roles that reset the password of any user of the tenant.
    pub const RESET_ANY: &[&str] = &[GLOBAL_ADMIN, PRIV_AUTH_ADMIN, PARTNER_TIER2];

    /// Display name of a built-in role template (for explanations).
    pub fn name(tpl: &str) -> Option<&'static str> {
        Some(match tpl {
            GLOBAL_ADMIN => "Global Administrator",
            PRIV_ROLE_ADMIN => "Privileged Role Administrator",
            PRIV_AUTH_ADMIN => "Privileged Authentication Administrator",
            PARTNER_TIER1 => "Partner Tier1 Support",
            PARTNER_TIER2 => "Partner Tier2 Support",
            USER_ADMIN => "User Administrator",
            HELPDESK_ADMIN => "Helpdesk Administrator",
            AUTH_ADMIN => "Authentication Administrator",
            PASSWORD_ADMIN => "Password Administrator",
            GROUPS_ADMIN => "Groups Administrator",
            DIRECTORY_WRITERS => "Directory Writers",
            IDENTITY_GOV_ADMIN => "Identity Governance Administrator",
            INTUNE_ADMIN => "Intune Administrator",
            KNOWLEDGE_ADMIN => "Knowledge Administrator",
            KNOWLEDGE_MANAGER => "Knowledge Manager",
            APP_ADMIN => "Application Administrator",
            CLOUD_APP_ADMIN => "Cloud Application Administrator",
            HYBRID_IDENTITY_ADMIN => "Hybrid Identity Administrator",
            DIRECTORY_SYNC => "Directory Synchronization Accounts",
            _ => return None,
        })
    }
}

/// Microsoft Graph application permission → the edges it derives.
pub(crate) const MG_POSTS: &[(&str, &[&str])] = &[
    ("AZMGApplication_ReadWrite_All", &["AZMGAddSecret", "AZMGAddOwner"]),
    ("AZMGDirectory_ReadWrite_All", &["AZMGAddMember", "AZMGAddOwner"]),
    ("AZMGGroup_ReadWrite_All", &["AZMGAddMember", "AZMGAddOwner"]),
    ("AZMGGroupMember_ReadWrite_All", &["AZMGAddMember"]),
    ("AZMGAppRoleAssignment_ReadWrite_All", &["AZMGGrantAppRoles"]),
    ("AZMGRoleManagement_ReadWrite_Directory", &["AZMGGrantRole"]),
    ("AZMGServicePrincipalEndpoint_ReadWrite_All", &["AZMGAddOwner"]),
];

/// Template id of a role node: `templateId`, else the object id's prefix.
pub(crate) fn role_template(g: &Graph, r: u32) -> String {
    get(&props(g, r), "templateId")
        .and_then(Value::as_str)
        .map(str::to_ascii_uppercase)
        .unwrap_or_else(|| g.oid(r).split('@').next().unwrap_or("").to_string())
}

pub(super) fn props(g: &Graph, id: u32) -> Map<String, Value> {
    serde_json::from_str(g.props(id)).unwrap_or_default()
}

/// Case-insensitive property lookup (AzureHound keys are camelCase).
pub(super) fn get<'a>(p: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    p.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
}

pub fn pass(g: &Graph) -> Vec<Edge> {
    let n = g.node_count() as u32;
    let tenants: Vec<u32> = (0..n).filter(|&i| g.kind(i) == NodeKind::AzTenant).collect();
    let mut out: AHashSet<(u32, u32, u16)> = AHashSet::new();
    let mut emit = |s: u32, d: u32, kind: &str| {
        if s != d {
            out.insert((s, d, ek_of(kind)));
        }
    };
    let contains = ek_of("AZContains");
    let has_role = ek_of("AZHasRole");
    let member_of = ek_of("AZMemberOf");
    let out_of = |x: u32, kind: u16| -> Vec<u32> {
        let (d, k) = g.out_edges(x);
        d.iter().zip(k).filter(|(_, kk)| **kk == kind).map(|(&v, _)| v).collect()
    };
    let in_of = |x: u32, kind: u16| -> Vec<u32> {
        let (s, k) = g.in_edges(x);
        s.iter().zip(k).filter(|(_, kk)| **kk == kind).map(|(&v, _)| v).collect()
    };
    let assignable = |gid: u32| get(&props(g, gid), "isAssignableToRole").and_then(Value::as_bool);

    // Scoped role nodes (azurehound.rs `scoped_role`): tenant id → (role node,
    // role definition id, scope object).
    let mut scoped: AHashMap<String, Vec<(u32, String, u32)>> = AHashMap::new();
    if let Some(scoped_to) = g.edge_kind_id("AZScopedTo") {
        for r in (0..n).filter(|&i| g.kind(i) == NodeKind::AzRole) {
            let Some(x) = out_of(r, scoped_to).first().copied() else { continue };
            let p = props(g, r);
            let s = |k: &str| get(&p, k).and_then(Value::as_str).map(str::to_ascii_uppercase);
            let (Some(t), Some(rd)) = (s("tenantId"), s("roleDefinitionId")) else { continue };
            scoped.entry(t).or_default().push((r, rd, x));
        }
    }

    for &t in &tenants {
        let children = out_of(t, contains);
        let of_kind = |k: NodeKind| -> Vec<u32> { children.iter().copied().filter(|&c| g.kind(c) == k).collect() };
        let users = of_kind(NodeKind::AzUser);
        let groups = of_kind(NodeKind::AzGroup);
        let sps = of_kind(NodeKind::AzServicePrincipal);
        let apps = of_kind(NodeKind::AzApp);
        let devices = of_kind(NodeKind::AzDevice);
        let roles = of_kind(NodeKind::AzRole);

        // template id → role node; role node → members (users, groups, SPs)
        let mut role_by_tpl: AHashMap<String, u32> = AHashMap::new();
        let mut members: AHashMap<u32, AHashSet<u32>> = AHashMap::new();
        for &r in &roles {
            let tpl = role_template(g, r);
            role_by_tpl.insert(tpl, r);
            let mut m = AHashSet::new();
            for holder in in_of(r, has_role) {
                match g.kind(holder) {
                    NodeKind::AzUser | NodeKind::AzServicePrincipal => {
                        m.insert(holder);
                    }
                    NodeKind::AzGroup => {
                        m.insert(holder);
                        // One level through a role-assignable group; nesting is not followed.
                        if assignable(holder) == Some(true) {
                            m.extend(in_of(holder, member_of).into_iter().filter(|&x| {
                                matches!(g.kind(x), NodeKind::AzUser | NodeKind::AzServicePrincipal)
                            }));
                        }
                    }
                    _ => {}
                }
            }
            members.insert(r, m);
        }
        let role = |tpl: &str| role_by_tpl.get(tpl).copied();
        let members_of = |tpl: &str| -> Vec<u32> {
            role(tpl).and_then(|r| members.get(&r)).map(|m| m.iter().copied().collect()).unwrap_or_default()
        };

        // Tenant-level control edges.
        for (tpl, edge) in [
            (role::GLOBAL_ADMIN, "AZGlobalAdmin"),
            (role::PRIV_ROLE_ADMIN, "AZPrivilegedRoleAdmin"),
            (role::PRIV_AUTH_ADMIN, "AZPrivilegedAuthAdmin"),
        ] {
            for m in members_of(tpl) {
                emit(m, t, edge);
            }
        }

        // AZAddMembers
        let non_assignable: Vec<u32> = groups.iter().copied().filter(|&gr| assignable(gr) == Some(false)).collect();
        let user_or_sp = |x: &u32| matches!(g.kind(*x), NodeKind::AzUser | NodeKind::AzServicePrincipal);
        for &tpl in role::ADD_MEMBERS_ANY {
            for m in members_of(tpl).iter().filter(|x| user_or_sp(x)) {
                for &gr in &groups {
                    emit(*m, gr, "AZAddMembers");
                }
            }
        }
        for &tpl in role::ADD_MEMBERS_NON_ASSIGNABLE {
            for m in members_of(tpl).iter().filter(|x| user_or_sp(x)) {
                for &gr in &non_assignable {
                    emit(*m, gr, "AZAddMembers");
                }
            }
        }

        // AZResetPassword (source: the role node).
        let mut roles_of_user: AHashMap<u32, AHashSet<&str>> = AHashMap::new();
        for (tpl, &r) in &role_by_tpl {
            for &m in members.get(&r).into_iter().flatten() {
                if g.kind(m) == NodeKind::AzUser {
                    roles_of_user.entry(m).or_default().insert(tpl.as_str());
                }
            }
        }
        // A role held at a restricted scope still makes its holder a role holder
        // (Entra's password-reset rules look at the target's roles, whatever
        // their scope).
        for (sr, rd, _) in scoped.get(g.oid(t)).into_iter().flatten() {
            for h in in_of(*sr, has_role) {
                let direct = (g.kind(h) == NodeKind::AzUser).then_some(h);
                let via_group =
                    if g.kind(h) == NodeKind::AzGroup && assignable(h) == Some(true) { in_of(h, member_of) } else { Vec::new() };
                for u in direct.into_iter().chain(via_group).filter(|&u| g.kind(u) == NodeKind::AzUser) {
                    roles_of_user.entry(u).or_default().insert(rd.as_str());
                }
            }
        }
        let rag_members: AHashSet<u32> = groups
            .iter()
            .filter(|&&gr| assignable(gr) == Some(true))
            .flat_map(|&gr| in_of(gr, member_of))
            .filter(|&x| g.kind(x) == NodeKind::AzUser)
            .collect();
        let without_roles: Vec<u32> = users.iter().copied().filter(|u| !roles_of_user.contains_key(u)).collect();
        let exclusive = |allowed: &[&str]| -> Vec<u32> {
            roles_of_user
                .iter()
                .filter(|(_, rs)| rs.iter().all(|r| allowed.contains(r)))
                .map(|(&u, _)| u)
                .collect()
        };
        let limited = |allowed: &[&str]| -> Vec<u32> {
            without_roles
                .iter()
                .copied()
                .chain(exclusive(allowed))
                .filter(|u| !rag_members.contains(u))
                .collect()
        };
        use role::*;
        let reset_targets: Vec<(&str, Vec<u32>)> = vec![
            (GLOBAL_ADMIN, users.clone()),
            (PRIV_AUTH_ADMIN, users.clone()),
            (PARTNER_TIER2, users.clone()),
            (
                USER_ADMIN,
                limited(&[USER_ADMIN, REPORTS_READER, MSG_CENTER_READER, HELPDESK_ADMIN, GUEST_INVITER, DIRECTORY_READERS, PASSWORD_ADMIN, USAGE_REPORTS_READER, GROUPS_ADMIN]),
            ),
            (
                HELPDESK_ADMIN,
                limited(&[REPORTS_READER, MSG_CENTER_READER, HELPDESK_ADMIN, GUEST_INVITER, DIRECTORY_READERS, PASSWORD_ADMIN, USAGE_REPORTS_READER]),
            ),
            (
                AUTH_ADMIN,
                limited(&[AUTH_ADMIN, REPORTS_READER, MSG_CENTER_READER, GUEST_INVITER, DIRECTORY_READERS, PASSWORD_ADMIN, USAGE_REPORTS_READER]),
            ),
            (PASSWORD_ADMIN, limited(&[PASSWORD_ADMIN, GUEST_INVITER, DIRECTORY_READERS])),
            (PARTNER_TIER1, without_roles.iter().copied().filter(|u| !rag_members.contains(u)).collect()),
        ];
        for (tpl, targets) in &reset_targets {
            if let Some(r) = role(tpl) {
                for &u in targets {
                    emit(r, u, "AZResetPassword");
                }
            }
        }

        // AZAddSecret / AZAddOwner (source: the role node) → every app and SP.
        for (tpls, edge) in [
            (ADD_SECRET, "AZAddSecret"),
            (ADD_OWNER, "AZAddOwner"),
        ] {
            for tpl in tpls {
                if let Some(r) = role(tpl) {
                    for &x in apps.iter().chain(&sps) {
                        emit(r, x, edge);
                    }
                }
            }
        }

        // AZExecuteCommand: Intune admins → Windows devices.
        let windows: Vec<u32> = devices
            .iter()
            .copied()
            .filter(|&dv| {
                get(&props(g, dv), "operatingSystem")
                    .and_then(Value::as_str)
                    .is_some_and(|os| os.to_ascii_lowercase().contains("windows"))
            })
            .collect();
        for m in members_of(INTUNE_ADMIN) {
            for &dv in &windows {
                emit(m, dv, "AZExecuteCommand");
            }
        }

        // Roles assigned at an object scope: the tenant-wide rules, restricted
        // to that one object. Administrative-unit scopes have no collected
        // members, so they grant nothing here (the scoped role node and its
        // AZScopedTo edge keep the assignment visible).
        if let Some(list) = scoped.get(g.oid(t)) {
            let set = |v: &[u32]| -> AHashSet<u32> { v.iter().copied().collect() };
            let reset: Vec<(&str, AHashSet<u32>)> = reset_targets.iter().map(|(tpl, v)| (*tpl, set(v))).collect();
            let (all_groups, non_assignable_set) = (set(&groups), set(&non_assignable));
            let app_or_sp = |x: u32| matches!(g.kind(x), NodeKind::AzApp | NodeKind::AzServicePrincipal) && (apps.contains(&x) || sps.contains(&x));
            for (sr, rd, x) in list {
                let (sr, x, rd) = (*sr, *x, rd.as_str());
                if let Some((_, users)) = reset.iter().find(|(tpl, _)| *tpl == rd) {
                    if users.contains(&x) {
                        emit(sr, x, "AZResetPassword");
                    }
                }
                let add_members_any = ADD_MEMBERS_ANY.contains(&rd);
                let add_members = ADD_MEMBERS_NON_ASSIGNABLE.contains(&rd);
                if (add_members_any && all_groups.contains(&x)) || (add_members && non_assignable_set.contains(&x)) {
                    emit(sr, x, "AZAddMembers");
                }
                if ADD_SECRET.contains(&rd) && app_or_sp(x) {
                    emit(sr, x, "AZAddSecret");
                }
                if ADD_OWNER.contains(&rd) && app_or_sp(x) {
                    emit(sr, x, "AZAddOwner");
                }
                if rd == INTUNE_ADMIN && windows.contains(&x) {
                    emit(sr, x, "AZExecuteCommand");
                }
            }
        }

        // MS Graph application permissions held by SPs on this tenant's SPs.
        let tenant_sps: AHashSet<u32> = sps.iter().copied().collect();
        let holders = |perm: &str| -> AHashSet<u32> {
            let kind = ek_of(perm);
            tenant_sps.iter().flat_map(|&res| in_of(res, kind)).collect()
        };
        for (perm, posts) in [
            ("AZMGApplication_ReadWrite_All", &["AZMGAddSecret", "AZMGAddOwner"][..]),
            ("AZMGDirectory_ReadWrite_All", &["AZMGAddMember", "AZMGAddOwner"][..]),
            ("AZMGGroup_ReadWrite_All", &["AZMGAddMember", "AZMGAddOwner"][..]),
            ("AZMGGroupMember_ReadWrite_All", &["AZMGAddMember"][..]),
        ] {
            for sp in holders(perm) {
                for &post in posts {
                    let targets: Vec<u32> = match (perm, post) {
                        ("AZMGApplication_ReadWrite_All", _) => apps.iter().chain(&sps).copied().collect(),
                        _ => non_assignable.clone(),
                    };
                    for x in targets {
                        emit(sp, x, post);
                    }
                }
            }
        }
        for sp in holders("AZMGAppRoleAssignment_ReadWrite_All") {
            emit(sp, t, "AZMGGrantAppRoles");
        }
        for sp in holders("AZMGRoleManagement_ReadWrite_Directory") {
            for &r in &roles {
                emit(sp, r, "AZMGGrantRole");
            }
        }
        for sp in holders("AZMGServicePrincipalEndpoint_ReadWrite_All") {
            for &x in &sps {
                emit(sp, x, "AZMGAddOwner");
            }
        }
    }

    out.into_iter().map(|(s, d, k)| Edge::new(s, d, k)).collect()
}
