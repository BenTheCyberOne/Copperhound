//! Port check: popular BloodHound (CE pre-built, legacy pre-built and
//! community) Cypher queries, verbatim or with the minimal change noted, must
//! parse and run on a small AD fixture and on a synthetic graph.
//!
//! `PORTED` lists queries that run unchanged. `NEEDS_CHANGE` lists original
//! queries CHQL rejects, with the reason and the working rewrite.

mod common;

use ch_model::{ek, flags, NodeKind};
use ch_query::{run, run_with, Cancel, QueryResult};
use ch_store::{Edge, Graph, GraphParts};
use std::time::Duration;

/// (name, query, expect a non-empty result on the fixture)
const PORTED: &[(&str, &str, bool)] = &[
    // ---------------------------------------------------------------- BloodHound CE pre-built
    ("CE: All Domain Admins",
     "MATCH p = (t:Group)<-[:MemberOf*1..]-(a) WHERE (a:User or a:Computer) AND t.objectid ENDS WITH '-512' RETURN p LIMIT 1000", true),
    ("CE: Map domain trusts",
     "MATCH p = (:Domain)-[:TrustedBy]->(:Domain) RETURN p LIMIT 1000", true),
    ("CE: Locations of Tier Zero objects",
     "MATCH p = (t:Base)<-[:Contains*1..]-(:Domain) WHERE COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0' RETURN p LIMIT 1000", true),
    ("CE: Online Tier Zero / High Value objects",
     "MATCH (n:Base) WHERE COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0' AND n.enabled = true RETURN n LIMIT 1000", true),
    ("CE: All Kerberoastable users",
     "MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true RETURN u LIMIT 100", true),
    ("CE: Kerberoastable members of Tier Zero",
     "MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true AND COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0' RETURN u LIMIT 100", true),
    ("CE: Kerberoastable users with most admin privileges",
     "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true MATCH (u)-[:MemberOf|AdminTo*1..]->(c:Computer) WITH DISTINCT u, COUNT(c) AS adminCount RETURN u ORDER BY adminCount DESC LIMIT 100", true),
    ("CE: AS-REP Roastable users (DontReqPreAuth)",
     "MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u LIMIT 100", true),
    ("CE: Shortest paths to systems trusted for unconstrained delegation",
     "MATCH p = shortestPath((s)-[:MemberOf|AdminTo|HasSession|GenericAll|Owns|WriteDacl|CanRDP*1..]->(t:Computer)) WHERE t.unconstraineddelegation = true AND s<>t RETURN p LIMIT 1000", true),
    ("CE: Shortest paths to Domain Admins from Kerberoastable users",
     "MATCH p=shortestPath((s:User)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights*1..]->(t:Group)) WHERE s.hasspn=true AND s.enabled = true AND t.objectid ENDS WITH '-512' AND s<>t RETURN p LIMIT 1000", true),
    ("CE: Shortest paths to Tier Zero from Domain Users",
     "MATCH p=shortestPath((s:Group)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|AllowedToDelegate|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions*1..]->(t:Base)) WHERE COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0' AND s.objectid ENDS WITH '-513' AND s<>t RETURN p LIMIT 1000", true),
    ("CE: Shortest paths from Owned objects to Tier Zero",
     "MATCH p=shortestPath((s:Base)-[*1..]->(t:Base)) WHERE COALESCE(s.system_tags, '') CONTAINS 'owned' AND COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0' AND s<>t RETURN p LIMIT 1000", true),
    ("CE: Shortest paths from Owned objects",
     "MATCH p=shortestPath((s:Base)-[*1..]->(t:Base)) WHERE COALESCE(s.system_tags, '') CONTAINS 'owned' AND NOT COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0' AND s<>t RETURN p LIMIT 1000", true),
    ("CE: Principals with DCSync privileges",
     "MATCH p=(:Base)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain) RETURN p LIMIT 1000", true),
    ("CE: Principals with foreign domain group membership",
     "MATCH p=(s:Base)-[:MemberOf]->(t:Group) WHERE s.domainsid<>t.domainsid RETURN p LIMIT 1000", true),
    ("CE: Computers where Domain Users are local administrators",
     "MATCH p=(s:Group)-[:AdminTo]->(:Computer) WHERE s.objectid ENDS WITH '-513' RETURN p LIMIT 1000", true),
    ("CE: Computers where Domain Users can read LAPS passwords",
     "MATCH p=(s:Group)-[:AllExtendedRights|ReadLAPSPassword]->(:Computer) WHERE s.objectid ENDS WITH '-513' RETURN p LIMIT 1000", true),
    ("CE: Workstations where Domain Users can RDP",
     "MATCH p=(s:Group)-[:CanRDP]->(t:Computer) WHERE s.objectid ENDS WITH '-513' AND NOT toUpper(t.operatingsystem) CONTAINS 'SERVER' RETURN p LIMIT 1000", true),
    ("CE: Servers where Domain Users can RDP",
     "MATCH p=(s:Group)-[:CanRDP]->(t:Computer) WHERE s.objectid ENDS WITH '-513' AND toUpper(t.operatingsystem) CONTAINS 'SERVER' RETURN p LIMIT 1000", true),
    ("CE: Dangerous privileges for Domain Users groups",
     "MATCH p=(s:Group)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert]->(:Base) WHERE s.objectid ENDS WITH '-513' RETURN p LIMIT 1000", true),
    ("CE: Domain Admins logons to non-Domain Controllers",
     "MATCH (s)-[:MemberOf*0..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(s) AS exclude MATCH p = (c:Computer)-[:HasSession]->(:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' AND NOT c IN exclude RETURN p LIMIT 1000", true),
    ("CE: Kerberos-enabled computers with unconstrained delegation (non-DC)",
     "MATCH (dc)-[:MemberOf*0..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(dc) AS exclude MATCH (c:Computer) WHERE c.unconstraineddelegation = true AND NOT c IN exclude RETURN c LIMIT 100", true),
    ("CE: Constrained delegation",
     "MATCH p=(:Base)-[:AllowedToDelegate]->(:Computer) RETURN p LIMIT 1000", true),
    ("CE: Resource-based constrained delegation",
     "MATCH p=(:Base)-[:AllowedToAct]->(:Computer) RETURN p LIMIT 1000", true),
    ("CE: Users with no password required",
     "MATCH (u:User) WHERE u.passwordnotreqd = true RETURN u LIMIT 100", true),
    ("CE: Enabled users with password never expires",
     "MATCH (u:User) WHERE u.pwdneverexpires = true AND u.enabled = true RETURN u LIMIT 100", true),
    ("CE: Users not logged in for 90 days",
     "MATCH (u:User) WHERE u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)) AND NOT u.lastlogontimestamp IN [-1.0, 0.0] RETURN u LIMIT 100", true),
    ("CE: Users with password not rotated in 1 year",
     "MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (365 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u LIMIT 100", true),
    ("CE: Enabled Tier Zero principals inactive for 60 days",
     "MATCH (n:Base) WHERE COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0' AND n.enabled = true AND n.lastlogontimestamp < (datetime().epochseconds - (60 * 86400)) AND n.lastlogon < (datetime().epochseconds - (60 * 86400)) AND NOT n.lastlogontimestamp IN [-1.0, 0.0] RETURN n LIMIT 100", true),
    ("CE: Computers with unsupported operating systems",
     "MATCH (c:Computer) WHERE c.operatingsystem =~ '(?i).*Windows.* (2000|2003|2008|2012|xp|vista|7|8|me|nt).*' RETURN c LIMIT 100", true),
    ("CE: Principals with SID history",
     "MATCH p=(:Base)-[:HasSIDHistory]->(:Base) RETURN p LIMIT 1000", true),
    ("CE: Tier Zero users with email",
     "MATCH (u:User) WHERE COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0' AND u.email <> '' RETURN u LIMIT 100", true),
    ("CE: Enrollment rights on published ESC1 certificate templates",
     "MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA) WHERE ct.enrolleesuppliessubject = True AND ct.authenticationenabled = True AND ct.requiresmanagerapproval = False AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1) RETURN p LIMIT 1000", true),
    ("CE: Domain controllers",
     "MATCH p = (:Domain)-[:Contains*1..]->(:Computer)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-516' RETURN p LIMIT 1000", true),
    ("CE: GPOs linked to OUs with computers",
     "MATCH p = (:GPO)-[:GPLink]->(:OU)-[:Contains*1..]->(:Computer) RETURN p LIMIT 1000", true),
    ("CE: Global Administrators (Entra ID)",
     "MATCH p = (:AZBase)-[:AZHasRole|AZMemberOf*1..2]->(r:AZRole) WHERE r.name =~ '(?i)Global Administrator.*' RETURN p LIMIT 1000", true),
    ("CE: Cross-forest trusts with SID filtering disabled (rel props are null in CHQL)",
     "MATCH p=(n:Domain)-[r:TrustedBy]->(m:Domain) WHERE (r.trusttype = 'Forest' OR r.trusttype = 'External') AND r.sidfiltering = false RETURN p LIMIT 1000", false),
    // ---------------------------------------------------------------- legacy BloodHound pre-built
    ("Legacy: Find all Domain Admins",
     "MATCH (n:Group) WHERE n.objectid =~ '(?i)S-1-5-.*-512' WITH n MATCH p=(n)<-[r:MemberOf*1..]-(m) RETURN p", true),
    ("Legacy: Shortest paths to Domain Admins",
     "MATCH (n:Group) WHERE n.objectid =~ '(?i)S-1-5-.*-512' WITH n MATCH p=shortestPath((m)-[*1..]->(n)) WHERE NOT m=n RETURN p", true),
    ("Legacy: Shortest paths to High Value targets",
     "MATCH p=shortestPath((n)-[*1..]->(m {highvalue:true})) WHERE NOT n=m RETURN p", true),
    ("Legacy: Find principals with DCSync rights",
     "MATCH (n1)-[:MemberOf|GetChanges*1..]->(u:Domain) WITH n1,u MATCH (n1)-[:MemberOf|GetChangesAll*1..]->(u) WITH n1,u MATCH p = (n1)-[:MemberOf|GetChanges|GetChangesAll*1..]->(u) RETURN p", true),
    ("Legacy: Shortest paths from Kerberoastable users",
     "MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),p=shortestPath((n)-[r:MemberOf|AdminTo|HasSession|Contains|GPLink|Owns|DCSync|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner*1..]->(m)) WHERE n.hasspn=true RETURN p", true),
    ("Legacy: Shortest path from owned principals to Domain Admins",
     "MATCH (n {owned:true}), (m:Group) WHERE m.objectid ENDS WITH '-512' MATCH p=shortestPath((n)-[*1..]->(m)) RETURN p", true),
    ("Legacy: Computers where Domain Admins are logged in",
     "MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(n) RETURN p", true),
    ("Legacy: Unconstrained delegation computers that are not DCs",
     "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2", true),
    ("Legacy: Computers with unsupported OS",
     "MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(2000|2003|2008|xp|vista|7|me).*' RETURN H", true),
    ("Legacy: AS-REP roastable users",
     "MATCH (u:User {dontreqpreauth: true}) RETURN u", true),
    ("Legacy: List all Kerberoastable accounts",
     "MATCH (n:User) WHERE n.hasspn=true RETURN n", true),
    // ---------------------------------------------------------------- community (hausec, CompassSecurity, …)
    ("Community: Top 10 computers with most admins",
     "MATCH (n)-[:AdminTo]->(c:Computer) WITH c, count(n) AS admins RETURN c.name, admins ORDER BY admins DESC LIMIT 10", true),
    ("Community: Top 10 users with most sessions",
     "MATCH (c:Computer)-[:HasSession]->(u:User) RETURN u.name, count(c) AS sessions ORDER BY sessions DESC LIMIT 10", true),
    ("Community: Percentage of users with a path to Domain Admins",
     "MATCH (totalUsers:User) MATCH p=shortestPath((UsersWithPath:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) WITH COUNT(DISTINCT(totalUsers)) as totalUsers, COUNT(DISTINCT(UsersWithPath)) as UsersWithPath RETURN 100.0 * UsersWithPath / totalUsers AS percentUsersToDA", true),
    ("Community: Groups with 'admin' in the name",
     "MATCH (g:Group) WHERE g.name =~ '(?i).*ADMIN.*' RETURN g.name ORDER BY g.name", true),
    ("Community: Users with admin rights and the number of computers",
     "MATCH (u:User)-[:MemberOf*0..]->(g)-[:AdminTo]->(c:Computer) RETURN u.name AS user, count(DISTINCT c) AS computers ORDER BY computers DESC, user LIMIT 25", true),
    ("Community: Users with local admin but no sessions",
     "MATCH (u:User)-[:AdminTo]->(c:Computer) WHERE NOT (c)-[:HasSession]->(u) RETURN u.name, c.name", true),
    ("Community: Count of direct admins per computer (legacy size(pattern))",
     "MATCH (c:Computer) WITH c, size((c)<-[:AdminTo]-()) AS admins WHERE admins > 0 RETURN c.name, admins ORDER BY admins DESC", true),
    ("Community: Members of groups with GenericAll on Domain Admins",
     "MATCH (u:User)-[:MemberOf*1..]->(g:Group)-[:GenericAll]->(t:Group) WHERE t.objectid ENDS WITH '-512' RETURN DISTINCT u.name", true),
    ("Community: Owned principals",
     "MATCH (n) WHERE n.owned = true RETURN n", true),
    ("Community: OPTIONAL MATCH sessions per DA",
     "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' OPTIONAL MATCH (c:Computer)-[:HasSession]->(u) RETURN u.name, collect(c.name) AS sessions", true),
    ("Community: Users and computers in one list (UNION)",
     "MATCH (u:User) WHERE u.enabled = true RETURN u.name AS name, 'user' AS type UNION ALL MATCH (c:Computer) WHERE c.enabled = true RETURN c.name AS name, 'computer' AS type", true),
    ("Community: Paths without passing through computers",
     "MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH '-512' AND NONE(n IN nodes(p) WHERE n:Computer) RETURN p", false),
    ("Community: Edge-kind histogram",
     "MATCH ()-[r]->() RETURN type(r) AS kind, count(*) AS n ORDER BY n DESC, kind", true),
];

/// Original queries CHQL does not accept: (name, original, reason, CHQL rewrite).
const NEEDS_CHANGE: &[(&str, &str, &str, &str)] = &[
    ("Pattern comprehension",
     "MATCH (u:User) RETURN u.name, [(u)-[:AdminTo]->(c) | c.name] AS admin_of",
     "pattern comprehensions are not supported",
     "MATCH (u:User) OPTIONAL MATCH (u)-[:AdminTo]->(c) RETURN u.name, collect(c.name) AS admin_of"),
    ("Query parameters",
     "MATCH (u:User {name: $name}) RETURN u",
     "parameters are not supported; inline the value",
     "MATCH (u:User {name: 'JDOE@CORP.LOCAL'}) RETURN u"),
    ("APOC / procedures",
     "CALL apoc.meta.stats() YIELD labels RETURN labels",
     "CALL procedures are not supported",
     "MATCH (n) RETURN n.kind, count(n)"),
    ("Neo4j 5 EXISTS subquery",
     "MATCH (u:User) WHERE EXISTS { MATCH (u)-[:AdminTo]->(:Computer) } RETURN u",
     "EXISTS { … } subqueries are not supported; use a pattern predicate",
     "MATCH (u:User) WHERE exists((u)-[:AdminTo]->(:Computer)) RETURN u"),
    ("Write clause (mark owned)",
     "MATCH (u:User {name:'JDOE@CORP.LOCAL'}) SET u.owned = true RETURN u",
     "CHQL is read-only; mark owned objects through the API",
     "MATCH (u:User {name:'JDOE@CORP.LOCAL'}) RETURN u"),
    ("Edge kind not in the data model",
     "MATCH p=(:User)-[:SQLAdmin]->(:Computer) RETURN p",
     "a relationship list made only of unknown kinds is reported as an error (lists mixing known and unknown kinds run)",
     "MATCH p=(:User)-[:SQLAdmin|AdminTo]->(:Computer) RETURN p"),
];

// -------------------------------------------------------------------- fixture

struct N {
    kind: NodeKind,
    flags: u32,
    name: &'static str,
    oid: &'static str,
    props: &'static str,
}

const OLD: &str = "1500000000";

fn fixture() -> Graph {
    const D: &str = "S-1-5-21-1";
    let _ = D;
    let nodes: Vec<N> = vec![
        /* 0 */ N { kind: NodeKind::Domain, flags: flags::TIER0, name: "CORP.LOCAL", oid: "S-1-5-21-1", props: r#"{"domainsid":"S-1-5-21-1"}"# },
        /* 1 */ N { kind: NodeKind::Domain, flags: 0, name: "PARTNER.LOCAL", oid: "S-1-5-21-2", props: r#"{"domainsid":"S-1-5-21-2"}"# },
        /* 2 */ N { kind: NodeKind::Group, flags: flags::TIER0 | flags::HIGHVALUE, name: "DOMAIN ADMINS@CORP.LOCAL", oid: "S-1-5-21-1-512", props: r#"{"domainsid":"S-1-5-21-1"}"# },
        /* 3 */ N { kind: NodeKind::Group, flags: 0, name: "DOMAIN USERS@CORP.LOCAL", oid: "S-1-5-21-1-513", props: r#"{"domainsid":"S-1-5-21-1"}"# },
        /* 4 */ N { kind: NodeKind::Group, flags: flags::TIER0, name: "DOMAIN CONTROLLERS@CORP.LOCAL", oid: "S-1-5-21-1-516", props: r#"{"domainsid":"S-1-5-21-1"}"# },
        /* 5 */ N { kind: NodeKind::Group, flags: 0, name: "IT ADMINS@CORP.LOCAL", oid: "S-1-5-21-1-1100", props: r#"{"domainsid":"S-1-5-21-1"}"# },
        /* 6 */ N { kind: NodeKind::User, flags: flags::TIER0 | flags::ENABLED | flags::ADMINCOUNT | flags::HAS_SPN, name: "ADMINISTRATOR@CORP.LOCAL", oid: "S-1-5-21-1-500", props: r#"{"domainsid":"S-1-5-21-1","enabled":true,"hasspn":true,"email":"admin@corp.local","lastlogontimestamp":1500000000,"lastlogon":1500000000,"pwdlastset":1500000000}"# },
        /* 7 */ N { kind: NodeKind::User, flags: flags::ENABLED | flags::HAS_SPN, name: "SVC_SQL@CORP.LOCAL", oid: "S-1-5-21-1-1101", props: r#"{"domainsid":"S-1-5-21-1","enabled":true,"hasspn":true,"pwdneverexpires":true,"pwdlastset":1500000000,"lastlogontimestamp":1500000000}"# },
        /* 8 */ N { kind: NodeKind::User, flags: flags::ENABLED | flags::DONT_REQ_PREAUTH, name: "ASREP@CORP.LOCAL", oid: "S-1-5-21-1-1102", props: r#"{"domainsid":"S-1-5-21-1","enabled":true,"dontreqpreauth":true,"passwordnotreqd":true}"# },
        /* 9 */ N { kind: NodeKind::User, flags: flags::ENABLED | flags::OWNED, name: "JDOE@CORP.LOCAL", oid: "S-1-5-21-1-1103", props: r#"{"domainsid":"S-1-5-21-1","enabled":true}"# },
        /* 10 */ N { kind: NodeKind::User, flags: flags::HAS_SPN, name: "KRBTGT@CORP.LOCAL", oid: "S-1-5-21-1-502", props: r#"{"domainsid":"S-1-5-21-1","enabled":false,"hasspn":true}"# },
        /* 11 */ N { kind: NodeKind::User, flags: flags::ENABLED, name: "PARTNERUSER@PARTNER.LOCAL", oid: "S-1-5-21-2-1104", props: r#"{"domainsid":"S-1-5-21-2","enabled":true}"# },
        /* 12 */ N { kind: NodeKind::Computer, flags: flags::TIER0 | flags::ENABLED | flags::UNCONSTRAINED_DELEGATION, name: "DC01.CORP.LOCAL", oid: "S-1-5-21-1-1000", props: r#"{"domainsid":"S-1-5-21-1","enabled":true,"unconstraineddelegation":true,"operatingsystem":"Windows Server 2019 Standard"}"# },
        /* 13 */ N { kind: NodeKind::Computer, flags: flags::ENABLED | flags::UNCONSTRAINED_DELEGATION, name: "WS01.CORP.LOCAL", oid: "S-1-5-21-1-1001", props: r#"{"domainsid":"S-1-5-21-1","enabled":true,"unconstraineddelegation":true,"operatingsystem":"Windows 10 Enterprise"}"# },
        /* 14 */ N { kind: NodeKind::Computer, flags: flags::ENABLED, name: "SRV01.CORP.LOCAL", oid: "S-1-5-21-1-1002", props: r#"{"domainsid":"S-1-5-21-1","enabled":true,"operatingsystem":"Windows Server 2008 R2 Standard"}"# },
        /* 15 */ N { kind: NodeKind::Ou, flags: 0, name: "SERVERS@CORP.LOCAL", oid: "OU-1", props: r#"{}"# },
        /* 16 */ N { kind: NodeKind::Gpo, flags: 0, name: "SERVER POLICY@CORP.LOCAL", oid: "GPO-1", props: r#"{}"# },
        /* 17 */ N { kind: NodeKind::CertTemplate, flags: 0, name: "ESC1TEMPLATE@CORP.LOCAL", oid: "CT-1", props: r#"{"enrolleesuppliessubject":true,"authenticationenabled":true,"requiresmanagerapproval":false,"authorizedsignatures":0,"schemaversion":2}"# },
        /* 18 */ N { kind: NodeKind::EnterpriseCa, flags: flags::TIER0, name: "CORP-CA@CORP.LOCAL", oid: "CA-1", props: r#"{}"# },
        /* 19 */ N { kind: NodeKind::AzUser, flags: 0, name: "JDOE@CORP.ONMICROSOFT.COM", oid: "AZ-U-1", props: r#"{}"# },
        /* 20 */ N { kind: NodeKind::AzRole, flags: flags::TIER0, name: "GLOBAL ADMINISTRATOR@CORP", oid: "AZ-R-1", props: r#"{}"# },
        /* 21 */ N { kind: NodeKind::Group, flags: 0, name: "HELPDESK@CORP.LOCAL", oid: "S-1-5-21-1-1105", props: r#"{"domainsid":"S-1-5-21-1"}"# },
    ];
    let e = |s: u32, d: u32, k: u16| Edge::new(s, d, k);
    let (edge_kinds, traversable) = ch_model::builtin_kind_tables();
    let kind = |name: &str| edge_kinds.iter().position(|k| k == name).unwrap_or_else(|| panic!("{name}")) as u16;
    let edges = vec![
        e(6, 2, ek::MEMBER_OF),
        e(5, 2, kind("MemberOf")),
        e(9, 3, ek::MEMBER_OF),
        e(7, 3, ek::MEMBER_OF),
        e(8, 3, ek::MEMBER_OF),
        e(12, 4, ek::MEMBER_OF),
        e(11, 21, ek::MEMBER_OF),
        e(9, 21, ek::MEMBER_OF),
        e(7, 5, ek::MEMBER_OF),
        e(3, 13, ek::ADMIN_TO),
        e(5, 14, ek::ADMIN_TO),
        e(21, 13, ek::ADMIN_TO),
        e(11, 13, ek::ADMIN_TO),
        e(13, 6, ek::HAS_SESSION),
        e(14, 7, ek::HAS_SESSION),
        e(3, 13, kind("CanRDP")),
        e(3, 14, kind("CanRDP")),
        e(3, 14, kind("ReadLAPSPassword")),
        e(21, 2, kind("GenericAll")),
        e(2, 0, kind("DCSync")),
        e(7, 0, kind("GetChanges")),
        e(7, 0, kind("GetChangesAll")),
        e(0, 1, kind("TrustedBy")),
        e(0, 15, kind("Contains")),
        e(0, 12, kind("Contains")),
        e(15, 14, kind("Contains")),
        e(0, 6, kind("Contains")),
        e(16, 15, kind("GPLink")),
        e(14, 13, kind("AllowedToDelegate")),
        e(13, 14, kind("AllowedToAct")),
        e(8, 6, kind("HasSIDHistory")),
        e(3, 17, kind("Enroll")),
        e(17, 18, kind("PublishedTo")),
        e(19, 20, kind("AZHasRole")),
    ];
    let (g, _) = Graph::build(GraphParts {
        kinds: nodes.iter().map(|n| n.kind as u8).collect(),
        flags: nodes.iter().map(|n| n.flags).collect(),
        names: nodes.iter().map(|n| Some(n.name.to_string())).collect(),
        oids: nodes.iter().map(|n| n.oid.to_string()).collect(),
        props: nodes.iter().map(|n| Some(n.props.replace("1500000000", OLD))).collect(),
        edge_chunks: vec![edges],
        edge_kinds,
        traversable,
        node_kinds: Vec::new(),
    })
    .unwrap();
    g
}

fn non_empty(r: &QueryResult) -> bool {
    !r.nodes.is_empty() || !r.rows.is_empty() || !r.paths.is_empty()
}

#[test]
fn bloodhound_queries_run_on_fixture() {
    let g = fixture();
    let mut empty = Vec::new();
    for (name, q, expect) in PORTED {
        let r = run(&g, q, 1000).unwrap_or_else(|e| panic!("{name}: {e}\n{q}"));
        if *expect && !non_empty(&r) {
            empty.push(*name);
        }
    }
    assert!(empty.is_empty(), "queries returned nothing on the fixture: {empty:#?}");
    assert!(PORTED.len() >= 40, "only {} ported queries", PORTED.len());
}

#[test]
fn needs_change_queries_fail_and_rewrites_work() {
    let g = fixture();
    for (name, original, reason, rewrite) in NEEDS_CHANGE {
        assert!(run(&g, original, 100).is_err(), "{name} unexpectedly runs ({reason})");
        run(&g, rewrite, 100).unwrap_or_else(|e| panic!("{name} rewrite: {e}"));
    }
}

#[test]
fn spot_check_results() {
    let g = fixture();
    let names = |q: &str| -> Vec<String> {
        let r = run(&g, q, 1000).unwrap();
        let mut v: Vec<String> = r.nodes.iter().map(|&i| g.name(i).to_string()).collect();
        v.sort();
        v
    };
    assert_eq!(
        names("MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true RETURN u"),
        ["ADMINISTRATOR@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"]
    );
    // Non-DC unconstrained delegation.
    assert_eq!(names(PORTED.iter().find(|p| p.0.contains("(non-DC)")).unwrap().1), ["WS01.CORP.LOCAL"]);
    // DA logons to non-DCs: WS01 has a session of ADMINISTRATOR.
    // SRV01 also holds a session of SVC_SQL (nested into DA through IT ADMINS).
    let r = run(&g, PORTED.iter().find(|p| p.0.contains("logons to non-Domain")).unwrap().1, 1000).unwrap();
    assert_eq!(r.paths.len(), 2);
    // Foreign group membership.
    let r = run(&g, PORTED.iter().find(|p| p.0.contains("foreign domain")).unwrap().1, 1000).unwrap();
    assert_eq!(r.edges.len(), 1);
    // Percentage of users with a path to DA: all but KRBTGT (5 of 6).
    let r = run(&g, PORTED.iter().find(|p| p.0.contains("Percentage")).unwrap().1, 1000).unwrap();
    let pct = r.rows[0][0].as_f64().unwrap();
    assert!((pct - 500.0 / 6.0).abs() < 1e-9, "{pct}");
    // DCSync (legacy): SVC_SQL has both GetChanges and GetChangesAll; DOMAIN ADMINS via DCSync is not GetChanges.
    let r = run(&g, PORTED.iter().find(|p| p.0.contains("DCSync rights")).unwrap().1, 1000).unwrap();
    assert!(r.nodes.contains(&7));
}

#[test]
fn bloodhound_queries_run_on_synthetic_graph() {
    let dir = std::env::temp_dir().join(format!("ch-compat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 3_000, computers: 600, groups: 200, seed: 5 }, &dir).unwrap();
    let g = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    for (name, q, _) in PORTED {
        let t = std::time::Instant::now();
        // Queries naming edge kinds absent from this data set are fine; they error only if every kind is unknown.
        match run_with(&g, q, 1000, &Cancel::new(Some(Duration::from_secs(60)))) {
            Ok(_) => {}
            Err(e) => panic!("{name}: {e}\n{q}"),
        }
        eprintln!("{:>8.1} ms  {name}", t.elapsed().as_secs_f64() * 1e3);
        assert!(t.elapsed() < Duration::from_secs(20), "{name} took {:?}", t.elapsed());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Pushdown on vs off: identical results for every ported query and every
/// rewrite, on the fixture and on a synthetic graph.
#[test]
fn pushdown_is_invisible() {
    let fx = fixture();
    fx.columns();
    let dir = std::env::temp_dir().join(format!("ch-compat-ch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    ch_synth::generate(&ch_synth::SynthConfig { users: 2_000, computers: 400, groups: 150, seed: 7 }, &dir).unwrap();
    let syn = ch_ingest::build_graph(std::slice::from_ref(&dir), &ch_ingest::IngestOptions::default()).unwrap().graph;
    syn.columns();
    for g in [&fx, &syn] {
        let mut hits = 0;
        for (_, q, _) in PORTED {
            hits += common::check(g, q);
        }
        for (_, original, _, rewrite) in NEEDS_CHANGE {
            common::check(g, original);
            hits += common::check(g, rewrite);
        }
        assert!(hits > 0);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
