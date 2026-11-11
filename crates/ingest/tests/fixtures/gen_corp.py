"""Generate the CORP.LOCAL equivalence fixture used by tests/ldap.rs.

The directory below is described twice, independently: once as raw LDAP
objects (written as LDIF in the three styles ingest must accept: ldapsearch
with comments and 76-column folding, ldifde with CRLF and `changetype: add`,
and gzip), and once as the SharpHound CE JSON a collector would emit for it.
This script only exists to compute the binary values (SIDs, GUIDs, security
descriptors, certificates, thumbprints); the output files are committed.

    python gen_corp.py <crates/ingest/tests/fixtures/corp>
"""
import base64, gzip, hashlib, json, os, struct, sys, uuid

OUT = sys.argv[1]
D = "S-1-5-21-1000-2000-3000"
DOM = "CORP.LOCAL"
BASE = "DC=corp,DC=local"
CONF = "CN=Configuration," + BASE
PKS = "CN=Public Key Services,CN=Services," + CONF


def G(n):
    return f"{n:08x}-0000-4000-8000-{n:012x}"


def GU(n):
    return G(n).upper()


def sid(s):
    p = s.split("-")
    subs = [int(x) for x in p[3:]]
    return bytes([int(p[1]), len(subs)]) + int(p[2]).to_bytes(6, "big") + b"".join(struct.pack("<I", x) for x in subs)


def guid(s):
    return uuid.UUID(s).bytes_le


def ace(mask, who, ot=None, flags=0, it=None):
    """(type, flags, mask, object type, inherited object type, trustee)"""
    return (5 if (ot or it) else 0, flags, mask, ot, it, who)


def sd(owner, aces):
    acl = b""
    for ty, fl, mask, ot, it, who in aces:
        body = struct.pack("<I", mask)
        if ty == 5:
            body += struct.pack("<I", (1 if ot else 0) | (2 if it else 0))
            if ot:
                body += guid(ot)
            if it:
                body += guid(it)
        body += sid(who)
        acl += bytes([ty, fl]) + struct.pack("<H", len(body) + 4) + body
    dacl = bytes([2, 0]) + struct.pack("<HHH", len(acl) + 8, len(aces), 0) + acl
    o = sid(owner)
    return bytes([1, 0]) + struct.pack("<HIIII", 0x8004, 20, 0, 0, 20 + len(o)) + o + dacl


def der(tag, c):
    if len(c) < 0x80:
        return bytes([tag, len(c)]) + c
    return bytes([tag, 0x82]) + struct.pack(">H", len(c)) + c


def cert(issuer, subject):
    """Certificate-shaped DER (structure only: issuer / subject names)."""
    tbs = der(0xA0, der(2, b"\x02")) + der(2, b"\x01") + der(0x30, b"") + der(0x30, issuer) + der(0x30, b"") + der(0x30, subject)
    return der(0x30, der(0x30, tbs) + der(0x30, b""))


def thumb(c):
    return hashlib.sha1(c).hexdigest().upper()


ROOT_CERT = cert(b"CORP-ROOT", b"CORP-ROOT")
CA_CERT = cert(b"CORP-ROOT", b"CORP-CA")
LAPS_GUID = "a1b2c3d4-1111-2222-3333-444455556666"

CTRL = 0x100  # control access (extended right)
WP = 0x20
SELF = 0x8
FULL = 0xF01FF
GW = 0x20028
GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
FCP = "00299570-246d-11d0-a768-00aa006e0529"
MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GPLINK = "f30e3bc1-9ff0-11d1-b603-0000f80367c1"
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
NAME_FLAG = "ea1dddc4-60ff-416e-8cc0-17cee534bce7"
C_USER = "bf967aba-0de6-11d0-a285-00aa003049e2"
C_GROUP = "bf967a9c-0de6-11d0-a285-00aa003049e2"
INHERITED, INHERIT_ONLY = 0x10, 0x08

U = lambda r: f"{D}-{r}"
WK = lambda s: f"{DOM}-{s}"
OC_USER = ["top", "person", "organizationalPerson", "user"]
OC_COMP = OC_USER + ["computer"]


def obj(dn, n, classes, **a):
    attrs = [("objectClass", c) for c in classes]
    attrs.append(("distinguishedName", dn))
    attrs.append(("objectGUID", guid(G(n))))
    attrs.append(("whenCreated", "20240102030405.0Z"))
    for k, v in a.items():
        for x in v if isinstance(v, list) else [v]:
            attrs.append((k, x))
    return (dn, attrs)


GPO1 = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
GPO2 = "{AAAA0000-0000-0000-0000-000000000024}"
domain = [
    obj(BASE, 1, ["top", "domain", "domainDNS"], objectSid=sid(D), name="corp",
        gPLink=f"[LDAP://cn={GPO1},cn=policies,cn=system,{BASE};0]",
        **{"msDS-Behavior-Version": "7", "ms-DS-MachineAccountQuota": "10",
           "nTSecurityDescriptor": sd(U(512), [ace(CTRL, U(1110), GET_CHANGES), ace(CTRL, U(1110), GET_CHANGES_ALL),
                                                ace(0xC0000, "S-1-5-32-544"), ace(CTRL, "S-1-5-9", GET_CHANGES),
                                                ace(0x20094, "S-1-5-11"),
                                                ace(CTRL, U(1111), GET_CHANGES), ace(CTRL, U(1111), GET_CHANGES_FILTERED),
                                                ace(CTRL, U(1112), GET_CHANGES_ALL)])}),
    obj(f"OU=Staff,{BASE}", 2, ["top", "organizationalUnit"], ou="Staff", name="Staff",
        gPLink=f"[LDAP://cn={GPO2},cn=policies,cn=system,{BASE};0][LDAP://cn={GPO1},cn=policies,cn=system,{BASE};1]",
        nTSecurityDescriptor=sd(U(512), [ace(FULL, U(1106), flags=INHERIT_ONLY | 0x2), ace(WP, U(1105), GPLINK)])),
    obj(f"CN=Users,{BASE}", 3, ["top", "container"], cn="Users"),
    obj(f"CN=Computers,{BASE}", 4, ["top", "container"], cn="Computers"),
    obj(f"OU=Domain Controllers,{BASE}", 5, ["top", "organizationalUnit"], ou="Domain Controllers", name="Domain Controllers"),
    obj(f"CN=Alice Smith,OU=Staff,{BASE}", 6, OC_USER, cn="Alice Smith", name="Alice Smith", sAMAccountName="alice",
        objectSid=sid(U(1104)), userAccountControl="66048", primaryGroupID="513",
        description="Helpdesk lead, with a description long enough that ldapsearch folds the line",
        pwdLastSet="133500000000000000", lastLogonTimestamp="133500000000000000",
        nTSecurityDescriptor=sd(U(512), [ace(CTRL, U(1105), FCP),
                                         ace(FULL, U(1106), flags=INHERITED, it=C_GROUP),
                                         ace(WP, U(1106), SPN, flags=INHERITED, it=C_USER)])),
    obj(f"CN=Bob,OU=Staff,{BASE}", 7, OC_USER, cn="Bob", name="Bob", sAMAccountName="bob", objectSid=sid(U(1105)),
        userAccountControl="4194816", primaryGroupID="513", servicePrincipalName="MSSQLSvc/sql01.corp.local:1433",
        sIDHistory=sid("S-1-5-21-9-9-9-1500"), **{"msDS-AllowedToDelegateTo": ["cifs/fs01.corp.local", "cifs/FS01"]}),
    obj(f"CN=svc_sync,CN=Users,{BASE}", 8, OC_USER, cn="svc_sync", sAMAccountName="svc_sync",
        objectSid=sid(U(1110)), userAccountControl="512", primaryGroupID="513", adminCount="1"),
    obj(f"CN=Administrator,CN=Users,{BASE}", 9, OC_USER, cn="Administrator", sAMAccountName="Administrator",
        objectSid=sid(U(500)), userAccountControl="512", primaryGroupID="513", adminCount="1"),
    obj(f"CN=Domain Admins,CN=Users,{BASE}", 10, ["top", "group"], cn="Domain Admins", sAMAccountName="Domain Admins",
        objectSid=sid(U(512)), adminCount="1", member=[f"CN=Administrator,CN=Users,{BASE}", f"CN=Helpdesk,OU=Staff,{BASE}"]),
    obj(f"CN=Domain Users,CN=Users,{BASE}", 11, ["top", "group"], sAMAccountName="Domain Users", objectSid=sid(U(513))),
    obj(f"CN=Domain Computers,CN=Users,{BASE}", 12, ["top", "group"], sAMAccountName="Domain Computers", objectSid=sid(U(515))),
    obj(f"CN=Domain Controllers,CN=Users,{BASE}", 13, ["top", "group"], sAMAccountName="Domain Controllers", objectSid=sid(U(516))),
    obj(f"CN=Enterprise Admins,CN=Users,{BASE}", 30, ["top", "group"], sAMAccountName="Enterprise Admins", objectSid=sid(U(519)),
        adminCount="1", member=f"CN=Administrator,CN=Users,{BASE}"),
    obj(f"CN=Helpdesk,OU=Staff,{BASE}", 14, ["top", "group"], sAMAccountName="Helpdesk", objectSid=sid(U(1106)),
        member=[f"CN=Alice Smith,OU=Staff,{BASE}", f"CN=S-1-5-11,CN=ForeignSecurityPrincipals,{BASE}",
                f"CN=S-1-5-21-9-9-9-1600,CN=ForeignSecurityPrincipals,{BASE}", f"CN=Ghost,OU=Gone,{BASE}"],
        nTSecurityDescriptor=sd(U(512), [ace(WP, U(1105), MEMBER), ace(SELF, U(1104), MEMBER)])),
    # Replication rights split over two groups: carol completes DCSync through
    # membership; Repl Changes alone can SyncLAPSPassword.
    obj(f"CN=Repl Changes,OU=Staff,{BASE}", 31, ["top", "group"], sAMAccountName="Repl Changes", objectSid=sid(U(1111)),
        member=f"CN=Carol,OU=Staff,{BASE}"),
    obj(f"CN=Repl All,OU=Staff,{BASE}", 32, ["top", "group"], sAMAccountName="Repl All", objectSid=sid(U(1112)),
        member=f"CN=Carol,OU=Staff,{BASE}"),
    obj(f"CN=Carol,OU=Staff,{BASE}", 33, OC_USER, cn="Carol", name="Carol", sAMAccountName="carol",
        objectSid=sid(U(1113)), userAccountControl="512", primaryGroupID="513"),
    obj(f"CN=Builtin,{BASE}", 26, ["top", "builtinDomain"], cn="Builtin"),
    obj(f"CN=Administrators,CN=Builtin,{BASE}", 15, ["top", "group"], sAMAccountName="Administrators",
        objectSid=sid("S-1-5-32-544"), member=f"CN=Domain Admins,CN=Users,{BASE}"),
    obj(f"CN=ForeignSecurityPrincipals,{BASE}", 27, ["top", "container"], cn="ForeignSecurityPrincipals"),
    obj(f"CN=S-1-5-11,CN=ForeignSecurityPrincipals,{BASE}", 16, ["top", "foreignSecurityPrincipal"], objectSid=sid("S-1-5-11")),
    obj(f"CN=S-1-5-21-9-9-9-1600,CN=ForeignSecurityPrincipals,{BASE}", 17, ["top", "foreignSecurityPrincipal"],
        objectSid=sid("S-1-5-21-9-9-9-1600")),
    obj(f"CN=DC01,OU=Domain Controllers,{BASE}", 18, OC_COMP, cn="DC01", sAMAccountName="DC01$", objectSid=sid(U(1000)),
        userAccountControl="532480", primaryGroupID="516", dNSHostName="dc01.corp.local",
        operatingSystem="Windows Server 2022 Datacenter"),
    obj(f"CN=FS01,CN=Computers,{BASE}", 19, OC_COMP, cn="FS01", sAMAccountName="FS01$", objectSid=sid(U(1107)),
        userAccountControl="4096", primaryGroupID="515", dNSHostName="fs01.corp.local",
        **{"ms-Mcs-AdmPwdExpirationTime": "133600000000000000",
           "nTSecurityDescriptor": sd(U(512), [ace(CTRL | 0x10, U(1106), LAPS_GUID)]),
           "msDS-AllowedToActOnBehalfOfOtherIdentity": sd("S-1-5-32-544", [ace(FULL, U(1108))])}),
    obj(f"CN=WS01,CN=Computers,{BASE}", 20, OC_COMP, cn="WS01", sAMAccountName="WS01$", objectSid=sid(U(1108)),
        userAccountControl="4096", primaryGroupID="515", dNSHostName="ws01.corp.local",
        nTSecurityDescriptor=sd(U(512), [ace(FULL, U(1106))])),
    obj(f"CN=Managed Service Accounts,{BASE}", 22, ["top", "container"], cn="Managed Service Accounts"),
    obj(f"CN=gmsa_web,CN=Managed Service Accounts,{BASE}", 21, OC_COMP + ["msDS-GroupManagedServiceAccount"],
        cn="gmsa_web", sAMAccountName="gmsa_web$", objectSid=sid(U(1109)), userAccountControl="4096", primaryGroupID="515",
        dNSHostName="gmsa_web.corp.local", servicePrincipalName="http/web.corp.local",
        **{"msDS-GroupMSAMembership": sd("S-1-5-32-544", [ace(FULL, U(1108))])}),
    obj(f"CN=System,{BASE}", 28, ["top", "container"], cn="System"),
    obj(f"CN=Policies,CN=System,{BASE}", 29, ["top", "container"], cn="Policies"),
    obj(f"CN={GPO1},CN=Policies,CN=System,{BASE}", 23, ["top", "container", "groupPolicyContainer"],
        displayName="Default Domain Policy",
        gPCFileSysPath=f"\\\\corp.local\\sysvol\\corp.local\\Policies\\{GPO1}",
        nTSecurityDescriptor=sd(U(512), [ace(GW, U(1105))])),
    obj(f"CN={GPO2},CN=Policies,CN=System,{BASE}", 24, ["top", "container", "groupPolicyContainer"], displayName="Staff Policy"),
    obj(f"CN=partner.local,CN=System,{BASE}", 25, ["top", "leaf", "trustedDomain"], trustPartner="partner.local",
        securityIdentifier=sid("S-1-5-21-9-9-9"), trustDirection="3", trustType="2", trustAttributes="8"),
]

TPL = f"CN=Certificate Templates,{PKS}"
config = [
    obj(f"CN=CORP,CN=Partitions,{CONF}", 41, ["top", "crossRef"], nCName=BASE, nETBIOSName="CORP", dnsRoot="corp.local"),
    obj(f"CN=Services,{CONF}", 42, ["top", "container"], cn="Services"),
    obj(PKS, 43, ["top", "container"], cn="Public Key Services"),
    obj(TPL, 44, ["top", "container"], cn="Certificate Templates"),
    obj(f"CN=Enrollment Services,{PKS}", 45, ["top", "container"], cn="Enrollment Services"),
    obj(f"CN=Certification Authorities,{PKS}", 46, ["top", "container"], cn="Certification Authorities"),
    obj(f"CN=AIA,{PKS}", 47, ["top", "container"], cn="AIA"),
    obj(f"CN=OID,{PKS}", 48, ["top", "msPKI-Enterprise-Oid"], cn="OID"),
    obj(f"CN=ESC1,{TPL}", 49, ["top", "pKICertificateTemplate"], cn="ESC1", name="ESC1", displayName="ESC1",
        **{"msPKI-Template-Schema-Version": "2", "msPKI-Enrollment-Flag": "0", "msPKI-Certificate-Name-Flag": "1",
           "pKIExtendedKeyUsage": "1.3.6.1.5.5.7.3.2", "msPKI-Certificate-Application-Policy": "1.3.6.1.5.5.7.3.2",
           "msPKI-RA-Signature": "0", "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.1.2.3",
           "msPKI-Certificate-Policy": "1.2.3.4", "pKIExpirationPeriod": struct.pack("<q", -315360000000000),
           "nTSecurityDescriptor": sd(U(519), [ace(CTRL, U(513), ENROLL), ace(WP, U(1105), NAME_FLAG)])}),
    obj(f"CN=WebServer,{TPL}", 55, ["top", "pKICertificateTemplate"], cn="WebServer", name="WebServer", displayName="Web Server",
        **{"msPKI-Template-Schema-Version": "1", "msPKI-Enrollment-Flag": "0", "msPKI-Certificate-Name-Flag": "1",
           "pKIExtendedKeyUsage": "1.3.6.1.5.5.7.3.1", "msPKI-RA-Signature": "0",
           "nTSecurityDescriptor": sd(U(519), [ace(CTRL, U(513), ENROLL)])}),
    obj(f"CN=CORP-CA,CN=Enrollment Services,{PKS}", 50, ["top", "pKIEnrollmentService"], cn="CORP-CA", name="CORP-CA",
        dNSHostName="dc01.corp.local", certificateTemplates=["ESC1", "WebServer", "Missing"], cACertificate=CA_CERT,
        nTSecurityDescriptor=sd("S-1-5-32-544", [ace(CTRL, "S-1-5-11", ENROLL)])),
    obj(f"CN=CORP-ROOT,CN=Certification Authorities,{PKS}", 51, ["top", "certificationAuthority"], cn="CORP-ROOT", cACertificate=ROOT_CERT),
    obj(f"CN=CORP-ROOT,CN=AIA,{PKS}", 52, ["top", "certificationAuthority"], cn="CORP-ROOT", cACertificate=ROOT_CERT),
    obj(f"CN=NTAuthCertificates,{PKS}", 53, ["top", "certificationAuthority"], cn="NTAuthCertificates", cACertificate=CA_CERT),
    obj(f"CN=400.ABC,CN=OID,{PKS}", 54, ["top", "msPKI-Enterprise-Oid"], cn="400.ABC", displayName="Low Assurance", flags="2",
        **{"msPKI-Cert-Template-OID": "1.2.3.4", "msDS-OIDToGroupLink": f"CN=Helpdesk,OU=Staff,{BASE}"}),
]
schema = [
    obj(f"CN=ms-Mcs-AdmPwd,CN=Schema,{CONF}", 60, ["top", "attributeSchema"], lDAPDisplayName="ms-Mcs-AdmPwd",
        schemaIDGUID=guid(LAPS_GUID)),
]


def safe(v):
    return isinstance(v, str) and v.isascii() and v and v[0] not in " :<" and v[-1] != " " and "\n" not in v


def fold(line, width=76):
    out = [line[:width]]
    rest = line[width:]
    while rest:
        out.append(" " + rest[: width - 1])
        rest = rest[width - 1:]
    return out


def ldif(entries, eol="\n", ldifde=False, header=""):
    lines = header.splitlines() if header else []
    if not ldifde:
        lines += ["version: 1", ""]
    for dn, attrs in entries:
        if not ldifde:
            lines.append(f"# {dn.split(',')[0].split('=', 1)[1]}, {dn.split(',', 1)[1] if ',' in dn else ''}")
        lines += fold(f"dn: {dn}")
        if ldifde:
            lines.append("changetype: add")
        for k, v in attrs:
            if safe(v):
                lines += fold(f"{k}: {v}")
            else:
                b = v if isinstance(v, bytes) else v.encode()
                lines += fold(f"{k}:: {base64.b64encode(b).decode()}")
        lines.append("")
    if not ldifde:
        lines += ["# search result", "search: 2", "result: 0 Success", "",
                  f"# refldap://corp.local/CN=Configuration,{BASE}", "", f"# numEntries: {len(entries)}"]
    return eol.join(lines) + eol


ld = os.path.join(OUT, "ldif")
os.makedirs(ld, exist_ok=True)
hdr = "# extended LDIF\n#\n# LDAPv3\n# base <DC=corp,DC=local> with scope subtree\n# filter: (objectClass=*)\n# requesting: * nTSecurityDescriptor\n#\n"
with open(os.path.join(ld, "corp-domain.ldif"), "w", newline="") as f:
    f.write(ldif(domain, header=hdr))
with open(os.path.join(ld, "corp-config.ldf"), "w", newline="") as f:
    f.write(ldif(config, eol="\r\n", ldifde=True))
with open(os.path.join(ld, "corp-schema.ldif.gz"), "wb") as f:
    f.write(gzip.compress(ldif(schema).encode(), mtime=0))

# ------------------------------------------------------------------ SharpHound CE JSON of the same directory
def ref(i, t):
    return {"ObjectIdentifier": i, "ObjectType": t}


def A_(sid_, t, right, inh=False):
    return {"PrincipalSID": sid_, "PrincipalType": t, "RightName": right, "IsInherited": inh}


def P(name, **kw):
    p = {"name": name, "domain": DOM, "domainsid": D}
    p.update(kw)
    return p


DA = A_(U(512), "Group", "Owns")
C_USERS, C_COMPS, OU_STAFF, OU_DCS, C_MSA = GU(3), GU(4), GU(2), GU(5), GU(22)
users = [
    {"ObjectIdentifier": U(1104), "Properties": P("ALICE@CORP.LOCAL", enabled=True),
     "PrimaryGroupSID": U(513), "ContainedBy": ref(OU_STAFF, "OU"),
     "Aces": [DA, A_(U(1105), "User", "ForceChangePassword"), A_(U(1106), "Group", "WriteSPN", True)]},
    {"ObjectIdentifier": U(1105), "Properties": P("BOB@CORP.LOCAL", enabled=True, dontreqpreauth=True, hasspn=True),
     "PrimaryGroupSID": U(513), "ContainedBy": ref(OU_STAFF, "OU"), "Aces": [],
     "AllowedToDelegate": [ref(U(1107), "Computer")], "HasSIDHistory": [ref("S-1-5-21-9-9-9-1500", "Base")]},
    {"ObjectIdentifier": U(1110), "Properties": P("SVC_SYNC@CORP.LOCAL", enabled=True, admincount=True),
     "PrimaryGroupSID": U(513), "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(1113), "Properties": P("CAROL@CORP.LOCAL", enabled=True),
     "PrimaryGroupSID": U(513), "ContainedBy": ref(OU_STAFF, "OU"), "Aces": []},
    {"ObjectIdentifier": U(500), "Properties": P("ADMINISTRATOR@CORP.LOCAL", enabled=True, admincount=True),
     "PrimaryGroupSID": U(513), "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(1109), "Properties": P("GMSA_WEB$@CORP.LOCAL", enabled=True, hasspn=True, gmsa=True),
     "PrimaryGroupSID": U(515), "ContainedBy": ref(C_MSA, "Container"), "Aces": [A_(U(1108), "Computer", "ReadGMSAPassword")]},
]
groups = [
    {"ObjectIdentifier": U(512), "Properties": P("DOMAIN ADMINS@CORP.LOCAL", admincount=True),
     "Members": [ref(U(500), "User"), ref(U(1106), "Group")], "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(513), "Properties": P("DOMAIN USERS@CORP.LOCAL"), "Members": [], "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(515), "Properties": P("DOMAIN COMPUTERS@CORP.LOCAL"), "Members": [], "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(516), "Properties": P("DOMAIN CONTROLLERS@CORP.LOCAL"), "Members": [], "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(519), "Properties": P("ENTERPRISE ADMINS@CORP.LOCAL", admincount=True),
     "Members": [ref(U(500), "User")], "ContainedBy": ref(C_USERS, "Container"), "Aces": []},
    {"ObjectIdentifier": U(1106), "Properties": P("HELPDESK@CORP.LOCAL"),
     "Members": [ref(U(1104), "User"), ref(WK("S-1-5-11"), "Group"), ref("S-1-5-21-9-9-9-1600", "Base")],
     "ContainedBy": ref(OU_STAFF, "OU"), "Aces": [DA, A_(U(1105), "User", "AddMember"), A_(U(1104), "User", "AddSelf")]},
    {"ObjectIdentifier": U(1111), "Properties": P("REPL CHANGES@CORP.LOCAL"), "Members": [ref(U(1113), "User")],
     "ContainedBy": ref(OU_STAFF, "OU"), "Aces": []},
    {"ObjectIdentifier": U(1112), "Properties": P("REPL ALL@CORP.LOCAL"), "Members": [ref(U(1113), "User")],
     "ContainedBy": ref(OU_STAFF, "OU"), "Aces": []},
    {"ObjectIdentifier": WK("S-1-5-32-544"), "Properties": P("ADMINISTRATORS@CORP.LOCAL"), "Members": [ref(U(512), "Group")], "Aces": []},
    {"ObjectIdentifier": WK("S-1-5-11"), "Properties": P("AUTHENTICATED USERS@CORP.LOCAL"), "Members": [], "Aces": []},
    {"ObjectIdentifier": WK("S-1-5-9"), "Properties": P("ENTERPRISE DOMAIN CONTROLLERS@CORP.LOCAL"), "Members": [], "Aces": []},
]
computers = [
    {"ObjectIdentifier": U(1000), "Properties": P("DC01.CORP.LOCAL", enabled=True, unconstraineddelegation=True, isdc=True),
     "PrimaryGroupSID": U(516), "ContainedBy": ref(OU_DCS, "OU"), "Aces": []},
    {"ObjectIdentifier": U(1107), "Properties": P("FS01.CORP.LOCAL", enabled=True, haslaps=True),
     "PrimaryGroupSID": U(515), "ContainedBy": ref(C_COMPS, "Container"),
     "Aces": [DA, A_(U(1106), "Group", "ReadLAPSPassword")], "AllowedToAct": [ref(U(1108), "Computer")]},
    {"ObjectIdentifier": U(1108), "Properties": P("WS01.CORP.LOCAL", enabled=True),
     "PrimaryGroupSID": U(515), "ContainedBy": ref(C_COMPS, "Container"),
     "Aces": [DA, A_(U(1106), "Group", "GenericAll")]},
]
domains = [
    {"ObjectIdentifier": D, "Properties": P(DOM, functionallevel="2016"),
     "Aces": [DA, A_(U(1110), "User", "GetChanges"), A_(U(1110), "User", "GetChangesAll"),
              A_(WK("S-1-5-32-544"), "Group", "WriteDacl"), A_(WK("S-1-5-32-544"), "Group", "WriteOwner"),
              A_(WK("S-1-5-9"), "Group", "GetChanges"),
              A_(U(1111), "Group", "GetChanges"), A_(U(1111), "Group", "GetChangesInFilteredSet"),
              A_(U(1112), "Group", "GetChangesAll")],
     "Links": [{"IsEnforced": False, "GUID": GU(23)}],
     "Trusts": [{"TargetDomainSid": "S-1-5-21-9-9-9", "TargetDomainName": "PARTNER.LOCAL", "IsTransitive": True,
                 "SidFilteringEnabled": True, "TrustDirection": "Bidirectional", "TrustType": "External"}]},
]
gpos = [
    {"ObjectIdentifier": GU(23), "Properties": P("DEFAULT DOMAIN POLICY@CORP.LOCAL"), "Aces": [DA, A_(U(1105), "User", "GenericWrite")]},
    {"ObjectIdentifier": GU(24), "Properties": P("STAFF POLICY@CORP.LOCAL"), "Aces": []},
]
ous = [
    {"ObjectIdentifier": OU_STAFF, "Properties": P("STAFF@CORP.LOCAL"), "ContainedBy": ref(D, "Domain"),
     "Links": [{"IsEnforced": False, "GUID": GU(24)}], "Aces": [DA, A_(U(1105), "User", "WriteGPLink")]},
    {"ObjectIdentifier": OU_DCS, "Properties": P("DOMAIN CONTROLLERS@CORP.LOCAL"), "ContainedBy": ref(D, "Domain"), "Links": [], "Aces": []},
]
CPKS = GU(43)
containers = [
    {"ObjectIdentifier": C_USERS, "Properties": P("USERS@CORP.LOCAL"), "ContainedBy": ref(D, "Domain"), "Aces": []},
    {"ObjectIdentifier": C_COMPS, "Properties": P("COMPUTERS@CORP.LOCAL"), "ContainedBy": ref(D, "Domain"), "Aces": []},
    {"ObjectIdentifier": C_MSA, "Properties": P("MANAGED SERVICE ACCOUNTS@CORP.LOCAL"), "ContainedBy": ref(D, "Domain"), "Aces": []},
    {"ObjectIdentifier": GU(27), "Properties": P("FOREIGNSECURITYPRINCIPALS@CORP.LOCAL"), "ContainedBy": ref(D, "Domain"), "Aces": []},
    {"ObjectIdentifier": GU(42), "Properties": P("SERVICES@CORP.LOCAL"), "Aces": []},
    {"ObjectIdentifier": CPKS, "Properties": P("PUBLIC KEY SERVICES@CORP.LOCAL"), "ContainedBy": ref(GU(42), "Container"), "Aces": []},
] + [
    {"ObjectIdentifier": GU(n), "Properties": P(f"{nm}@CORP.LOCAL"), "ContainedBy": ref(CPKS, "Container"), "Aces": []}
    for n, nm in [(44, "CERTIFICATE TEMPLATES"), (45, "ENROLLMENT SERVICES"), (46, "CERTIFICATION AUTHORITIES"), (47, "AIA")]
]
TPROPS = dict(schemaversion=2, requiresmanagerapproval=False, nosecurityextension=False, enrolleesuppliessubject=True,
              subjectaltrequireupn=False, subjectaltrequiredns=False, subjectaltrequiredomaindns=False, subjectaltrequireemail=False,
              subjectaltrequirespn=False, subjectrequireemail=False, ekus=["1.3.6.1.5.5.7.3.2"],
              certificateapplicationpolicy=["1.3.6.1.5.5.7.3.2"], certificatepolicy=["1.2.3.4"], authorizedsignatures=0,
              applicationpolicies=[], issuancepolicies=[], effectiveekus=["1.3.6.1.5.5.7.3.2"], authenticationenabled=True,
              schannelauthenticationenabled=True)
WPROPS = dict(TPROPS, schemaversion=1, ekus=["1.3.6.1.5.5.7.3.1"], certificateapplicationpolicy=[], certificatepolicy=[],
              effectiveekus=["1.3.6.1.5.5.7.3.1"], authenticationenabled=False, schannelauthenticationenabled=False)
certtemplates = [
    {"ObjectIdentifier": GU(49), "Properties": P("ESC1@CORP.LOCAL", **TPROPS), "ContainedBy": ref(GU(44), "Container"),
     "Aces": [A_(U(519), "Group", "Owns"), A_(U(513), "Group", "Enroll"), A_(U(1105), "User", "WritePKINameFlag")]},
    {"ObjectIdentifier": GU(55), "Properties": P("WEBSERVER@CORP.LOCAL", **WPROPS), "ContainedBy": ref(GU(44), "Container"),
     "Aces": [A_(U(519), "Group", "Owns"), A_(U(513), "Group", "Enroll")]},
]
enterprisecas = [
    {"ObjectIdentifier": GU(50), "HostingComputer": U(1000),
     "Properties": P("CORP-CA@CORP.LOCAL", certthumbprint=thumb(CA_CERT), certchain=[thumb(CA_CERT), thumb(ROOT_CERT)]),
     "EnabledCertTemplates": [ref(GU(49), "CertTemplate"), ref(GU(55), "CertTemplate")], "ContainedBy": ref(GU(45), "Container"),
     "Aces": [A_(WK("S-1-5-32-544"), "Group", "Owns"), A_(WK("S-1-5-11"), "Group", "Enroll")]},
]
rootcas = [
    {"ObjectIdentifier": GU(51), "DomainSID": D, "ContainedBy": ref(GU(46), "Container"), "Aces": [],
     "Properties": P("CORP-ROOT@CORP.LOCAL", certthumbprint=thumb(ROOT_CERT), certchain=[thumb(ROOT_CERT)])},
]
aiacas = [
    {"ObjectIdentifier": GU(52), "ContainedBy": ref(GU(47), "Container"), "Aces": [],
     "Properties": P("CORP-ROOT@CORP.LOCAL", certthumbprint=thumb(ROOT_CERT), certchain=[thumb(ROOT_CERT)])},
]
ntauthstores = [
    {"ObjectIdentifier": GU(53), "DomainSID": D, "ContainedBy": ref(CPKS, "Container"), "Aces": [],
     "Properties": P("NTAUTHCERTIFICATES@CORP.LOCAL", certthumbprints=[thumb(CA_CERT)])},
]
issuancepolicies = [
    {"ObjectIdentifier": GU(54), "GroupLink": ref(U(1106), "Group"), "Aces": [],
     "Properties": P("LOW ASSURANCE@CORP.LOCAL", certtemplateoid="1.2.3.4", displayname="Low Assurance")},
]
sh = os.path.join(OUT, "sharphound")
os.makedirs(sh, exist_ok=True)
for name, data in [("users", users), ("groups", groups), ("computers", computers), ("domains", domains), ("gpos", gpos),
                   ("ous", ous), ("containers", containers), ("certtemplates", certtemplates), ("enterprisecas", enterprisecas),
                   ("rootcas", rootcas), ("aiacas", aiacas), ("ntauthstores", ntauthstores), ("issuancepolicies", issuancepolicies)]:
    with open(os.path.join(sh, f"20261109_{name}.json"), "w", newline="\n") as f:
        json.dump({"data": data, "meta": {"methods": 0, "type": name, "count": len(data), "version": 6}}, f, indent=1)
print("ok")
