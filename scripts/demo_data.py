#!/usr/bin/env python3
"""Generate a fabricated demo environment for trying CopperHound.

Every name, SID, GUID and tenant id below is made up. The company
("Hollowbrook", HOLLOWBROOK.LOCAL, tenant hollowbrook.example) does not
exist. The data is SharpHound CE and AzureHound shaped JSON with a few
deliberate weaknesses so the findings, paths and planner have something to
show:

* IT Helpdesk can reset passwords of server admins, who are local admins on
  a file server where a Domain Admin is logged on.
* A kerberoastable SQL service account is a Domain Admin.
* An AD Connect sync account has DCSync rights.
* A print server has unconstrained delegation.
* A certificate template lets Domain Users supply the subject (ESC1).
* Stale admin accounts, passwords that never expire, computers without LAPS.
* Entra ID: synchronised users, a Global Administrator who is also on-prem,
  an app registration owned by a regular user with a privileged role.

With --ot it adds a production site (docs/OT.md): a Plant OU with a jump
host, historians, engineering workstations and HMIs, plus an OpenGraph asset
inventory that sets their Purdue levels and adds PLCs with CanProgram edges.
Its weaknesses: IT-WorkstationAdmins (the helpdesk) are local admins on an
engineering workstation, a Domain Admin is logged on to the historian,
Domain Users can RDP to an HMI, and legacy Windows without LAPS.

    python scripts/demo_data.py demo/                # current state (November)
    python scripts/demo_data.py demo-aug/ --stage 1  # August: before any fixes
    python scripts/demo_data.py demo-ot/ --ot        # with the OT site

Stages 1-4 are monthly collections (August to November) in which the
weaknesses get fixed one batch at a time: ESC1 in September, the Domain Users
local admin rights and ACL in October, the rest in November.

Upload a folder's files (or a zip of them) in the web UI, or run
`copperhound ingest demo/ -o demo.chg`. Ingesting the stages in order
(deleting the previous upload each time) gives the posture history and
change alerts something to compare.
"""
import argparse
import json
import os
import random
import time

DOM = "HOLLOWBROOK.LOCAL"
DSID = "S-1-5-21-3141592653-589793238-462643383"
TENANT = "7f3c2a10-5b6e-4d8f-9a1c-2e4b6d8f0a12"
TDOMAIN = "hollowbrook.example"
DAY = 86400

FIRST = """Ava Liam Noah Emma Olivia Mia Lucas Ethan Isla Grace Leo Ella Jack Chloe Henry Ruby Oscar Freya Theo Hannah
Mason Zoe Ivy Nora Adam Lena Felix Clara Hugo Maya Owen Alice Rosa Elliot Iris Jonah Esme Caleb Nina Ezra Aria Miles Elsa
Rowan Daisy Silas Hazel Arlo Willow Jude Mabel Tobias Ada Reuben Lydia Kit Phoebe Ronan Talia Wren Imogen Dmitri Priya Kenji
Amara Mateo Sofia Yusuf Leila Ines Tomas Anika Rahul Mei Joao Fatima Kofi Sienna Aditya Yara Bruno Nadia""".split()
LAST = """Abbott Ashford Barlow Bellamy Blackwood Brennan Calloway Carver Cassidy Dalton Darby Ellery Fairbanks Fenwick
Garrick Gilmore Hadley Halloran Harlow Hawthorne Holloway Ingram Kendrick Kingsley Langley Lockwood Marlowe Mercer Merritt
Norwood Oakley Pemberton Prescott Quill Radcliffe Rowntree Sallow Sherwood Stanton Thorne Underhill Vance Wakefield Whitlock
Winslow Yardley Okafor Nakamura Silva Kowalski Haddad Petrov Moreau Lindqvist Castellano Varga Brandt Duarte Rasmussen""".split()
DEPTS = ["Finance", "HR", "Sales", "Marketing", "Engineering", "Operations", "Legal", "Logistics", "Support", "Facilities"]


def guid(n):
    return f"{n:08X}-4C6F-4E67-8000-{n:012X}"


class Env:
    def __init__(self, stage, now, seed):
        self.stage = stage
        self.now = now
        self.r = random.Random(seed)
        self.rid = 1100
        self.gid = 0x100
        self.users, self.groups, self.computers = [], [], []
        self.ous, self.containers, self.gpos = [], [], []
        self.by_name = {}

    # ---- helpers
    def next_rid(self):
        self.rid += 1
        return f"{DSID}-{self.rid}"

    def next_guid(self):
        self.gid += 1
        return guid(self.gid)

    def ago(self, lo, hi):
        return int(self.now - self.r.uniform(lo, hi) * DAY)

    @staticmethod
    def ace(sid, kind, right, inherited=False):
        return {"PrincipalSID": sid, "PrincipalType": kind, "RightName": right, "IsInherited": inherited}

    def owner_aces(self):
        return [self.ace(f"{DSID}-512", "Group", "Owns"), self.ace(f"{DSID}-512", "Group", "GenericAll", True),
                self.ace(f"{DSID}-519", "Group", "GenericAll", True), self.ace(f"{DOM}-S-1-5-32-544", "Group", "GenericAll", True)]

    # ---- object builders
    def ou(self, name, parent=None, desc=""):
        o = {"ObjectIdentifier": self.next_guid(),
             "Properties": {"name": f"{name.upper()}@{DOM}", "domain": DOM, "domainsid": DSID, "description": desc,
                            "distinguishedname": f"OU={name},DC=HOLLOWBROOK,DC=LOCAL", "blocksinheritance": False},
             "ContainedBy": parent or {"ObjectIdentifier": DSID, "ObjectType": "Domain"},
             "Links": [], "Aces": self.owner_aces(), "ChildObjects": []}
        self.ous.append(o)
        return o

    def ref(self, o, kind):
        return {"ObjectIdentifier": o["ObjectIdentifier"], "ObjectType": kind}

    def user(self, sam, display, ou, **p):
        sid = p.pop("sid", None) or self.next_rid()
        props = {"name": f"{sam.upper()}@{DOM}", "domain": DOM, "domainsid": DSID, "samaccountname": sam,
                 "displayname": display, "enabled": True, "userprincipalname": f"{sam}@{TDOMAIN}",
                 "lastlogontimestamp": self.ago(0, 20), "pwdlastset": self.ago(10, 300),
                 "whencreated": self.ago(300, 2500), "pwdneverexpires": False, "dontreqpreauth": False,
                 "hasspn": False, "admincount": False, "sensitive": False, "serviceprincipalnames": [],
                 "description": "", "title": "",
                 "distinguishedname": f"CN={display},OU=Staff,DC=HOLLOWBROOK,DC=LOCAL"}
        props.update(p)
        u = {"ObjectIdentifier": sid, "Properties": props, "PrimaryGroupSID": f"{DSID}-513",
             "ContainedBy": self.ref(ou, "OU"), "Aces": self.owner_aces(), "AllowedToDelegate": [],
             "HasSIDHistory": [], "SPNTargets": []}
        self.users.append(u)
        self.by_name[sam.lower()] = u
        return u

    def group(self, name, members=(), sid=None, ou=None, desc="", **p):
        sid = sid or self.next_rid()
        props = {"name": f"{name.upper()}@{DOM}", "domain": DOM, "domainsid": DSID, "samaccountname": name,
                 "description": desc, "admincount": False, "whencreated": self.ago(500, 2500)}
        props.update(p)
        g = {"ObjectIdentifier": sid, "Properties": props, "Members": [], "Aces": self.owner_aces(),
             "ContainedBy": self.ref(ou, "OU") if ou else {"ObjectIdentifier": self.users_cn["ObjectIdentifier"], "ObjectType": "Container"}}
        for m in members:
            self.add_member(g, m)
        self.groups.append(g)
        self.by_name[name.lower()] = g
        return g

    def add_member(self, g, m):
        kind = "User" if m in self.users else "Computer" if m in self.computers else "Group"
        g["Members"].append({"ObjectIdentifier": m["ObjectIdentifier"], "ObjectType": kind})

    def computer(self, name, ou, os_name, **p):
        sid = p.pop("sid", None) or self.next_rid()
        props = {"name": f"{name.upper()}.{DOM}", "domain": DOM, "domainsid": DSID, "samaccountname": f"{name.upper()}$",
                 "enabled": True, "operatingsystem": os_name, "haslaps": True, "unconstraineddelegation": False,
                 "lastlogontimestamp": self.ago(0, 7), "pwdlastset": self.ago(0, 30), "whencreated": self.ago(200, 2000),
                 "isdc": False, "description": "",
                 "distinguishedname": f"CN={name.upper()},OU={ou['Properties']['name'].split('@')[0].title()},DC=HOLLOWBROOK,DC=LOCAL"}
        props.update(p)
        c = {"ObjectIdentifier": sid, "Properties": props, "PrimaryGroupSID": f"{DSID}-{516 if props['isdc'] else 515}",
             "ContainedBy": self.ref(ou, "OU"), "Aces": self.owner_aces(), "AllowedToDelegate": [], "AllowedToAct": [],
             "HasSIDHistory": [],
             "Sessions": {"Collected": True, "FailureReason": None, "Results": []},
             "PrivilegedSessions": {"Collected": True, "FailureReason": None, "Results": []},
             "RegistrySessions": {"Collected": True, "FailureReason": None, "Results": []},
             "LocalAdmins": {"Collected": True, "FailureReason": None, "Results": []},
             "RemoteDesktopUsers": {"Collected": True, "FailureReason": None, "Results": []},
             "DcomUsers": {"Collected": True, "FailureReason": None, "Results": []},
             "PSRemoteUsers": {"Collected": True, "FailureReason": None, "Results": []}}
        self.computers.append(c)
        self.by_name[name.lower()] = c
        return c

    def session(self, comp, user):
        comp["Sessions"]["Results"].append({"ComputerSID": comp["ObjectIdentifier"], "UserSID": user["ObjectIdentifier"]})

    def local(self, comp, slot, principal):
        kind = "User" if principal in self.users else "Group" if principal in self.groups else "Computer"
        comp[slot]["Results"].append({"ObjectIdentifier": principal["ObjectIdentifier"], "ObjectType": kind})

    # ---- the environment
    def build(self):
        r = self.r
        st = self.stage
        s1 = st == 1           # fixed in September
        before_oct = st <= 2   # fixed in October
        before_nov = st <= 3   # fixed in November
        self.users_cn = {"ObjectIdentifier": self.next_guid(),
                         "Properties": {"name": f"USERS@{DOM}", "domain": DOM, "domainsid": DSID},
                         "ContainedBy": {"ObjectIdentifier": DSID, "ObjectType": "Domain"}, "Aces": [], "ChildObjects": []}
        self.containers.append(self.users_cn)
        dcs_ou = self.ou("Domain Controllers", desc="Default container for domain controllers")
        tier0 = self.ou("Tier0", desc="Tier Zero admin accounts and groups")
        staff = self.ou("Staff")
        it = self.ou("IT", desc="IT department")
        svc = self.ou("Service Accounts")
        servers = self.ou("Servers")
        wks = self.ou("Workstations")

        # built-in principals
        admin = self.user("Administrator", "Administrator", tier0, sid=f"{DSID}-500", admincount=True,
                          pwdneverexpires=True, description="Built-in account for administering the domain",
                          lastlogontimestamp=self.ago(200, 260))
        self.user("krbtgt", "krbtgt", tier0, sid=f"{DSID}-502", enabled=False, admincount=True,
                  description="Key Distribution Center Service Account", lastlogontimestamp=0)
        guest = self.user("Guest", "Guest", staff, sid=f"{DSID}-501", enabled=False, lastlogontimestamp=0)

        # people
        people = []
        used = set()
        for i in range(420):
            while True:
                f, l = r.choice(FIRST), r.choice(LAST)
                sam = f"{f[0]}{l}".lower()
                if sam not in used:
                    used.add(sam)
                    break
            dept = DEPTS[i % len(DEPTS)]
            enabled = r.random() > 0.06
            u = self.user(sam, f"{f} {l}", staff, title=f"{dept} {r.choice(['Analyst', 'Coordinator', 'Manager', 'Specialist', 'Lead'])}",
                          department=dept, enabled=enabled,
                          lastlogontimestamp=self.ago(0, 25) if enabled else self.ago(120, 600))
            u["_dept"] = dept
            people.append(u)

        def person(first, last, ou, **p):
            sam = f"{first[0]}{last}".lower()
            return self.user(sam, f"{first} {last}", ou, **p)

        # IT staff and admin accounts
        helpdesk_people = [person(f, l, it, title="Service Desk Analyst", department="IT")
                           for f, l in [("Marcus", "Fielding"), ("Tara", "Quinlan"), ("Devi", "Raman"), ("Sam", "Oduya"), ("Lucia", "Ferro")]]
        sysadmins = [person(f, l, it, title="Systems Engineer", department="IT")
                     for f, l in [("Grant", "Ashby"), ("Helena", "Voss"), ("Ibrahim", "Sadiq")]]
        da_accounts = [self.user("adm.gashby", "Grant Ashby (admin)", tier0, admincount=True, title="Domain administration"),
                       self.user("adm.hvoss", "Helena Voss (admin)", tier0, admincount=True, pwdneverexpires=True,
                                 title="Domain administration")]
        stale_admin = self.user("adm.pwhitlock", "Peter Whitlock (admin)", tier0, admincount=True, pwdneverexpires=True,
                                lastlogontimestamp=self.ago(240, 400), pwdlastset=self.ago(900, 1200),
                                description="Left 2025 - keep for audit")
        srv_admin_accts = [self.user(f"srv.{u['Properties']['samaccountname']}", f"{u['Properties']['displayname']} (server)", it,
                                     title="Server administration") for u in sysadmins]

        # service accounts
        svc_sql = self.user("svc_sql", "SQL Service", svc, hasspn=True, admincount=True, pwdneverexpires=True,
                            serviceprincipalnames=[f"MSSQLSvc/sql01.{DOM.lower()}:1433", f"MSSQLSvc/sql01.{DOM.lower()}"],
                            pwdlastset=self.ago(1500, 1800), description="SQL Server service - do not change password")
        svc_backup = self.user("svc_backup", "Backup Service", svc, hasspn=True, pwdneverexpires=True,
                               serviceprincipalnames=[f"backup/bkp01.{DOM.lower()}"], description="Veeam-style backup agent")
        svc_adsync = self.user("MSOL_8a1f4c2e9b07", "On-Premises Directory Synchronization Service Account", svc,
                               pwdneverexpires=True, description="Account created by AD Connect on SYNC01")
        svc_web = self.user("svc_web", "Intranet App Pool", svc, hasspn=True,
                            serviceprincipalnames=[f"HTTP/intranet.{DOM.lower()}"], dontreqpreauth=before_nov)
        svc_scan = self.user("svc_scanner", "Copier scan-to-folder", svc, dontreqpreauth=True, pwdneverexpires=True,
                             description="Multifunction printers - pwd in printer config")

        # computers
        dc1 = self.computer("DC01", dcs_ou, "Windows Server 2022 Datacenter", isdc=True, unconstraineddelegation=True, haslaps=False)
        dc2 = self.computer("DC02", dcs_ou, "Windows Server 2022 Datacenter", isdc=True, unconstraineddelegation=True, haslaps=False)
        srv = {}
        for name, os_name, extra in [
            ("FS01", "Windows Server 2019 Standard", {}),
            ("SQL01", "Windows Server 2019 Standard", {}),
            ("APP01", "Windows Server 2022 Standard", {}),
            ("PRINT01", "Windows Server 2016 Standard", {"unconstraineddelegation": True, "haslaps": False}),
            ("SYNC01", "Windows Server 2022 Standard", {"description": "Microsoft Entra Connect"}),
            ("BKP01", "Windows Server 2019 Standard", {}),
            ("CA01", "Windows Server 2022 Standard", {"description": "Enterprise issuing CA"}),
            ("WEB01", "Windows Server 2016 Standard", {"haslaps": False}),
            ("RDS01", "Windows Server 2019 Standard", {}),
            ("LEGACY-APP", "Windows Server 2012 R2 Standard", {"haslaps": False, "lastlogontimestamp": self.ago(150, 200)}),
        ]:
            srv[name] = self.computer(name, servers, os_name, **extra)
        workstations = []
        for i in range(1, 181):
            os_name = r.choice(["Windows 11 Enterprise"] * 6 + ["Windows 10 Enterprise"] * 3 + ["Windows 10 Pro"])
            workstations.append(self.computer(f"WS-{i:04d}", wks, os_name, haslaps=r.random() > [0.40, 0.30, 0.20, 0.12][st - 1],
                                              enabled=r.random() > 0.04))

        # built-in groups
        da = self.group("Domain Admins", [admin] + da_accounts + [svc_sql] + ([stale_admin] if True else []),
                        sid=f"{DSID}-512", ou=tier0, admincount=True, desc="Designated administrators of the domain")
        du = self.group("Domain Users", [], sid=f"{DSID}-513", desc="All domain users")
        dcomp = self.group("Domain Computers", [], sid=f"{DSID}-515", desc="All workstations and servers")
        dcs = self.group("Domain Controllers", [dc1, dc2], sid=f"{DSID}-516", admincount=True)
        ea = self.group("Enterprise Admins", [admin], sid=f"{DSID}-519", ou=tier0, admincount=True)
        self.group("Schema Admins", [admin], sid=f"{DSID}-518", ou=tier0, admincount=True)
        self.group("Protected Users", da_accounts, sid=f"{DSID}-525", desc="Members get extra protection against credential theft")
        self.group("Administrators", [admin, da, ea], sid=f"{DOM}-S-1-5-32-544", admincount=True)
        self.group("Account Operators", [], sid=f"{DOM}-S-1-5-32-548", admincount=True)
        backup_ops = self.group("Backup Operators", [svc_backup] if before_nov else [], sid=f"{DOM}-S-1-5-32-551", admincount=True)
        self.group("Server Operators", [], sid=f"{DOM}-S-1-5-32-549", admincount=True)

        # organisational groups
        helpdesk = self.group("IT-Helpdesk", helpdesk_people, ou=it, desc="First-line support: password resets")
        server_admins = self.group("IT-ServerAdmins", srv_admin_accts, ou=it, desc="Local admin on member servers")
        wks_admins = self.group("IT-WorkstationAdmins", [helpdesk], ou=it, desc="Local admin on workstations")
        dept_groups = {}
        for d in DEPTS:
            members = [p for p in people if p["_dept"] == d]
            dept_groups[d] = self.group(f"DEPT-{d}", members, ou=staff, desc=f"All {d} staff")
        all_staff = self.group("All-Staff", list(dept_groups.values()), ou=staff, desc="Everyone")
        finance_share = self.group("FS-Finance-Modify", [dept_groups["Finance"]], ou=staff, desc="Modify on \\\\FS01\\Finance")
        rdp_users = self.group("RDS-Users", [dept_groups["Support"], dept_groups["Logistics"]], ou=staff)
        sql_admins = self.group("SQL-Admins", [sysadmins[2], srv_admin_accts[2]], ou=it)
        self.web_team = self.group("APP-WebTeam", [p for p in people if p["_dept"] == "Engineering"][:8], ou=staff,
                                   desc="Intranet developers")
        for i in range(12):
            self.group(f"APP-{r.choice(['Payroll', 'CRM', 'Wiki', 'Ticketing', 'Expenses', 'BI'])}-{i:02d}",
                       r.sample(people, 6), ou=staff)
        for u in self.users:
            if u["PrimaryGroupSID"].endswith("-513"):
                pass
        for c in self.computers:
            if not c["Properties"]["isdc"]:
                self.add_member(dcomp, c)

        # local rights
        for c in srv.values():
            self.local(c, "LocalAdmins", server_admins)
            self.local(c, "LocalAdmins", da)
        self.local(srv["SQL01"], "LocalAdmins", sql_admins)
        self.local(srv["RDS01"], "RemoteDesktopUsers", rdp_users)
        self.local(srv["APP01"], "PSRemoteUsers", helpdesk)
        for w in workstations:
            self.local(w, "LocalAdmins", wks_admins)
            self.local(w, "LocalAdmins", da)
        if s1:
            # an old GPO made Domain Users local admin on a slice of workstations
            for w in workstations[:40]:
                self.local(w, "LocalAdmins", du)

        # sessions
        for i, p in enumerate(people):
            if p["Properties"]["enabled"]:
                self.session(workstations[i % len(workstations)], p)
        for i, h in enumerate(helpdesk_people + sysadmins):
            self.session(workstations[150 + i], h)
        self.session(srv["FS01"], da_accounts[0])          # DA logged on to a member server
        self.session(srv["RDS01"], srv_admin_accts[1])
        self.session(srv["SQL01"], svc_sql)
        if before_nov:
            self.session(workstations[151], da_accounts[1])  # DA on a helpdesk PC (fixed later)

        # ACL weaknesses
        for a in srv_admin_accts:
            a["Aces"].append(self.ace(helpdesk["ObjectIdentifier"], "Group", "ForceChangePassword"))
        for p in people:
            p["Aces"].append(self.ace(helpdesk["ObjectIdentifier"], "Group", "ForceChangePassword", True))
        server_admins["Aces"].append(self.ace(sysadmins[0]["ObjectIdentifier"], "User", "AddMember"))
        svc_backup["Aces"].append(self.ace(server_admins["ObjectIdentifier"], "Group", "GenericWrite"))
        srv["WEB01"]["AllowedToAct"].append({"ObjectIdentifier": srv["APP01"]["ObjectIdentifier"], "ObjectType": "Computer"})
        svc_web["AllowedToDelegate"].append({"ObjectIdentifier": srv["SQL01"]["ObjectIdentifier"], "ObjectType": "Computer"})
        srv["FS01"]["Aces"].append(self.ace(helpdesk["ObjectIdentifier"], "Group", "ReadLAPSPassword"))
        if s1:
            sql_admins["Aces"].append(self.ace(du["ObjectIdentifier"], "Group", "GenericAll"))
        elif before_oct:
            # September: narrowed from Domain Users to three departments; removed in October
            for d in ["Sales", "Marketing", "Operations"]:
                sql_admins["Aces"].append(self.ace(dept_groups[d]["ObjectIdentifier"], "Group", "GenericAll"))
        if before_oct:
            stale_admin["Aces"].append(self.ace(dept_groups["Support"]["ObjectIdentifier"], "Group", "ForceChangePassword"))

        # GPOs
        ddp = {"ObjectIdentifier": self.next_guid(), "Properties": {"name": f"DEFAULT DOMAIN POLICY@{DOM}", "domain": DOM,
               "domainsid": DSID, "gpcpath": "\\\\HOLLOWBROOK.LOCAL\\SYSVOL\\HOLLOWBROOK.LOCAL\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}"},
               "Aces": self.owner_aces()}
        ddcp = {"ObjectIdentifier": self.next_guid(), "Properties": {"name": f"DEFAULT DOMAIN CONTROLLERS POLICY@{DOM}", "domain": DOM,
                "domainsid": DSID}, "Aces": self.owner_aces()}
        wks_gpo = {"ObjectIdentifier": self.next_guid(), "Properties": {"name": f"WORKSTATION BASELINE@{DOM}", "domain": DOM,
                   "domainsid": DSID, "description": "Desktop hardening and local admin groups"},
                   "Aces": self.owner_aces() + [self.ace(wks_admins["ObjectIdentifier"], "Group", "GenericWrite")]}
        srv_gpo = {"ObjectIdentifier": self.next_guid(), "Properties": {"name": f"SERVER BASELINE@{DOM}", "domain": DOM, "domainsid": DSID},
                   "Aces": self.owner_aces() + [self.ace(server_admins["ObjectIdentifier"], "Group", "WriteDacl")]}
        self.gpos = [ddp, ddcp, wks_gpo, srv_gpo]
        dcs_ou["Links"].append({"IsEnforced": False, "GUID": ddcp["ObjectIdentifier"]})
        wks["Links"].append({"IsEnforced": False, "GUID": wks_gpo["ObjectIdentifier"]})
        servers["Links"].append({"IsEnforced": False, "GUID": srv_gpo["ObjectIdentifier"]})
        self.domain_links = [{"IsEnforced": True, "GUID": ddp["ObjectIdentifier"]}]

        # domain object
        dom_aces = [self.ace(f"{DSID}-512", "Group", "GenericAll"), self.ace(f"{DSID}-519", "Group", "GenericAll"),
                    self.ace(f"{DOM}-S-1-5-32-544", "Group", "WriteDacl"), self.ace(f"{DOM}-S-1-5-32-544", "Group", "WriteOwner"),
                    self.ace(f"{DSID}-516", "Group", "GetChangesAll"), self.ace(f"{DOM}-S-1-5-9", "Group", "GetChanges"),
                    self.ace(svc_adsync["ObjectIdentifier"], "User", "GetChanges"),
                    self.ace(svc_adsync["ObjectIdentifier"], "User", "GetChangesAll")]
        self.domain = {"ObjectIdentifier": DSID,
                       "Properties": {"name": DOM, "domain": DOM, "domainsid": DSID, "functionallevel": "2016",
                                      "distinguishedname": "DC=HOLLOWBROOK,DC=LOCAL", "whencreated": self.ago(2900, 3000)},
                       "Aces": dom_aces, "Links": self.domain_links, "ChildObjects": [], "Trusts": [], "IsDeleted": False}
        self.dc1, self.du, self.da = dc1, du, da
        self.srv = srv
        self.people, self.sysadmins, self.helpdesk_people, self.da_accounts = people, sysadmins, helpdesk_people, da_accounts
        self.svc_adsync = svc_adsync
        self.build_adcs()
        _ = (guest, finance_share, all_staff, backup_ops, svc_scan)

    def build_adcs(self):
        cont = lambda name: {"ObjectIdentifier": self.next_guid(), "Properties": {"name": f"{name}@{DOM}", "domain": DOM, "domainsid": DSID},
                             "ContainedBy": {"ObjectIdentifier": DSID, "ObjectType": "Domain"}, "Aces": [], "ChildObjects": []}
        pks = cont("PUBLIC KEY SERVICES")
        tpl_c, eca_c, root_c, aia_c, nta_c = (cont(n) for n in ["CERTIFICATE TEMPLATES", "ENROLLMENT SERVICES", "CERTIFICATION AUTHORITIES", "AIA", "NTAUTHCERTIFICATES-CONTAINER"])
        self.containers += [pks, tpl_c, eca_c, root_c, aia_c, nta_c]
        root_tp, ca_tp = "4D2C3B1A0F9E8D7C6B5A49382716051F2E3D4C5B", "9A8B7C6D5E4F30211203F4E5D6C7B8A99A8B7C6D"
        base = {"domain": DOM, "domainsid": DSID}

        def tpl(name, display, enrollee_subject, ekus, enroll_sid, approval=False):
            return {"ObjectIdentifier": self.next_guid(),
                    "Properties": {"name": f"{name.upper()}@{DOM}", "displayname": display, **base, "schemaversion": 2,
                                   "requiresmanagerapproval": approval, "nosecurityextension": False,
                                   "enrolleesuppliessubject": enrollee_subject, "subjectaltrequireupn": not enrollee_subject,
                                   "subjectaltrequiredns": False, "subjectaltrequiredomaindns": False,
                                   "subjectaltrequireemail": False, "subjectaltrequirespn": False, "subjectrequireemail": False,
                                   "ekus": ekus, "certificateapplicationpolicy": ekus, "certificatepolicy": [],
                                   "authorizedsignatures": 0, "applicationpolicies": [], "issuancepolicies": [],
                                   "effectiveekus": ekus, "authenticationenabled": "1.3.6.1.5.5.7.3.2" in ekus,
                                   "schannelauthenticationenabled": "1.3.6.1.5.5.7.3.2" in ekus, "validityperiod": "1 year"},
                    "ContainedBy": self.ref(tpl_c, "Container"),
                    "Aces": [self.ace(f"{DSID}-519", "Group", "Owns"), self.ace(enroll_sid, "Group", "Enroll")]}

        client_auth = ["1.3.6.1.5.5.7.3.2"]
        self.templates = [
            tpl("User", "User", False, client_auth + ["1.3.6.1.4.1.311.10.3.4", "1.3.6.1.5.5.7.3.4"], f"{DSID}-513"),
            # ESC1: Domain Users could enrol before the fix; now only the web team (still a finding).
            tpl("WebServer-Legacy", "Web Server (Legacy)", True, client_auth + ["1.3.6.1.5.5.7.3.1"],
                f"{DSID}-513" if self.stage == 1 else self.web_team["ObjectIdentifier"]),
            tpl("Machine", "Computer", False, client_auth + ["1.3.6.1.5.5.7.3.1"], f"{DSID}-515"),
            tpl("SmartcardLogon-IT", "Smartcard Logon (IT)", False, client_auth + ["1.3.6.1.4.1.311.20.2.2"], f"{DSID}-512", approval=True),
        ]
        ca_host = self.srv["CA01"]
        self.eca = {"ObjectIdentifier": self.next_guid(), "HostingComputer": ca_host["ObjectIdentifier"],
                    "Properties": {"name": f"HOLLOWBROOK-ISSUING-CA@{DOM}", "caname": "HOLLOWBROOK-ISSUING-CA", **base,
                                   "dnshostname": f"ca01.{DOM.lower()}", "certthumbprint": ca_tp, "certchain": [ca_tp, root_tp],
                                   "isuserspecifiessanenabled": False},
                    "EnabledCertTemplates": [self.ref(t, "CertTemplate") for t in self.templates],
                    "ContainedBy": self.ref(eca_c, "Container"),
                    "Aces": [self.ace(f"{DOM}-S-1-5-32-544", "Group", "Owns"), self.ace(f"{DOM}-S-1-5-11", "Group", "Enroll"),
                             self.ace(f"{DSID}-512", "Group", "ManageCA")]}
        self.rootca = {"ObjectIdentifier": self.next_guid(), "DomainSID": DSID, "ContainedBy": self.ref(root_c, "Container"), "Aces": [],
                       "Properties": {"name": f"HOLLOWBROOK-ROOT-CA@{DOM}", **base, "certthumbprint": root_tp, "certchain": [root_tp]}}
        self.aiaca = {"ObjectIdentifier": self.next_guid(), "ContainedBy": self.ref(aia_c, "Container"), "Aces": [],
                      "Properties": {"name": f"HOLLOWBROOK-ROOT-CA@{DOM}", **base, "certthumbprint": root_tp, "certchain": [root_tp]}}
        self.ntauth = {"ObjectIdentifier": self.next_guid(), "DomainSID": DSID, "ContainedBy": self.ref(pks, "Container"), "Aces": [],
                       "Properties": {"name": f"NTAUTHCERTIFICATES@{DOM}", **base, "certthumbprints": [ca_tp]}}

    # ---- Entra ID (AzureHound)
    def azure(self):
        t, tn = TENANT, "HOLLOWBROOK"
        items = [{"kind": "AZTenant", "data": {"tenantId": t, "displayName": "Hollowbrook", "verifiedDomains": [{"name": TDOMAIN}]}}]
        ids = {}

        def az_id(n):
            return f"{0xA2000000 + n:08x}-1d2e-4f30-8a41-{0x5c6d7e8f9000 + n:012x}"

        def user(key, n, upn, display, onprem=None, enabled=True):
            ids[key] = az_id(n)
            d = {"id": ids[key], "userPrincipalName": upn, "displayName": display, "accountEnabled": enabled, "tenantId": t, "tenantName": tn}
            if onprem:
                d.update({"onPremisesSecurityIdentifier": onprem["ObjectIdentifier"], "onPremisesSyncEnabled": True})
            items.append({"kind": "AZUser", "data": d})

        n = 1
        for p in self.people[:300]:
            user(p["Properties"]["samaccountname"], n, p["Properties"]["userprincipalname"], p["Properties"]["displayname"], p,
                 p["Properties"]["enabled"])
            n += 1
        for p in self.sysadmins + self.helpdesk_people:
            user(p["Properties"]["samaccountname"], n, p["Properties"]["userprincipalname"], p["Properties"]["displayname"], p)
            n += 1
        user("sync", 900, f"Sync_SYNC01_8a1f4c2e9b07@{TDOMAIN}", "On-Premises Directory Synchronization Service Account")
        user("breakglass", 901, f"breakglass01@{TDOMAIN}", "Break Glass 01")
        user("cloudadmin", 902, f"cloudadmin.hvoss@{TDOMAIN}", "Helena Voss (cloud admin)")

        def group(key, n, name, members, role_assignable=False, onprem=None):
            ids[key] = az_id(n)
            d = {"id": ids[key], "displayName": name, "securityEnabled": True, "isAssignableToRole": role_assignable,
                 "tenantId": t, "tenantName": tn}
            if onprem:
                d.update({"onPremisesSecurityIdentifier": onprem["ObjectIdentifier"], "onPremisesSyncEnabled": True})
            items.append({"kind": "AZGroup", "data": d})
            items.append({"kind": "AZGroupMember", "data": {"groupId": ids[key], "members": [
                {"groupId": ids[key], "member": {"id": ids[m], "@odata.type": "#microsoft.graph.user"}} for m in members]}})

        hd_keys = [p["Properties"]["samaccountname"] for p in self.helpdesk_people]
        group("g-helpdesk", 950, "Cloud Helpdesk", hd_keys, role_assignable=True)
        group("g-it", 951, "IT Department", hd_keys + [p["Properties"]["samaccountname"] for p in self.sysadmins])

        sp_id, app_id = az_id(980), az_id(981)
        owner = self.people[7]["Properties"]["samaccountname"]
        items.append({"kind": "AZApp", "data": {"id": app_id, "appId": az_id(982), "displayName": "Expense Sync Connector",
                                                "tenantId": t, "tenantName": tn}})
        items.append({"kind": "AZAppOwner", "data": {"appId": az_id(982), "owners": [
            {"appId": az_id(982), "owner": {"id": ids[owner], "@odata.type": "#microsoft.graph.user"}}]}})
        items.append({"kind": "AZServicePrincipal", "data": {"id": sp_id, "appId": az_id(982), "displayName": "Expense Sync Connector",
                                                             "servicePrincipalType": "Application", "tenantId": t, "tenantName": tn}})
        ids["sp"] = sp_id

        roles = [("62e90394-69f5-4237-9190-012177145e10", "Global Administrator", ["breakglass", "cloudadmin"]),
                 ("d29b2b05-8046-44ba-8758-1e26182fcf32", "Directory Synchronization Accounts", ["sync"]),
                 ("729827e3-9c14-49f7-bb1b-9608f156bbb8", "Helpdesk Administrator", ["g-helpdesk"]),
                 ("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "Application Administrator", [self.sysadmins[1]["Properties"]["samaccountname"]]),
                 ("7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "Privileged Authentication Administrator", ["sp"])]
        if self.stage <= 3:
            roles.append(("fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator", [self.people[11]["Properties"]["samaccountname"]]))
        for rid, name, principals in roles:
            items.append({"kind": "AZRole", "data": {"id": rid, "templateId": rid, "displayName": name, "tenantId": t, "tenantName": tn}})
            items.append({"kind": "AZRoleAssignment", "data": {"roleDefinitionId": rid, "tenantId": t, "roleAssignments": [
                {"principalId": ids[p], "roleDefinitionId": rid, "directoryScopeId": "/"} for p in principals]}})
        return items

    # ---- operational technology (--ot)
    def build_ot(self):
        r = random.Random(self.r.random())  # own sequence: default output unchanged
        g = self.by_name
        plant = self.ou("Plant", desc="Production site: OT servers, engineering workstations and HMIs")
        dcomp, du = g["domain computers"], g["domain users"]
        engineers = [self.user(sam, name, plant, title="Controls Engineer", department="Operations",
                               distinguishedname=f"CN={name},OU=Plant,DC=HOLLOWBROOK,DC=LOCAL")
                     for sam, name in [("rkeller", "Rosa Keller"), ("tbaptiste", "Theo Baptiste"), ("anovak", "Anika Novak")]]
        operators = [self.user(f"op.line{i}", f"Line {i} Operator", plant, title="Shared operator logon",
                               department="Operations", pwdneverexpires=True,
                               distinguishedname=f"CN=Line {i} Operator,OU=Plant,DC=HOLLOWBROOK,DC=LOCAL")
                     for i in (1, 2)]
        vendor = self.user("vnd.rockfield", "Rockfield Automation (vendor)", plant, pwdneverexpires=True,
                           title="Vendor remote support", lastlogontimestamp=self.ago(150, 220),
                           pwdlastset=self.ago(1100, 1400), description="Integrator support account - enable on request",
                           distinguishedname="CN=Rockfield Automation (vendor),OU=Plant,DC=HOLLOWBROOK,DC=LOCAL")
        ot_eng = self.group("OT-Engineers", engineers, ou=plant, desc="Program PLCs, administer EWS and HMIs")
        ot_ops = self.group("OT-Operators", operators, ou=plant, desc="Operate the HMIs")
        ot_vendor = self.group("OT-VendorRemote", [vendor], ou=plant, desc="Vendor access via the OT jump host")
        hosts = {}
        for name, os_name, level, role, extra in [
            ("OT-JUMP01", "Windows Server 2019 Standard", 3.5, "JumpHost", {}),
            ("OT-HISTDMZ", "Windows Server 2019 Standard", 3.5, "Historian", {"description": "Historian replica for business reporting"}),
            ("OT-HIST01", "Windows Server 2016 Standard", 3, "Historian", {}),
            ("OT-SCADA01", "Windows Server 2012 R2 Standard", 3, "SCADA", {"haslaps": False}),
            ("OT-EWS01", "Windows 10 Enterprise LTSC", 2, "EWS", {"haslaps": False}),
            ("OT-EWS02", "Windows 7 Professional", 2, "EWS", {"haslaps": False, "description": "Legacy PLC programming suite"}),
            ("OT-HMI01", "Windows 10 IoT Enterprise", 2, "HMI", {"haslaps": False}),
            ("OT-HMI02", "Windows 10 IoT Enterprise", 2, "HMI", {"haslaps": False}),
            ("OT-HMI03", "Windows Embedded Standard 7", 2, "HMI", {"haslaps": False}),
        ]:
            c = self.computer(name, plant, os_name, **extra)
            hosts[name] = (c, level, role)
            self.add_member(dcomp, c)
        for c, _, _ in hosts.values():
            self.local(c, "LocalAdmins", ot_eng)
            self.local(c, "LocalAdmins", self.da)
        h = {n: v[0] for n, v in hosts.items()}
        for n in ("OT-HMI01", "OT-HMI02", "OT-HMI03"):
            self.local(h[n], "RemoteDesktopUsers", ot_ops)
        self.local(h["OT-JUMP01"], "RemoteDesktopUsers", ot_vendor)
        self.local(h["OT-JUMP01"], "RemoteDesktopUsers", ot_eng)
        # weaknesses
        self.local(h["OT-EWS01"], "LocalAdmins", g["it-workstationadmins"])  # the workstation GPO also hit the EWS
        self.local(h["OT-HMI01"], "RemoteDesktopUsers", du)
        self.session(h["OT-HIST01"], self.da_accounts[0])
        for e, n in zip(engineers, ("OT-EWS01", "OT-EWS02", "OT-JUMP01")):
            self.session(h[n], e)
        for i, o in enumerate(operators):
            self.session(h[f"OT-HMI0{i + 1}"], o)

        # OpenGraph asset inventory: Purdue levels and roles of the AD hosts,
        # the controllers, and what can program them.
        nodes = [{"id": c["ObjectIdentifier"], "kinds": ["Computer"],
                  "properties": {"purdue_level": level, "ot_role": role, "site": "Hollowbrook Mill"}}
                 for c, level, role in hosts.values()]
        for u in engineers + operators + [vendor]:
            nodes.append({"id": u["ObjectIdentifier"], "kinds": ["User"],
                          "properties": {"ot_role": "Vendor" if u is vendor else "OTUser"}})
        for grp, role in ((ot_eng, "OTGroup"), (ot_ops, "OTGroup"), (ot_vendor, "Vendor")):
            nodes.append({"id": grp["ObjectIdentifier"], "kinds": ["Group"], "properties": {"ot_role": role}})
        devices = [("PLC-LINE1", "PLC", "PLC", 1, "Line 1 packaging"), ("PLC-LINE2", "PLC", "PLC", 1, "Line 2 packaging"),
                   ("PLC-BOILER", "PLC", "PLC", 1, "Boiler house"),
                   ("SIS-BOILER", "PLC", "SIS", 1, "Boiler safety instrumented system"),
                   ("DRIVE-L1-01", "OTDevice", "Drive", 0, "Line 1 conveyor drive")]
        for name, kind, role, level, desc in devices:
            nodes.append({"id": f"ot-{name.lower()}", "kinds": [kind],
                          "properties": {"name": name, "purdue_level": level, "ot_role": role, "description": desc,
                                         "vendor": "Fabricated Controls",
                                         "firmware": f"{r.randint(2, 4)}.{r.randint(0, 9)}.{r.randint(0, 20)}",
                                         "site": "Hollowbrook Mill"}})
        ids = {**{n: c["ObjectIdentifier"] for n, c in h.items()}, **{d[0]: f"ot-{d[0].lower()}" for d in devices}}
        prog = [("OT-EWS01", "PLC-LINE1"), ("OT-EWS01", "PLC-LINE2"), ("OT-EWS01", "PLC-BOILER"),
                ("OT-EWS02", "SIS-BOILER"), ("PLC-LINE1", "DRIVE-L1-01")]
        edges = [{"kind": "CanProgram", "start": {"value": ids[a]}, "end": {"value": ids[b]}} for a, b in prog]
        self.ot_graph = {"metadata": {"source_kind": "OTInventory"}, "graph": {"nodes": nodes, "edges": edges}}

    # ---- output
    def write(self, out):
        os.makedirs(out, exist_ok=True)
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(self.now))

        def dump(kind, data, version=6):
            for o in data:
                o.pop("_dept", None)
            doc = {"data": data, "meta": {"methods": 521215, "type": kind, "count": len(data), "version": version,
                                          "collectorversion": "demo"}}
            path = os.path.join(out, f"{stamp}_{kind}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f, separators=(",", ":"))
            return path

        dump("domains", [self.domain])
        dump("users", self.users)
        dump("groups", self.groups)
        dump("computers", self.computers)
        dump("ous", self.ous)
        dump("containers", self.containers)
        dump("gpos", self.gpos)
        dump("certtemplates", self.templates)
        dump("enterprisecas", [self.eca])
        dump("rootcas", [self.rootca])
        dump("aiacas", [self.aiaca])
        dump("ntauthstores", [self.ntauth])
        if getattr(self, "ot_graph", None):
            with open(os.path.join(out, f"{stamp}_ot_inventory.json"), "w", encoding="utf-8") as f:
                json.dump(self.ot_graph, f, separators=(",", ":"))
        az = self.azure()
        with open(os.path.join(out, f"{stamp}_azurehound.json"), "w", encoding="utf-8") as f:
            json.dump({"data": az, "meta": {"methods": 0, "type": "azure", "count": len(az), "version": 5}}, f, separators=(",", ":"))
        print(f"wrote {out}: {len(self.users)} users, {len(self.groups)} groups, {len(self.computers)} computers, "
              f"{len(az)} Entra items (stage {self.stage})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--stage", type=int, choices=[1, 2, 3, 4], default=4,
                    help="1 = August (before fixes) ... 4 = November (current)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--ot", action="store_true", help="add a production site with OT assets (docs/OT.md)")
    ap.add_argument("--now", type=int, default=None, help="Unix time the timestamps are relative to (default: now)")
    a = ap.parse_args()
    now = a.now or int(time.time())
    now -= (4 - a.stage) * 30 * DAY
    env = Env(a.stage, now, a.seed)
    env.build()
    if a.ot:
        env.build_ot()
    env.write(a.out)


if __name__ == "__main__":
    main()
