# Operational technology (OT)

In plants, utilities and other industrial sites, the question is usually whether
the IT side can reach the control systems: an IT admin group that is local admin
on an engineering workstation, a Domain Admin logged on to a historian, a vendor
account on the jump host. These are attack paths, so CopperHound can show them
once it knows which objects are OT and what can program the controllers.

AD collectors know nothing about Purdue levels or PLCs. You add that knowledge as
an [OpenGraph](DATA.md#custom-data-opengraph) file next to the AD data, usually
exported from an OT asset inventory. Nothing else changes: the graph format,
ingest and analysis are the same.

## Conventions

| Property / kind | On | Meaning |
|---|---|---|
| `purdue_level` | any node | Purdue level as a number: `0` field devices, `1` controllers, `2` supervisory (HMI, EWS), `3` site operations (historian, SCADA servers), `3.5` OT DMZ, `4`–`5` enterprise IT |
| `ot_role` | any node | free text; the library and zone templates use `EWS` (engineering workstation), `HMI`, `Historian`, `SCADA`, `JumpHost`, `PLC`, `SIS`, `Vendor` |
| `CanProgram` edge | EWS or account → controller | the source can change the target's logic, configuration or firmware ([edge reference](EDGES.md#ot)) |
| custom node kinds | controllers and devices | e.g. `PLC`, `OTDevice`; any name works and becomes a CHQL label |
| `net_zone` | hosts, controllers | network zone for [network reachability](#network-reachability) |
| `fix_cost` | any node | `window`: changing it needs a maintenance window; `fixed`: it must not be changed (see [Fix cost](#fix-cost)) |

Objects without `purdue_level` count as IT in the queries below.

## Adding OT data

One OpenGraph file does three things:

1. **Enriches the collected AD computers and users** with `purdue_level` and
   `ot_role`. Use the built-in kind (`Computer`, `User`) and the object's SID as
   `id`. The properties merge into the collected object, and its name and other
   properties are kept.
2. **Adds controllers** as custom kinds with their own ids.
3. **Adds `CanProgram` edges** from engineering workstations (or the accounts
   that hold programming rights) to the controllers they can program.

```json
{"metadata": {"source_kind": "OTInventory"},
 "graph": {
   "nodes": [
     {"id": "S-1-5-21-…-1301", "kinds": ["Computer"], "properties": {"purdue_level": 2, "ot_role": "EWS"}},
     {"id": "S-1-5-21-…-1302", "kinds": ["Computer"], "properties": {"purdue_level": 3.5, "ot_role": "JumpHost"}},
     {"id": "plc-line1", "kinds": ["PLC"], "properties": {"name": "PLC-LINE1", "purdue_level": 1, "ot_role": "PLC",
                                                       "vendor": "…", "firmware": "3.4.1"}}
   ],
   "edges": [
     {"kind": "CanProgram", "start": {"value": "S-1-5-21-…-1301"}, "end": {"value": "plc-line1"}}
   ]}}
```

Edge ends can also match by name (`"match_by": "name"`) when the inventory knows
host names but not SIDs. Upload the file on the **Data** page with the
collections and rebuild the graph.

Most OT asset inventories (Claroty, Nozomi, Dragos, Tenable OT and others)
export assets as CSV or JSON. Map their asset type to `ot_role` and their zone or
level to `purdue_level`.

## Collecting AD data safely in OT

Many OT devices and older hosts do not cope well with active scanning.

- **Prefer collection from the domain controllers only.** That means the
  built-in LDAP collector, an LDIF export or an AD Explorer snapshot, or
  SharpHound with `-c DCOnly`. This gives memberships, ACLs, GPOs, delegation and
  trusts without touching OT hosts.
- **Do not run session, local group or RDP enumeration against Purdue level
  0–2 networks.** Skip these SharpHound collection methods for OT subnets
  (`Session`, `LocalGroup`, `RDP`, `DCOM`, `PSRemote`). If you need local admin
  data for HMIs and EWS, take it from the OT team's configuration records or
  GPO-assigned groups instead.
- **Collect in the maintenance window agreed with the site,** and tell the
  OT team before you do.
- **Air-gapped sites:** CopperHound needs no internet access. Move the image
  in with `docker save copperhound:latest -o copperhound.tar` and
  `docker load -i copperhound.tar`, or run
  the binary directly. Copy collections in on approved media.

## Zones

**Zones → New zone → Start from a template** offers OT zones:

- **OT assets (Purdue 0–3)**
- **Controllers (Purdue 0–1)**
- **Engineering workstations** (`ot_role = 'EWS'`)
- **OT DMZ (Purdue 3.5)**
- **OT organizational unit** and **OT domain**, which select by distinguished
  name or domain without any OpenGraph data; edit the name in the selector.

Each zone gets its own exposure, choke points and remediation plan. For example,
the planner on "Controllers" names the object whose fix cuts the most IT
principals off the PLCs.

## Queries

The **OT / ICS** category in the query library:

| Query | Shows |
|---|---|
| `ot-assets`, `ot-assets-by-level` | inventory by Purdue level |
| `ot-can-program` | every `CanProgram` edge |
| `ot-paths-to-controllers` | shortest paths from enabled users to level 0–1 |
| `ot-paths-to-ews` | shortest paths from enabled users to engineering workstations |
| `ot-it-into-ot` | shortest paths from IT users (no `purdue_level`) to level 0–3 |
| `ot-remote-access` | AdminTo, CanRDP, CanPSRemote and ExecuteDCOM on level 0–3 computers |
| `ot-broad-group-access` | the same rights held by Domain Users, Domain Computers, Authenticated Users or Everyone |
| `ot-tier0-sessions` | Tier Zero accounts logged on to level 0–3 computers |
| `ot-sessions` | every session on level 0–3 computers |
| `ot-dmz-admins` | administrators of OT DMZ hosts |
| `ot-legacy-os` | Windows XP / Vista / 7 / Embedded 7 and Server 2003–2012 R2 at level 0–3 |
| `ot-no-laps` | level 0–3 computers without LAPS |
| `ot-unconstrained` | unconstrained delegation at level 0–3 |

## Fix cost

In OT many fixes cannot happen at any time: a reboot needs a production stop, a
vendor-certified configuration voids support when changed, and a safety system's
configuration must not change at all. Tell the remediation planner with the
`fix_cost` node property (set it in the OpenGraph inventory like the Purdue
level):

- `fixed`: never change this object. The planner skips every choke object with
  an edge to or from it, and proposes the next best cut instead.
- `window`: changes need a maintenance window. Steps that touch such an object
  are labelled **maintenance window** in the planner, the report and the CLI.
- Anything else, or no property: the fix can be done any time.

An edge costs the higher of its two ends. For example, removing IT access to an
engineering workstation marked `window` is a window step.

**Remediation → Remediation planner** honours fix costs by default. **Fixes that
need no maintenance window first** puts every step you can do any time before
the window steps, so the plan splits into "now" and "next maintenance window". On
the command line, use `copperhound plan corp.chg --live-first`. The setting works
for every zone, not just OT ones.

## Findings

The OT findings run with every analysis. With no OT data they find nothing. A
principal counts as IT when it has neither `purdue_level` nor `ot_role`, so mark
OT accounts and groups too, e.g. `"ot_role": "OTGroup"`. Their impact is
measured against **OT controllers** (Purdue level 0–1) instead of Tier Zero:
"fixing this removes N principals' paths to OT controllers".

| Finding | Severity | Items |
|---|---|---|
| IT principals can access engineering workstations | Critical | AdminTo, CanRDP, CanPSRemote or ExecuteDCOM held by IT principals (not Tier Zero) on hosts with `ot_role` EWS or a `CanProgram` edge |
| IT principals can access OT hosts | High | the same rights on other Purdue level 0–3 computers |
| Legacy Windows in OT | Medium | enabled level 0–3 computers on XP / Vista / 7 / Embedded 7 / Server 2003–2012 R2 |
| OT hosts without LAPS | Medium | enabled level 0–3 computers without LAPS |
| Enabled vendor accounts | Medium | enabled users with `ot_role` Vendor |

The MITRE references are ATT&CK for ICS techniques: T0886 Remote Services,
T0843 Program Download, T0859 Valid Accounts, T0866 Exploitation of Remote
Services, T0822 External Remote Services.

## Demo

```sh
python scripts/demo_data.py demo-ot/ --ot
```

This adds a fabricated production site to the Hollowbrook demo. The site has a
Plant OU with a jump host, historians, a SCADA server, engineering workstations
and HMIs, plus an OpenGraph inventory with PLCs, a safety system and a drive. It
has these weaknesses:

- IT-WorkstationAdmins (the helpdesk) are local admins on an engineering
  workstation, giving a four-hop path from any helpdesk analyst to the boiler PLC.
- A Domain Admin is logged on to the historian.
- Domain Users can RDP to an HMI.
- Some hosts run Windows 7 or Server 2012 R2, and some have no LAPS.

Hosts below the DMZ and the PLCs have `fix_cost: window`, and the safety system
has `fix_cost: fixed`. Every OT host and device has a `net_zone` (`OT-DMZ`,
`OT-L3`, `OT-L2`, `OT-L1`). The generator also writes `demo-ot-conduits.json`
next to the output folder. Keep it out of the upload, and paste it under
**Admin → Server → Network conduits** or pass it to `--conduits`. With the
conduits, the helpdesk's four-hop path to the boiler PLC is blocked. The
shortest path the network allows is nine hops: it goes through the Domain Admin
session, the jump host in the OT DMZ, an engineer's session and the engineering
workstation.

## Network reachability

Identity paths assume the network lets the attacker connect. In OT this is
rarely true: the plant sits behind an OT DMZ, and only a few conduits cross
each boundary. CopperHound can follow only the paths the conduits allow.

1. **Zones.** Give hosts a `net_zone` property in the OpenGraph inventory,
   for example `"net_zone": "OT-L2"`. Controllers can have zones too.
2. **Conduits.** Under **Admin → Server → Network conduits**, enter which
   services may cross from one zone to another, and the zone an attacker starts
   in:

   ```json
   {"attacker_zone": "IT",
    "conduits": [
      {"from": "IT", "to": "OT-DMZ", "services": ["rdp"]},
      {"from": "OT-DMZ", "to": "OT-L2", "services": ["rdp"]},
      {"from": "OT-L2", "to": "OT-L1", "services": ["plc"]}]}
   ```

   The services are `smb`, `rdp`, `winrm`, `rpc` (DCOM / WMI), `mssql`, `plc`
   and `ssh`; `*` means any service. `"*"` as `from` or `to` means every zone.
   Within one zone everything is allowed, and with no conduit between two
   zones nothing crosses.
3. **Use it.** In the Path tab, tick **Only paths the network allows**. On the
   command line, add `--conduits conduits.json` to `copperhound path` and
   `copperhound tier0`. `GET /network/exposure` compares identity exposure with
   network-feasible exposure.

How a path is checked:

- **Remote access** (`AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`,
  `SQLAdmin`, `CanProgram`) into a host with a zone needs a conduit from the
  attacker's current zone for a matching service. `AdminTo` accepts any of
  smb, rdp, winrm and rpc; `CanProgram` needs plc. The attacker then moves into
  that zone.
- **`HasSession`** needs administrative access (smb, rdp, winrm or rpc) to the
  computer holding the session, and moves the attacker onto it.
- **Other edges** (memberships, ACLs, delegation, cloud roles) are directory
  or cloud operations and need no conduit.
- **Starting zone.** An attacker holding a principal starts in that host's zone
  if it is a host with one, otherwise in `attacker_zone`. Hosts without a zone
  are never blocked.

The findings, the remediation planner and posture still use identity paths.
Network-feasible paths are a second view, not a replacement.

## Not covered yet

- **Conduits from firewall exports.** Conduits are entered by hand. Rules
  exported from firewalls are not imported yet.
- **Network-aware findings and planning.** These still use identity paths (see above).
