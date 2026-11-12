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

## Not covered yet

- **Network reachability.** Firewall rules and conduits are not modelled, so a
  path through `AdminTo` assumes the network allows the connection. Read OT
  paths as "the identity allows it". Check the conduit rules before you rank a
  path as exploitable.
- **OT findings.** These queries do not yet appear as measured findings.
- **Fix cost.** The remediation planner does not weigh how hard a fix is,
  such as a reboot window or a vendor-certified configuration.
