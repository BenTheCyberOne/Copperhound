# ADCS in SharpHound CE / BloodHound CE: source-verified reference

Scope: what SharpHound CE writes for ADCS objects, how BloodHound CE (BH CE) turns that into nodes and structural edges, and the exact conditions BH CE's Go post-processing uses for its composite ADCS edges. Every fact here comes from the source at the commits listed below. Anything the source does not settle is marked **UNVERIFIED**.

## Pinned sources

| Repo | Commit | Base URL used in citations |
|---|---|---|
| SpecterOps/SharpHoundCommon | `de3b30af930455dbc301e219df3193dc36dda3d0` (2026-10-29) | `SHC:` = https://github.com/SpecterOps/SharpHoundCommon/blob/de3b30af930455dbc301e219df3193dc36dda3d0/ |
| SpecterOps/SharpHound | `85924979a9d23ab0e83a3fcfabee3b9962bb14be` (2026-10-16) | `SH:` = https://github.com/SpecterOps/SharpHound/blob/85924979a9d23ab0e83a3fcfabee3b9962bb14be/ |
| SpecterOps/BloodHound (CE) | `1a8806d1c42d5df4a832a628e3c828c41db6a9dd` (2026-11-04) | `BH:` = https://github.com/SpecterOps/BloodHound/blob/1a8806d1c42d5df4a832a628e3c828c41db6a9dd/ |

Main files:
- Collector: `SH:src/Runtime/ObjectProcessors.cs` (ProcessRootCA L700, ProcessAIACA L733, ProcessEnterpriseCA L764, ProcessNTAuthStore L878, ProcessCertTemplate L918, ProcessIssuancePolicy L950), `SHC:src/CommonLib/Processors/LdapPropertyProcessor.cs` (ReadRootCAProperties L485, ReadAIACAProperties L506, ReadEnterpriseCAProperties L532, ReadNTAuthStoreProperties L557, ReadCertTemplateProperties L567, ReadIssuancePolicyProperties L650), `SHC:src/CommonLib/Processors/CertAbuseProcessor.cs`, `SHC:src/CommonLib/Processors/ACLProcessor.cs`, `SHC:src/CommonLib/OutputTypes/*.cs`.
- Ingest: `BH:packages/go/ein/incoming_models.go`, `BH:packages/go/ein/ad.go`, `BH:cmd/api/src/services/graphify/convertors.go`.
- Post-processing: `BH:packages/go/analysis/ad/{adcs.go, adcscache.go, esc_shared.go, esc1.go, esc3.go, esc4.go, esc6.go, esc9.go, esc10.go, esc13.go, ntlm.go, ad.go, post.go, queries.go}`.
- Schema: `BH:packages/go/graphschema/ad/ad.go`.
- Tier Zero: `BH:cmd/api/src/database/migration/migrations/00000000000001_init.sql` (L1221–L1305, L1701–L1702).
- Real sample JSON (older collector version, v6 data format): `BH:cmd/api/src/test/fixtures/fixtures/v6/all/{certtemplates,enterprisecas,rootcas,aiacas,ntauthstores,issuancepolicies}.json`.

I read the code itself, not the SpecterOps blog or docs prose. Where this document disagrees with the docs, the code wins.

---

## 1. SharpHound CE JSON output

### 1.0 Common envelope and conventions

- Each file is `{"data":[...], "meta":{"methods":<long>, "type":"<type>", "count":<long>, "version":6, "collectorversion":"<str>"}}`. `DataVersion = 6` (`SH:src/Writers/JsonDataWriter.cs` L26, L99). Meta fields come from `SHC:src/CommonLib/OutputTypes/MetaTag.cs`.
- The `meta.type` strings come from `SHC:src/CommonLib/Enums/DataType.cs`:

| File | `meta.type` | Node kind (BH) |
|---|---|---|
| certtemplates | `certtemplates` | `CertTemplate` |
| enterprisecas | `enterprisecas` | `EnterpriseCA` |
| rootcas | `rootcas` | `RootCA` |
| aiacas | `aiacas` | `AIACA` |
| ntauthstores | `ntauthstores` | `NTAuthStore` |
| issuancepolicies | `issuancepolicies` | `IssuancePolicy` |

- Enums are serialized with Newtonsoft `StringEnumConverter` (`SH:src/Writers/JsonDataWriter.cs` L39–L45). As a result:
  - `PrincipalType` and `ObjectType` are strings: `"User"`, `"Computer"`, `"Group"`, `"CertTemplate"`, `"Base"`, `"ADLocalGroup"`, and so on (`SHC:src/CommonLib/Enums/Labels.cs`).
  - The `[Flags]` enums (`enrollmentflag`, `certificatenameflag`, CA `flags`) are comma-separated strings, for example `"INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT"`. **Do not parse ESC logic from these strings.** Use the derived booleans.
- Base object (`SHC:src/CommonLib/OutputTypes/OutputBase.cs`): `Properties` (object), `Aces` (array of ACE), `ObjectIdentifier` (string), `IsDeleted` (bool), `IsACLProtected` (bool), `ContainedBy` (TypedPrincipal or null).
  - ACE fields (`OutputTypes/ACE.cs`): `PrincipalSID`, `PrincipalType`, `RightName`, `IsInherited`, `InheritanceHash`, `IsPermissionForOwnerRightsSid`, `IsInheritedPermissionForOwnerRightsSid`.
  - TypedPrincipal fields: `ObjectIdentifier`, `ObjectType`.
- `ObjectIdentifier` for all six ADCS types is the object GUID, uppercase (see the fixtures). Well-known principals in ACEs use the `DOMAIN-S-1-5-32-544` style.
- Common `Properties` on every type:
  - From `SH:ObjectProcessors.cs` GetCommonProperties L147: `domain`, `name` (`NAME@DOMAIN`), `distinguishedname` (uppercase), `domainsid` (string).
  - From `SHC:LdapPropertyProcessor.cs` GetCommonProps L50: `objectclass` (string[]), `description` (string, only when present), `whencreated` (int, unix epoch), `objectguid`.
  - From ACL collection: `isaclprotected` (bool), `doesanyacegrantownerrights` (bool), `doesanyinheritedacegrantownerrights` (bool).
- Collection method gating (`SHC:src/CommonLib/Enums/CollectionMethod.cs` L36–L42):
  - `CertServices` is in `Default` and `DCOnly`. It covers LDAP properties, ACLs, containers, `HostingComputer` and the HTTP enrollment endpoint scan.
  - `CARegistry` (CA registry: `CARegistryData`) and `DCRegistry` (DC cert-mapping registry values used by ESC6b/9/10) are only in `All` or when requested explicitly.

### 1.1 certtemplates (`CertTemplate`, output class `SHC:OutputTypes/CertTemplate.cs`)

Top level: only the base fields. There is no `DomainSID` or `HostingComputer` at the top level.

`Properties` relevant to ESC logic (`SHC:LdapPropertyProcessor.cs` L567–L648):

| Key | JSON type | Source / derivation |
|---|---|---|
| `schemaversion` | int | `msPKI-Template-Schema-Version`. Omitted if the attribute is absent. |
| `oid` | string | `msPKI-Cert-Template-OID` |
| `displayname` | string | |
| `validityperiod`, `renewalperiod` | string (e.g. `"1 year"`) | |
| `enrollmentflag` | string (flags) | `msPKI-Enrollment-Flag` |
| `requiresmanagerapproval` | bool | `enrollmentflag & PEND_ALL_REQUESTS (0x2)` |
| `nosecurityextension` | bool | `enrollmentflag & NO_SECURITY_EXTENSION (0x80000)` |
| `certificatenameflag` | string (flags) | `msPKI-Certificate-Name-Flag` |
| `enrolleesuppliessubject` | bool | `ENROLLEE_SUPPLIES_SUBJECT (0x1)` |
| `subjectaltrequireupn` | bool | `0x02000000` |
| `subjectaltrequiredns` | bool | `0x08000000` |
| `subjectaltrequiredomaindns` | bool | `0x00400000` |
| `subjectaltrequireemail` | bool | `0x04000000` |
| `subjectaltrequirespn` | bool | `0x00800000` |
| `subjectrequireemail` | bool | `0x20000000` |
| `ekus` | string[] | `pKIExtendedKeyUsage` |
| `certificateapplicationpolicy` | string[] | `msPKI-Certificate-Application-Policy` |
| `certificatepolicy` | string[] | `msPKI-Certificate-Policy`. These are the issuance policy OIDs that ExtendedByPolicy and ESC13 use. |
| `authorizedsignatures` | int | `msPKI-RA-Signature`. Omitted if absent. |
| `applicationpolicies` | string[] | `msPKI-RA-Application-Policies`. For schema v3+ (or v4 without `USE_LEGACY_PROVIDER`), parsed from the `` Name`Type`Value `` format (L754–L774). |
| `issuancepolicies` | string[] | `msPKI-RA-Policies` (RA issuance policies, **not** the template's issuance policies) |
| `effectiveekus` | string[] | `(schemaversion == 1 && ekus.Length > 0) ? ekus : certificateapplicationpolicy` |
| `authenticationenabled` | bool | `effectiveekus` contains ClientAuth `1.3.6.1.5.5.7.3.2`, PKINIT `1.3.6.1.5.2.3.4`, SmartcardLogon `1.3.6.1.4.1.311.20.2.2` or AnyPurpose `2.5.29.37.0`, **or** `effectiveekus` is empty (`SHC:Helpers.cs` L296) |
| `schannelauthenticationenabled` | bool | `effectiveekus` contains ClientAuth or AnyPurpose, **or** is empty (`SHC:Helpers.cs` L303) |

Note: when `schemaversion` is missing it defaults to 0 in the `effectiveekus` expression.

ACE `RightName` values that SharpHound emits on templates (`SHC:ACLProcessor.cs` L886–L906, L910–L1042):
- `Owns`, `GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`
- `AllExtendedRights` (an ExtendedRight with an all or empty GUID)
- `Enroll` (Certificate-Enrollment extended right `0e10c968-78fb-11d2-90d4-00c04f79dc55`)
- `WritePKIEnrollmentFlag` (WriteProperty on `d15ef7d8-…`)
- `WritePKINameFlag` (WriteProperty on `ea1dddc4-…`)

SharpHound does not emit AutoEnroll.

```json
{"Properties":{"domain":"ESC1.LOCAL","name":"ESC1@ESC1.LOCAL","distinguishedname":"CN=ESC1,CN=CERTIFICATE TEMPLATES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=ESC1,DC=LOCAL",
  "domainsid":"S-1-5-21-909015691-3030120388-2582151266","whencreated":1664426237,"isaclprotected":false,
  "schemaversion":2,"displayname":"ESC1","oid":"1.3.6.1.4.1.311.21.8.1.2.3",
  "enrollmentflag":"INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS","requiresmanagerapproval":false,"nosecurityextension":false,
  "certificatenameflag":"ENROLLEE_SUPPLIES_SUBJECT","enrolleesuppliessubject":true,"subjectaltrequireupn":false,
  "subjectaltrequiredns":false,"subjectaltrequiredomaindns":false,"subjectaltrequireemail":false,"subjectaltrequirespn":false,"subjectrequireemail":false,
  "ekus":["1.3.6.1.5.5.7.3.2"],"certificateapplicationpolicy":["1.3.6.1.5.5.7.3.2"],"certificatepolicy":[],
  "authorizedsignatures":0,"applicationpolicies":[],"issuancepolicies":[],"effectiveekus":["1.3.6.1.5.5.7.3.2"],
  "authenticationenabled":true,"schannelauthenticationenabled":true},
 "Aces":[{"PrincipalSID":"S-1-5-21-909015691-3030120388-2582151266-513","PrincipalType":"Group","RightName":"Enroll","IsInherited":false},
         {"PrincipalSID":"S-1-5-21-909015691-3030120388-2582151266-519","PrincipalType":"Group","RightName":"Owns","IsInherited":false}],
 "ObjectIdentifier":"DEBC8BEB-40AF-48B5-940F-AAFAFE961B26","IsDeleted":false,"IsACLProtected":false,
 "ContainedBy":{"ObjectIdentifier":"95D1A36E-7782-4CC5-823C-F5994359DDC0","ObjectType":"Container"}}
```

### 1.2 enterprisecas (`EnterpriseCA`, `SHC:OutputTypes/EnterpriseCA.cs`, `CARegistryData.cs`)

Top-level fields beyond the base: `HostingComputer`, `CARegistryData`, `EnabledCertTemplates`, `HttpEnrollmentEndpoints`.

- `HostingComputer` (string SID). This is `dnshostname` resolved to a computer SID, and it is set only if the SID starts with `S-1-` (`SH:ObjectProcessors.cs` L797–L805, L826–L836).
- **There is no top-level `DomainSID` on EnterpriseCA in SharpHoundCommon.** The BH `ein.EnterpriseCA` struct has one, but it would be empty. BH reads the CA's domain from `Properties.domainsid`.
- `EnabledCertTemplates`: TypedPrincipal[] (`ObjectType: "CertTemplate"`). Built from `certificateTemplates`, which are CNs resolved to template GUIDs. CNs that fail to resolve go into `Properties.unresolvedpublishedtemplates` (string[]).
- `HttpEnrollmentEndpoints`: array of `APIResult<CAEnrollmentEndpoint>`:
  - Each entry is `{Collected, FailureReason, Result:{Url, Type, Status, ADCSWebEnrollmentHTTP, ADCSWebEnrollmentHTTPS, ADCSWebEnrollmentEPA}}`.
  - Sources: `SHC:OutputTypes/CAHttpEndpoint.cs` and `APIResult.cs`.
  - BH uses these to set `hasvulnerableendpoint`, `httpenrollmentendpoints` and `httpsenrollmentendpoints` (`BH:packages/go/ein/ad.go` ConvertEnterpriseCAToNode L187).
- `CARegistryData` (present only with the `CARegistry` method) contains four results:
  - `CASecurity`: `{Collected: bool, FailureReason: string|null, Data: ACE[]}`. ACEs come from the CA registry `Security` value. The owner becomes an `Owns` ACE, and the access-mask bits become `ManageCA`, `ManageCertificates` and `Enroll`. Deny ACEs are skipped. Local principals become `ADLocalGroup` with the SID `<computerSID>-<RID>` (`SHC:CertAbuseProcessor.cs` ProcessRegistryEnrollmentPermissions).
  - `EnrollmentAgentRestrictions`: `{Collected, FailureReason, Restrictions: [{AccessType: "AccessAllowedCallback"|"AccessDeniedCallback", Agent: TypedPrincipal, Targets: TypedPrincipal[], Template: TypedPrincipal|null, AllTemplates: bool}]}`. The source is the registry `EnrollmentAgentRights` value (`CertAbuseProcessor.cs` CreateEnrollmentAgentRestriction).
  - `IsUserSpecifiesSanEnabled`: `{Collected, FailureReason, Value: bool}`. Value is `EditFlags & 0x00040000` (EDITF_ATTRIBUTESUBJECTALTNAME2).
  - `RoleSeparationEnabled`: `{Collected, FailureReason, Value: bool}`. Value is registry `RoleSeparationEnabled == 1`.

`Properties`:

| Key | JSON type | Notes |
|---|---|---|
| `flags` | string (flags) | e.g. `"SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED"` |
| `caname` | string | |
| `dnshostname` | string | |
| `certthumbprint` | string | Uppercase SHA-1 hex (X509Certificate2.Thumbprint) |
| `certname` | string | |
| `certchain` | string[] | Thumbprints, built with X509Chain **on the collector host**. `[0]` is the CA itself and `[1]` is its issuer. |
| `hasbasicconstraints` | bool | |
| `basicconstraintpathlength` | int | |
| `unresolvedpublishedtemplates` | string[] | |
| `casecuritycollected`, `enrollmentagentrestrictionscollected`, `isuserspecifiessanenabledcollected`, `roleseparationenabledcollected` | bool | Added only when `CARegistry` ran (`SH:ObjectProcessors.cs` L870–L873) |

BH also adds the following when it parses `CARegistryData` (`BH:packages/go/ein/ad.go` ParseCARegistryProperties L1309):
- `hasenrollmentagentrestrictions` (bool, true if `Restrictions` is non-empty, **including Deny entries**). Only when `Collected`.
- `isuserspecifiessanenabled` (bool). Only when `Collected`.
- `roleseparationenabled` (bool). Only when `Collected`.

ACE `RightName` values on the CA object DACL (`SHC:ACLProcessor.cs` L1044–L1092):
- The generic ones: `Owns`, `GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`
- `Enroll` (extended right or CA access-mask bit)
- `ManageCA`
- `ManageCertificates`

```json
{"Properties":{"domain":"ESC1.LOCAL","name":"ESC1-DC-CA@ESC1.LOCAL","domainsid":"S-1-5-21-909015691-3030120388-2582151266",
  "distinguishedname":"CN=ESC1-DC-CA,CN=ENROLLMENT SERVICES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=ESC1,DC=LOCAL",
  "flags":"SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED","caname":"ESC1-DC-CA","dnshostname":"ESC1-DC.ESC1.LOCAL",
  "certthumbprint":"5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703","certname":"5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703",
  "certchain":["5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703"],"hasbasicconstraints":false,"basicconstraintpathlength":0,
  "unresolvedpublishedtemplates":[],"casecuritycollected":true,"enrollmentagentrestrictionscollected":true,
  "isuserspecifiessanenabledcollected":true,"roleseparationenabledcollected":true},
 "HostingComputer":"S-1-5-21-909015691-3030120388-2582151266-1000",
 "CARegistryData":{
  "CASecurity":{"Collected":true,"FailureReason":null,"Data":[
     {"PrincipalSID":"ESC1.LOCAL-S-1-5-32-544","PrincipalType":"Group","RightName":"Owns","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-909015691-3030120388-2582151266-512","PrincipalType":"Group","RightName":"ManageCA","IsInherited":false},
     {"PrincipalSID":"ESC1.LOCAL-S-1-5-11","PrincipalType":"Group","RightName":"Enroll","IsInherited":false}]},
  "EnrollmentAgentRestrictions":{"Collected":true,"FailureReason":null,"Restrictions":[
     {"AccessType":"AccessAllowedCallback","Agent":{"ObjectIdentifier":"S-1-5-21-909015691-3030120388-2582151266-513","ObjectType":"Group"},
      "Targets":[{"ObjectIdentifier":"S-1-5-21-909015691-3030120388-2582151266-513","ObjectType":"Group"}],"Template":null,"AllTemplates":true}]},
  "IsUserSpecifiesSanEnabled":{"Collected":true,"FailureReason":null,"Value":false},
  "RoleSeparationEnabled":{"Collected":true,"FailureReason":null,"Value":false}},
 "EnabledCertTemplates":[{"ObjectIdentifier":"DEBC8BEB-40AF-48B5-940F-AAFAFE961B26","ObjectType":"CertTemplate"}],
 "HttpEnrollmentEndpoints":[{"Collected":true,"FailureReason":null,"Result":{"Url":"http://esc1-dc.esc1.local/certsrv/","Type":"WebEnrollmentApplication","Status":"Vulnerable_NtlmHttpEndpoint","ADCSWebEnrollmentHTTP":true,"ADCSWebEnrollmentHTTPS":false,"ADCSWebEnrollmentEPA":false}}],
 "Aces":[{"PrincipalSID":"S-1-5-21-909015691-3030120388-2582151266-519","PrincipalType":"Group","RightName":"Owns","IsInherited":false}],
 "ObjectIdentifier":"14CEE53E-4D95-4DDD-A244-BF15C73DC06A","IsDeleted":false,"IsACLProtected":false,
 "ContainedBy":{"ObjectIdentifier":"…","ObjectType":"Container"}}
```

**UNVERIFIED:** the exact `HttpEnrollmentEndpoints` sample values. The field names and types come from `CAHttpEndpoint.cs`. The values above are illustrative.

### 1.3 rootcas (`RootCA`, `SHC:OutputTypes/RootCA.cs`)

- Top level: the base fields plus **`DomainSID`** (string). It is set to the collecting domain's SID (`SH:ObjectProcessors.cs` L700–L704).
- `Properties`: `certthumbprint`, `certname`, `certchain` (string[]), `hasbasicconstraints`, `basicconstraintpathlength`, plus the common keys (L485).
- ACEs: generic AD rights only.

```json
{"Properties":{"domain":"ESC1.LOCAL","name":"ESC1-DC-CA@ESC1.LOCAL","domainsid":"S-1-5-21-909015691-3030120388-2582151266",
  "distinguishedname":"CN=ESC1-DC-CA,CN=CERTIFICATION AUTHORITIES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=ESC1,DC=LOCAL",
  "certthumbprint":"5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703","certname":"5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703",
  "certchain":["5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703"],"hasbasicconstraints":false,"basicconstraintpathlength":0},
 "DomainSID":"S-1-5-21-909015691-3030120388-2582151266",
 "Aces":[{"PrincipalSID":"S-1-5-21-909015691-3030120388-2582151266-517","PrincipalType":"Group","RightName":"GenericAll","IsInherited":false}],
 "ObjectIdentifier":"4B5183E1-DB57-4A57-8159-3E9649F3B01C","IsDeleted":false,"IsACLProtected":false,
 "ContainedBy":{"ObjectIdentifier":"242AB0E0-13D1-4517-BEB0-07E504802B6B","ObjectType":"Container"}}
```

### 1.4 aiacas (`AIACA`, `SHC:OutputTypes/AIACA.cs`)

- Top level: base fields only. There is **no** `DomainSID`.
- `Properties`: `crosscertificatepair` (array; the fixture shows `[]`), `hascrosscertificatepair` (bool), `certthumbprint`, `certname`, `certchain`, `hasbasicconstraints`, `basicconstraintpathlength` (L506).

```json
{"Properties":{"domain":"ESC1.LOCAL","name":"ESC1-DC-CA@ESC1.LOCAL","domainsid":"S-1-5-21-909015691-3030120388-2582151266",
  "distinguishedname":"CN=ESC1-DC-CA,CN=AIA,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=ESC1,DC=LOCAL",
  "crosscertificatepair":[],"hascrosscertificatepair":false,"certthumbprint":"5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703",
  "certname":"5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703","certchain":["5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703"],
  "hasbasicconstraints":false,"basicconstraintpathlength":0},
 "Aces":[],"ObjectIdentifier":"6345151F-D854-4D83-B7D0-D94E10CFBAF2","IsDeleted":false,"IsACLProtected":false,
 "ContainedBy":{"ObjectIdentifier":"D44AC8AF-C24E-489B-B0BB-E832A5E3C91A","ObjectType":"Container"}}
```

### 1.5 ntauthstores (`NTAuthStore`, `SHC:OutputTypes/NTAuthStore.cs`)

- Top level: the base fields plus **`DomainSID`** (string, the collecting domain).
- `Properties`: `certthumbprints` (string[]; uppercase thumbprints of every cert in the `cACertificate` attribute) plus the common keys (`SH:ObjectProcessors.cs` L900–L906).

```json
{"Properties":{"domain":"ESC1.LOCAL","name":"NTAUTHCERTIFICATES@ESC1.LOCAL","domainsid":"S-1-5-21-909015691-3030120388-2582151266",
  "distinguishedname":"CN=NTAUTHCERTIFICATES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=ESC1,DC=LOCAL",
  "certthumbprints":["5F0143662A7EA16E8DB90E44D0F1F1FC87B1E703"],"whencreated":1664426237},
 "DomainSID":"S-1-5-21-909015691-3030120388-2582151266",
 "Aces":[{"PrincipalSID":"ESC1.LOCAL-S-1-5-32-544","PrincipalType":"Group","RightName":"GenericAll","IsInherited":false}],
 "ObjectIdentifier":"722A8BB3-AEF5-49C7-9C8C-C1C97A219007","IsDeleted":false,"IsACLProtected":false,
 "ContainedBy":{"ObjectIdentifier":"A18A3A99-3E4C-46DD-9C90-E5542FA4EC84","ObjectType":"Container"}}
```

### 1.6 issuancepolicies (`IssuancePolicy`, `SHC:OutputTypes/IssuancePolicy.cs`)

- Top level: the base fields plus **`GroupLink`** (TypedPrincipal). It defaults to an empty object, which serializes as `{"ObjectIdentifier":null,"ObjectType":"Base"}`.
- `Properties` (L650):
  - `displayname`
  - `certtemplateoid` (string; `msPKI-Cert-Template-OID`, the policy OID)
  - `oidgrouplink` (string SID; only if `msDS-OIDToGroupLink` resolves)
- BH also sets `grouplinkid` (`BH:convertors.go` convertIssuancePolicy L309–L330).

```json
{"Properties":{"domain":"TESTLAB.LOCAL","name":"LOW ASSURANCE@TESTLAB.LOCAL","domainsid":"S-1-5-21-318463681-1533741871-3192839656",
  "distinguishedname":"CN=400.031E754FE9CE51DB698FA6F04E181946,CN=OID,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,DC=TESTLAB,DC=LOCAL",
  "displayname":"Low Assurance","certtemplateoid":"1.3.6.1.4.1.311.21.8.13791726.4349508.5000099.2617275.11656885.78.1.400",
  "oidgrouplink":"S-1-5-21-318463681-1533741871-3192839656-1105"},
 "GroupLink":{"ObjectIdentifier":"S-1-5-21-318463681-1533741871-3192839656-1105","ObjectType":"Group"},
 "Aces":[],"ObjectIdentifier":"8A0CF606-AED8-44B1-A336-1A3A9E37D10B","IsDeleted":false,"IsACLProtected":false,
 "ContainedBy":{"ObjectIdentifier":"42EE71D2-445E-4B4C-A327-EFBBB1DEB54E","ObjectType":"Container"}}
```

### 1.7 DC-side properties the ESCs depend on (computers.json, `DCRegistry`)

These are read by ESC6b, ESC9 and ESC10 (`BH:ein/ad.go` ParseDCRegistryData L1539):
- `certificatemappingmethodsraw` (int; −1 means the registry value does not exist). This is Schannel `CertificateMappingMethods`, where `0x4` is UPN mapping.
- `strongcertificatebindingenforcementraw` (int; −1 means it does not exist, 0 is disabled, 1 is compatibility, 2 is full).

They come from `Computer.DCRegistryData.{CertificateMappingMethods, StrongCertificateBindingEnforcement}.{Collected, Value}`. User nodes also need `gmsa` and `msa` (bool), which the DNS-SAN filter uses.

---

## 2. Structural edges (ingest-time and post-processed)

Ingest-time edges are created in `BH:packages/go/ein/ad.go` and `BH:cmd/api/src/services/graphify/convertors.go`. Post-processed structural edges are created in `BH:packages/go/analysis/ad/esc_shared.go` and `esc3.go` through `PostADCS` (`adcs.go` L40).

| Edge | Direction | Created | Exact rule |
|---|---|---|---|
| `PublishedTo` | CertTemplate → EnterpriseCA | ingest | One edge per `EnterpriseCA.EnabledCertTemplates[i]` (ein/ad.go ParseEnterpriseCAMiscData L1339). |
| `HostsCAService` | Computer → EnterpriseCA | ingest | Created if `HostingComputer != ""` (L1375). |
| `DelegatedEnrollmentAgent` | Restriction.Agent (any kind) → CertTemplate | ingest | Only when `EnrollmentAgentRestrictions.Collected`, and only for restrictions with `AccessType == "AccessAllowedCallback"`. Target is `Template`, or **every** `EnabledCertTemplates` entry of that CA when `AllTemplates`. `Targets` is ignored (L1386–L1420). |
| `RootCAFor` | RootCA → Domain | ingest | Created if the top-level `RootCA.DomainSID != ""`; the target is the domain with that SID (L1461). |
| `NTAuthStoreFor` | NTAuthStore → Domain | ingest | Created if the top-level `NTAuthStore.DomainSID != ""` (L1487). |
| `OIDGroupLink` | IssuancePolicy → Group (GroupLink kind) | ingest | Created if `GroupLink.ObjectIdentifier != ""` (convertors.go L311–L326). |
| `Contains` | container → ADCS object | ingest | From `ContainedBy` (ParseObjectContainer). |
| ACL edges (`Enroll`, `ManageCA`, `ManageCertificates`, `WritePKIEnrollmentFlag`, `WritePKINameFlag`, `GenericAll`, …) | principal → object | ingest | `ParseACEData`. ACEs whose PrincipalSID equals the target are skipped. Owns becomes `OwnsRaw` or `OwnsLimitedRights`, and WriteOwner becomes `WriteOwnerRaw` or `WriteOwnerLimitedRights`; these are post-processed later into `Owns`/`WriteOwner` (L455+, `owns.go`). |
| `TrustedForNTAuth` | EnterpriseCA → NTAuthStore | post step 1 | For each NTAuthStore and each non-empty thumbprint in `certthumbprints`: an edge from **every EnterpriseCA** whose `certthumbprint` equals it (esc_shared.go L42). |
| `IssuedSignedBy` | (EnterpriseCA\|RootCA\|AIACA) → (EnterpriseCA\|RootCA\|AIACA) | post step 1 | For each ECA, RootCA and AIACA with `len(certchain) > 1`: edges to every ECA, RootCA or AIACA node whose `certthumbprint == certchain[1]`. Only the direct parent is linked; a self-signed node (`len == 1`) gets no edge (L107, L412). |
| `EnterpriseCAFor` | EnterpriseCA → RootCA and EnterpriseCA → AIACA | post step 1 | Edge to each RootCA and each AIACA whose `certthumbprint` equals the ECA's `certthumbprint`, i.e. the same certificate published in several containers (L149). |
| `ExtendedByPolicy` | CertTemplate → IssuancePolicy | post step 1 | For each template OID in `certificatepolicy` and each IssuancePolicy with `certtemplateoid == oid` **and** the same non-empty `domainsid` (L324). |
| `EnrollOnBehalfOf` | CertTemplate (agent) → CertTemplate (target) | post step 2 | See §3.3 (esc3.go L164). |

**Enterprise CA ACL merge** (`ein/ad.go` handleEnterpriseCASecurity L1422):
- When `CASecurity.Collected`, edges are built from `CASecurity.Data` minus ACEs with `PrincipalType == "LocalGroup"` minus `Owns`, plus the object DACL `Aces` minus `ManageCA`, `ManageCertificates` and `Enroll`. The exception is that ACEs where `PrincipalSID == HostingComputer` are kept. The intent is that the registry is authoritative for CA rights.
- **Caveat from reading the code:** `convertEnterpriseCAData` (`convertors.go` L276–L281) *also* calls `ParseACEData` on the raw `enterpriseca.Aces`, unfiltered. As written, DACL-derived `Enroll`/`ManageCA`/`ManageCertificates` edges are therefore created as well, so the graph holds the union.
- **UNVERIFIED:** whether this is intended. It is not covered by a test I checked.
- Also: the filter compares against the string `"LocalGroup"`, while SharpHound emits `"ADLocalGroup"`. **UNVERIFIED** whether the BH `parseADKind`/label mapping makes those equal; I did not trace it.

### Chain validity: the prerequisite for every ESC edge

The cache is built in `adcscache.go` BuildCache (L174), using `queries.go` L1844 and L1896. For each Domain D:

```
rootCAForChainValid[D] = { eca : EnterpriseCA |
   (eca)-[IssuedSignedBy|EnterpriseCAFor]->(EnterpriseCA|AIACA)* ... -[IssuedSignedBy|EnterpriseCAFor]->(RootCA)-[RootCAFor]->(D) }
   // inbound acyclic traversal from D; depth 1 must be RootCAFor from a RootCA; deeper hops must be
   // IssuedSignedBy/EnterpriseCAFor and the *traversed-into* node must be EnterpriseCA or AIACA;
   // nodes collected are EnterpriseCA. Arbitrary depth.
authStoreForChainValid[D] = { eca | (eca)-[TrustedForNTAuth]->(:NTAuthStore)-[NTAuthStoreFor]->(D) }   // exactly 2 hops
```

**UNVERIFIED** detail on the RootCA query: the DescentFilter checks `segment.Node` kinds (EnterpriseCA or AIACA) for hops beyond depth 1. From reading it, the hop *from* the RootCA *to* the next node must land on an EnterpriseCA or AIACA, which matches the pattern above.

For each EnterpriseCA E, using `GetECAHostedChainedDomains` (L555):
- E must have a **qualifying host** (L432–L540). That means some `(c:Computer)-[:HostsCAService]->(E)` where `c.enabled == true`.
- When E's forest is resolvable, `c.domainsid` must also map to a Domain inside E's forest. E's forest is the domain matching `E.domainsid` plus its inbound `SameForestTrust` closure.
- If E's forest cannot be resolved (the domainsid is missing or there is no matching domain), any enabled host qualifies.
- `E.Domains = { D : E ∈ rootCAForChainValid[D] ∧ E ∈ authStoreForChainValid[D] }`. If this set is empty, E is skipped.

The composite edges below are computed **per E** for E's `Domains`, all in `processEnterpriseCAWithValidCertChainToDomain` (adcs.go L189).

---

## 3. Composite edge conditions

### 3.0 Shared primitives (read these first)

**Principal sets** (adcscache.go BuildCache L196–L292). These are all first-degree incoming edges, with the start node of kind `Base`/Entity:
- `TemplateEnrollers(T)` = sources of `Enroll` ∪ `GenericAll` ∪ `AllExtendedRights` → T
- `TemplateControllers(T)` = `Owns` ∪ `GenericAll` ∪ `WriteDACL` ∪ `WriteOwner` → T
- `TemplateGenericWriters(T)` = `GenericWrite`
- `TemplateEnrollOrAER(T)` = `Enroll` ∪ `AllExtendedRights` (not GenericAll)
- `TemplateWritePKINameFlag(T)` and `TemplateWritePKIEnrollmentFlag(T)`
- `CAEnrollers(E)` = sources of **`Enroll` only** → E. GenericAll or ManageCA on the CA does not count.
- `Published(E)` = templates with `PublishedTo` → E

**Special groups** are Group nodes whose `objectid` ends with `S-1-5-11` (Authenticated Users) or `S-1-1-0` (Everyone), across all domains (`queries.go` FetchAuthUsersAndEveryoneGroups L1994). They are `LocalGroupData.ExcludedShortcutGroups` (post.go L790).

**`CalculateCrossProductNodeSets(S1..Sn)`** (`ad.go` L528; design note in `CalculateCrossProductNodeSetsDoc.md`) returns the principals that hold *all* the rights, with group shortcutting:

```
for each set Si:
   Si is "excluded" (treated as satisfied by everybody) if
      Si directly contains a special group, OR
      any group in Si has a special group in its transitive membership (MemberOf/MemberOfLocalGroup reach)
   else unrolled(Si) = Si ∪ all transitive members of groups in Si
nonExcluded = [Si not excluded]
if |nonExcluded| == 0: return ∪ Si (first-degree principals of all sets)
if |nonExcluded| == 1: return first-degree principals of that one set
ref = nonExcluded[0] (first-degree); check = ∩_{i≥1} unrolled(nonExcluded[i])
result = { p ∈ ref : p ∈ check }
for p ∈ ref \ check: candidates += transitive members of p
  process candidate groups by ascending member count:
     if group ∈ check: emit group, drop its members from candidates
     else: drop group only
emit remaining non-group candidates ∈ check
```

So the edge is emitted from the **highest principal that holds every right**, usually a group, not from every expanded member. The **order of the sets matters**, because the first non-excluded set is the reference that sources come from. Nodes are emitted with whatever kind they have (User, Computer, Group, LocalGroup, …).

**Victim expansion for ESC9/ESC10/ESC8** (`getVictimBitmap`, esc_shared.go L553). There is no shortcutting here: groups are fully expanded to non-Group members (`expandCachedPrincipalsToBitmapWithoutGroups` L448).

```
T = expand(TemplateEnrollers), C = expand(CAEnrollers)
specialT = containsAuthUsersOrEveryone(TemplateEnrollers); specialC = same for CAEnrollers
   // special = a set member IS AU/Everyone, OR AU/Everyone has a direct (1-hop) MemberOf edge into a group in the set (L472)
if !specialT && !specialC: victims = T ∩ C
else victims = (specialT ? C : ∅) ∪ (specialC ? T : ∅)
```

**DNS-SAN user filter** (`filterUserDNSResults`, L509–L551):
- If the template's `subjectaltrequiredns == true` **or** `subjectaltrequiredomaindns == true` (a missing property also counts as "requires DNS"), then every `User` node is removed **unless** `gmsa == true` or `msa == true`.
- Groups and Computers are kept.

**Template validity: the "signature" clause** used by almost every ESC is `!(schemaversion > 1 && authorizedsignatures > 0)`. Both properties must exist, otherwise the template is rejected; numbers are read as float64. A missing required boolean also rejects the template (`logPropertyLookupFailure`).

**Forest-level DC checks** (adcscache.go L788 and L816) are evaluated over the domains in `FetchNodesWithSameForestTrustRelationship(D)` (queries.go L1749). That is D's inbound `SameForestTrust` traversal closure, or D alone if there are no edges. "DCs" means `(c:Computer)-[:DCFor]->(domain)`.
- `HasUPNCertMappingInForest(D)`: some DC has `certificatemappingmethodsraw != -1` with `& 0x4`.
- `HasWeakCertBindingInForest(D)`: some DC has `strongcertificatebindingenforcementraw ∈ {0, 1, -1}`. A missing property means the DC is skipped.

### 3.1 GoldenCert (`esc_shared.go` PostGoldenCert L208)

- Source: every **qualifying host** Computer of E. That is `HostsCAService` → E, where the computer is enabled and in-forest when resolvable.
- Target: each Domain in `E.Domains`.
- There are no template or rights conditions.

### 3.2 ADCSESC1 (`esc1.go` L34)

```
for T in Published(E) where validESC1(T):
    src ∪= CrossProduct(TemplateEnrollers(T), CAEnrollers(E))
emit src -[ADCSESC1]-> each D in E.Domains
validESC1(T): requiresmanagerapproval==false ∧ authenticationenabled==true ∧ enrolleesuppliessubject==true
              ∧ !(schemaversion>1 ∧ authorizedsignatures>0)
```

There is no DNS-SAN user filter for ESC1.

### 3.3 EnrollOnBehalfOf and ADCSESC3 (`esc3.go` L36, L164)

`EnrollOnBehalfOf` (agent CT1 → target CT2):
- For every pair of hosted, chained ECAs (Ea, Et) whose `Domains` intersect, take CT1 ∈ Published(Ea) and CT2 ∈ Published(Et). Duplicate edges are suppressed.
- When CT2 has `schemaversion >= 2`: CT1's `effectiveekus` does **not** contain `2.5.29.37.0` **and** does contain `1.3.6.1.4.1.311.20.2.1` (CertRequestAgent), CT1 ≠ CT2, CT2 `authorizedsignatures == 1`, **and** CT2's `applicationpolicies` contains `1.3.6.1.4.1.311.20.2.1`.
- When CT2 has `schemaversion == 1`: CT1's `effectiveekus` is empty, **or** contains CertRequestAgent, **or** contains AnyPurpose.

ADCSESC3 (computed with E as eca2):

```
hasEAR = E.enrollmentagentrestrictionscollected==true ∧ E.hasenrollmentagentrestrictions==true
for CT2 in Published(E) where CT2.authenticationenabled==true ∧ CT2.requiresmanagerapproval==false:
  for CT1 with (CT1)-[EnrollOnBehalfOf]->(CT2) where
        CT1.requiresmanagerapproval==false ∧ (CT1.schemaversion==1 ∨ (CT1.schemaversion>1 ∧ CT1.authorizedsignatures==0)):
    if hasEAR: agents = first-degree sources of DelegatedEnrollmentAgent -> CT2; if empty: skip
    for eca1 in CAs that CT1 is PublishedTo, where eca1 has a qualifying host:
       sets = [TemplateEnrollers(CT1), TemplateEnrollers(CT2), CAEnrollers(eca1), CAEnrollers(E)] (+ agents if hasEAR)
       r = DNSUserFilter(CrossProduct(sets...), CT1)
       for D in E.Domains where eca1 is chain-valid for D (RootCAFor ∧ NTAuth): src[D] ∪= r
emit src[D] -[ADCSESC3]-> D
```

- `DelegatedEnrollmentAgent` is checked per template, not per CA. Any CA's restriction that targets CT2 counts (code-level observation).
- Deny restrictions are not subtracted.

### 3.4 ADCSESC4 (`esc4.go` L34)

For each T ∈ Published(E), with `CE = CAEnrollers(E)`:

```
a) CrossProduct(CE, TemplateControllers(T))                                  // no template property checks
b) CrossProduct(CE, TemplateGenericWriters(T), TemplateEnrollOrAER(T))       // no template property checks
   -- then require validESC4(T): authenticationenabled==true ∧ !(schemaversion>1 ∧ authorizedsignatures>0)
d) CrossProduct(CE, EnrollOrAER(T), WritePKINameFlag(T), WritePKIEnrollmentFlag(T))
e) if T.enrolleesuppliessubject:      CrossProduct(CE, EnrollOrAER(T), WritePKIEnrollmentFlag(T))
f) if !T.requiresmanagerapproval:     CrossProduct(CE, EnrollOrAER(T), WritePKINameFlag(T))
emit union -[ADCSESC4]-> each D in E.Domains
```

Templates missing `enrolleesuppliessubject` or `requiresmanagerapproval` are skipped entirely, including (a) and (b). There is no DNS-SAN user filter.

**Ordering caveat** (`post.go` Post L971–L1009): `PostADCS` runs **before** `PostOwnsAndWriteOwner`. Ingest only creates `OwnsRaw` and `WriteOwnerRaw`, so on a fresh database the `Owns`/`WriteOwner` members of `TemplateControllers` (and of the ESC9/ESC10 attacker edges) come only from a previous analysis run's post-processed edges. **UNVERIFIED** whether this is intended. A reimplementation should resolve Owns/WriteOwner first.

### 3.5 ADCSESC6a / ADCSESC6b (`esc6.go` L35, L82)

CA requirement for both: `isuserspecifiessanenabledcollected == true` ∧ `isuserspecifiessanenabled == true`. If either property is missing, the function returns an error and no edges are created for that CA.

```
for T in Published(E) where validESC6(T, b):
    r = DNSUserFilter(CrossProduct(TemplateEnrollers(T), CAEnrollers(E)), T)
    6a: emit r -> each D in E.Domains
    6b: emit r -> each D in E.Domains where HasUPNCertMappingInForest(D)
validESC6 common: requiresmanagerapproval==false ∧ !(schemaversion>1 ∧ authorizedsignatures>0)
   6a: ∧ nosecurityextension==true ∧ authenticationenabled==true
   6b: ∧ schannelAuthenticationEnabled(T)
schannelAuthenticationEnabled(T) = T.schannelauthenticationenabled if present,
   else effectiveekus ∋ 1.3.6.1.5.5.7.3.2 ∨ ∋ 2.5.29.37.0 ∨ empty      (esc_shared.go L580)
```

ESC6a does **not** check DC strong certificate binding in code. Neither the function nor its composition query has such a check.

### 3.6 ADCSESC9a / ADCSESC9b (`esc9.go` L34, L87)

These skip E entirely if `CAEnrollers(E)` is empty, and skip any T whose `TemplateEnrollers(T)` is empty.

```
for T in Published(E) where validESC9(T, b):
    victims = getVictimBitmap(TemplateEnrollers(T), CAEnrollers(E), specialT, specialC)
    9a: victims = DNSUserFilter(victims, T)
    attackers = { s : (s:Group|User|Computer)-[R]->(v), v ∈ victims }      // first-degree only (queries.go L1966)
        9a: R ∈ {GenericAll, GenericWrite, Owns, WriteOwner, WriteDACL, WritePublicInformation}
        9b: R ∈ {GenericAll, GenericWrite, Owns, WriteOwner, WriteDACL} and v must be :Computer
emit attackers -> each D in E.Domains where HasWeakCertBindingInForest(D)
validESC9: requiresmanagerapproval==false ∧ authenticationenabled==true ∧ nosecurityextension==true
           ∧ enrolleesuppliessubject==false ∧ !(schemaversion>1 ∧ authorizedsignatures>0)
   9a: ∧ (subjectaltrequireupn ∨ subjectaltrequirespn)
   9b: ∧ subjectaltrequiredns
```

Sources are the principals holding the write right on a victim. There is no group expansion for attackers.

### 3.7 ADCSESC10a / ADCSESC10b (`esc10.go` L35, L92)

These use the same victim, attacker and emptiness logic as ESC9, including the 10a DNS filter and the 10b Computer-only victims and rights set. The domain condition is `HasUPNCertMappingInForest(D)` instead of weak binding.

```
validESC10: requiresmanagerapproval==false ∧ schannelAuthenticationEnabled(T) ∧ enrolleesuppliessubject==false
            ∧ !(schemaversion>1 ∧ authorizedsignatures>0)
   10a: ∧ (subjectaltrequireupn ∨ subjectaltrequirespn)
   10b: ∧ subjectaltrequiredns
```

ESC10 does not require `nosecurityextension`.

### 3.8 ADCSESC13 (`esc13.go` L34). Target is a **Group**, not a Domain.

```
for T in Published(E) where validESC13(T):
    G = { g : (T)-[ExtendedByPolicy]->(:IssuancePolicy)-[OIDGroupLink]->(g:Group) }; skip if empty
    r = DNSUserFilter(CrossProduct(CAEnrollers(E), TemplateEnrollers(T)), T)
    for g in G, D in E.Domains where groupIsContainedOrTrusted(g, D): emit r -[ADCSESC13]-> g
validESC13: requiresmanagerapproval==false ∧ authenticationenabled==true ∧ !(schemaversion>1 ∧ authorizedsignatures>0)
groupIsContainedOrTrusted(g, D): inbound traversal from g over Contains|SameForestTrust until a Domain is reached;
   true if D is that domain or is reached from it through a contiguous chain of Domain nodes
   (≈ (D)-[:Contains|SameForestTrust*]->(g), as in the composition comment)
```

Note the set order here: CAEnrollers comes first, so CA enrollers are the reference set unless they are excluded (for example, Authenticated Users holds Enroll).

### 3.9 CoerceAndRelayNTLMToADCS (ESC8; `ntlm.go` L408). This is the only other ADCS composite in BH CE.

- It runs only when the NTLM post-processing feature flag is on (`analysis.go` L292–L300).
- For each hosted, chained E with `hasvulnerableendpoint == true`, and each T ∈ Published(E) with `requiresmanagerapproval == false` ∧ `authenticationenabled == true` ∧ (`schemaversion <= 1` ∨ `authorizedsignatures == 0`):
  - `victims = getVictimBitmap(...) ∩ UnprotectedComputers`.
  - UnprotectedComputers (ntlm.go L62–L127): computers with `restrictoutboundntlm == false` (a missing property excludes the computer) and not in Protected Users, unless the domain functional level is vulnerable.
- Edge: the **Authenticated Users group of each D ∈ E.Domains** → each victim Computer.

### 3.10 Newer ESCs

The graph schema (`BH:packages/go/graphschema/ad/ad.go` L104–L120) defines no `ADCSESC15`, ESC2, ESC5, ESC7 or ESC11+ kinds; a repository grep confirms this. The full set is: GoldenCert, ESC1, ESC3, ESC4, ESC6a/b, ESC9a/b, ESC10a/b, ESC13, plus CoerceAndRelayNTLMToADCS (ESC8).

### 3.11 Traversability (`graphschema/ad/ad.go` PathfindingRelationships L1199)

- **Traversable:**
  - `GoldenCert`, `ADCSESC1`, `ADCSESC3`, `ADCSESC4`, `ADCSESC6a`, `ADCSESC6b`, `ADCSESC9a`, `ADCSESC9b`, `ADCSESC10a`, `ADCSESC10b`, `ADCSESC13`
  - `CoerceAndRelayNTLMToADCS`, `ManageCA`, `ManageCertificates`
  - The generic ACL edges and `Contains`
- **Not traversable** (present in `Relationships()` but absent from pathfinding):
  - `Enroll`, `PublishedTo`, `HostsCAService`, `RootCAFor`, `NTAuthStoreFor`, `TrustedForNTAuth`, `EnterpriseCAFor`, `IssuedSignedBy`
  - `EnrollOnBehalfOf`, `DelegatedEnrollmentAgent`, `ExtendedByPolicy`, `OIDGroupLink`
  - `WritePKIEnrollmentFlag`, `WritePKINameFlag`
- All composite ESC edges use delta-change-apply sinks. Stale edges are deleted when the conditions no longer hold (`adcs.go` L115–L128).

---

## 4. Tier Zero defaults for ADCS

The default selectors are seeded in `BH:cmd/api/src/database/migration/migrations/00000000000001_init.sql` L1221–L1305. The columns are `(name, enabled, allow_disable, cypher, …)`, and all rows have `is_default = true`.

| Selector name | Cypher | Seeded `enabled` |
|---|---|---|
| Enterprise CA Computers | `MATCH (n:Computer)-[:HostsCAService]->(:EnterpriseCA) RETURN n` | false (`allow_disable=true`) |
| Enterprise CA (AD object) | `MATCH (n:EnterpriseCA) RETURN n` | false |
| Root CA object | `MATCH (n:RootCA) RETURN n` | false |
| AIA CA (AD object) | `MATCH (n:AIACA) RETURN n` | false |
| NTAuth store | `MATCH (n:NTAuthStore) RETURN n` | false |
| Certificate template | `MATCH (n:CertTemplate) RETURN n` | false |
| Cert Publishers (group, `-517`) | `MATCH (n:Group) WHERE n.objectid ENDS WITH '-517'` | false |

- **IssuancePolicy has no Tier Zero selector.**
- On **freshly bootstrapped** instances, L1701–L1702 runs `UPDATE asset_group_tag_selectors SET disabled_at = NULL … WHERE is_default = true AND created_at > now() - 7 min`. That enables all default selectors, so on a new install all of the above are Tier Zero.
- On **upgraded** instances they stay disabled. The legacy hard-coded Tier Zero set (`analysis/ad/ad.go` FetchWellKnownTierZeroEntities L72, TierZeroWellKnownSIDSuffixes) contains no ADCS objects.
- Recommended default for CopperHound, matching a fresh BH CE: EnterpriseCA, RootCA, AIACA, NTAuthStore, CertTemplate, the HostsCAService computers, and Cert Publishers.

---

## 5. Implementation checklist for CopperHound (derived, not from the BloodHound source)

1. Structural pass:
   1. Ingest-time edges.
   2. TrustedForNTAuth, IssuedSignedBy, EnterpriseCAFor and ExtendedByPolicy (thumbprint equality; compare case-sensitively as BH does, since the values are uppercase).
   3. Resolve Owns/WriteOwner.
   4. EnrollOnBehalfOf.
2. Per ECA: check for a qualifying host, then compute `Domains` as RootCA-chain ∩ NTAuth (§2).
3. Per ECA and template: apply the §3 predicates exactly, including the "missing property ⇒ reject" behaviour, the CrossProduct shortcut semantics and set order, the victim expansion without shortcutting, and the DNS-SAN user filter where it applies (ESC3, ESC6a/b, ESC9a, ESC10a, ESC13 only).
4. Domain gates:
   - ESC6b and ESC10a/b need UPN mapping in the forest.
   - ESC9a/b need weak binding in the forest.
   - ESC6a/b need the CA's user-specified SAN flag, collected and true.
   - ESC3 needs eca1 to be chain-valid for D.
