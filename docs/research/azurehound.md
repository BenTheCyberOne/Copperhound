# AzureHound ingest reference (source-verified)

Scope: what AzureHound writes, and how BloodHound CE turns it into nodes, edges, post-processed edges and Tier Zero.
Everything below comes from reading source code. Items marked **UNVERIFIED** could not be confirmed from source. Items marked **(inference)** were derived by reading code and were not tested at runtime.

## Sources (pinned commits)

| Repo | Ref | Short name used below |
|---|---|---|
| SpecterOps/AzureHound `main` | `b02d4577731f69c729a53055a09c44673689eefd` (2026-10-16, latest tag v3.1.3) | `AH:` |
| SpecterOps/AzureHound tag `v2.12.1` | the version BloodHound CE compiles against (`go.mod`: `github.com/bloodhoundad/azurehound/v2 v2.12.1`) | `AH@v2.12.1:` |
| SpecterOps/BloodHound `main` | `1a8806d1c42d5df4a832a628e3c828c41db6a9dd` (2026-11-04) | `BH:` |

URL patterns:
- `AH:path` = `https://github.com/SpecterOps/AzureHound/blob/b02d4577731f69c729a53055a09c44673689eefd/path`
- `BH:path` = `https://github.com/SpecterOps/BloodHound/blob/1a8806d1c42d5df4a832a628e3c828c41db6a9dd/path`

Key files:
- AH: `models/*.go`, `models/azure/*.go`, `enums/kind.go`, `enums/entity.go`, `constants/roles.go`, `cmd/list-*.go`, `cmd/utils.go`, `sinks/file.go`, `models/utils.go`
- BH: `cmd/api/src/services/graphify/azure_convertors.go` (dispatcher; the path `cmd/api/src/daemons/datapipe/azure_convertors.go` no longer exists), `packages/go/ein/azure.go`, `packages/go/ein/models.go`, `cmd/api/src/services/graphify/{decoders,ingest,ingestnodes,ingestrelationships,models}.go`, `packages/go/analysis/azure/{post,role,tenant,filters,queries}.go`, `packages/go/analysis/hybrid/hybrid.go`, `packages/go/analysis/agt.go`, `packages/go/graphschema/azure/{azure,identifiers,roles}.go`, `packages/cue/bh/azure/azure.cue`, `cmd/api/src/database/migration/migrations/00000000000001_init.sql`

---

## 0. Version caveat: ID casing changed between v2 and v3

- **AzureHound v3 (`main`)** uppercases nearly every ID and name in its custom `MarshalJSON` methods (`AH:models/*.go`, helpers `UpperRoleAssignment`, `UpperManagedIdentity`, `OmitEmptyUpper` in `AH:models/utils.go`). That covers `id`, `appId`, `tenantId`, `displayName`, `principalId`, `scope`, nested owner/member `id`, `onPremisesSecurityIdentifier`, and so on.
- **AzureHound v2.12.1** emits the raw casing returned by Graph/ARM. For example, `AH@v2.12.1:models/user.go` and `models/role-assignments.go` have no `MarshalJSON`.
- **BloodHound** uppercases `objectid` on every node (`normalizeEinNodeProperties`) and uppercases both relationship endpoint values (`ingestibleRelationshipsToUpdates`). This happens unless the `use_raw_object_id` flag is set (`BH:cmd/api/src/services/graphify/ingestnodes.go:141-158`, `ingestrelationships.go:216-232`). It also uppercases `name` and `operatingsystem`.
- **(inference) Possible BH bug with v3 output.** In v3, `AZRoleAssignment.roleAssignments[].roleDefinitionId` is uppercased (`AH:models/role-assignments.go`). BH checks for Application Administrator and Cloud Application Administrator in `ein.CanAddSecret` using a case-sensitive `==` against lowercase constants (`BH:packages/go/ein/azure.go`, `CanAddSecret`). With v3 output, an app-scoped App Admin or Cloud App Admin assignment would therefore turn into a scoped `AZHasRole` instead of `AZAppAdmin`/`AZCloudAppAdmin`.
- **Recommendation for CopperHound:** compare all GUIDs, role IDs, ARM IDs and scopes case-insensitively, and store them uppercase.

---

## 1. Output file envelope

Written by `AH:sinks/file.go` (`WriteToFile`) when `-o file` is used:

```json
{
	"data": [
		{"kind":"AZUser","data":{...}},
		{"kind":"AZGroup","data":{...}}
	],
	"meta": {"type":"azure","version":5,"count":2}
}
```

- **Envelope fields.** `meta` is `models.Meta{Type string "type"; Version int "version"; Count int "count"}` (`AH:models/ingest-request.go`). The file sink always writes `type:"azure"`, `version:5`, and `count` = number of `data` elements. `meta` comes **after** `data`.
- **Line format.** The file is literally `{\n\t"data": [\n` + `\t\t<item>` joined by `,\n\t\t` + `\n\t],\n\t"meta": {...}\n}\n`. Each item is one compact JSON object on one line, produced by `pipeline.FormatJson` with `json.Marshal` (`AH:pipeline/pipeline.go`). Do not rely on that layout; parse the file as JSON or stream the `data` array.
- **Item wrapper.** Each item is `{"kind": <enums.Kind>, "data": <object>}` (`AzureWrapper` / `azureWrapper[T]` in `AH:cmd/utils.go`). BH decodes it as `AzureBase{Kind enums.Kind "kind"; Data json.RawMessage "data"}` (`BH:cmd/api/src/services/graphify/models.go:56`).
- **Mixed kinds.** One file mixes all kinds. `list` = `listAllAD` + `listAllRM` (`AH:cmd/list-root.go`, `list-azure-ad.go`, `list-azure-rm.go`), merged by a concurrent `pipeline.Mux`. Order is therefore **non-deterministic**, and a relationship record (for example AZGroupMember) can appear before its node record.
- **Upload variant.** When sending to a BloodHound Enterprise server, the body is `IngestRequest{meta:{type:"azure"}, data:[...]}`, gzipped and POSTed to `/api/v2/ingest` (`AH:client/bloodhound/client.go`).
- **BH-side parsing.**
  - The validator walks the top-level object and accepts `meta` and `data` in either order. It rejects duplicates and rejects files that have one without the other (`BH:packages/go/chow/payload/validator.go`).
  - `meta.type` must be `"azure"` (`DataTypeAzure`, `BH:packages/go/chow/ingest/ingest.go:46`).
  - Items are streamed with `decoder.More()` / `Decode(&AzureBase)` and dispatched by `getKindConverter(kind)`. An unknown kind becomes a silent no-op (`BH:.../graphify/decoders.go:252`, `azure_convertors.go`).
  - Whether BH validates `meta.count` or `meta.version` for azure: **UNVERIFIED**, and not apparent in the Azure path.

---

## 2. Kinds and their `data` shapes

All kinds AzureHound defines are listed in `AH:enums/kind.go`. The table shows which ones the default `list` command emits (`AH:cmd/list-azure-ad.go`, `list-azure-rm.go` Mux lists) and which ones BH consumes (`BH:.../graphify/azure_convertors.go` `getKindConverter`).

| kind | emitted by `list` | BH converter | data model (AH) |
|---|---|---|---|
| AZApp | yes | yes | `models.App` |
| AZAppOwner | yes | yes | `models.AppOwners` |
| AZAppMember | no | no | `models.AppMember` |
| AZFederatedIdentityCredential | yes | yes | `models.AppFICs` |
| AZAppRoleAssignment | yes | yes | `models.AppRoleAssignment` |
| AZDevice | yes | yes | `models.Device` |
| AZDeviceOwner | **not defined** in AH enums and no BH converter (`models.DeviceOwner` struct exists but no list command emits it) | no | — |
| AZGroup / AZGroupMember / AZGroupOwner | yes | yes | `models.Group` / `models.GroupMembers` / `models.GroupOwners` |
| AZRole | yes | yes | `models.Role` |
| AZRoleAssignment | yes | yes | `models.RoleAssignments` (Entra directory roles) |
| AZRoleEligibilityScheduleInstance | yes | yes | `models.RoleEligibilityScheduleInstance` |
| AZRoleManagementPolicyAssignment | yes | yes | `models.RoleManagementPolicyAssignment` |
| AZServicePrincipal / AZServicePrincipalOwner | yes | yes | `models.ServicePrincipal` / `models.ServicePrincipalOwners` |
| AZTenant | yes | yes | `models.Tenant` |
| AZUser | yes | yes | `models.User` |
| AZManagementGroup | yes | yes | `models.ManagementGroup` |
| AZManagementGroupDescendant | yes | yes | `azure.DescendantInfo` (no wrapper) |
| AZManagementGroupOwner / Contributor / UserAccessAdmin | yes | yes | `models.ManagementGroup{Owners,Contributors,UserAccessAdmins}` |
| AZManagementGroupRoleAssignment | no (internal intermediate) | no | — |
| AZSubscription | yes | yes | `models.Subscription` (BH unmarshals as `azure.Subscription`) |
| AZSubscriptionOwner / Contributor / UserAccessAdmin | yes | yes | `models.Subscription{Owners,...}` |
| AZSubscriptionRoleAssignment | no (intermediate) | no | — |
| AZResourceGroup | yes | yes | `models.ResourceGroup` |
| AZResourceGroupOwner / Contributor / UserAccessAdmin | yes | yes | `models.ResourceGroup{Owners,...}` |
| AZResourceGroupRoleAssignment | no (intermediate) | no | — |
| AZKeyVault | yes | yes | `models.KeyVault` |
| AZKeyVaultAccessPolicy | yes | yes | `models.KeyVaultAccessPolicy` |
| AZKeyVaultOwner / Contributor / KVContributor / UserAccessAdmin | yes | yes | `models.KeyVault{Owners,Contributors,KVContributors,UserAccessAdmins}` |
| AZKeyVaultRoleAssignment | no (intermediate) | no | — |
| AZVM | yes | yes | `models.VirtualMachine` |
| AZVMOwner / AZVMContributor / AZVMAvereContributor / AZVMAdminLogin / AZVMUserAccessAdmin | yes | yes | `models.VirtualMachine{Owners,Contributors,AvereContributors,AdminLogins,UserAccessAdmins}` |
| AZVMVMContributor | **no** (not in `listAllRM` Mux; only via `list virtual-machine-vmcontributors`) | yes | `models.VirtualMachineVMContributors` |
| AZVMRoleAssignment | no (intermediate) | no | — |
| AZVMScaleSet + AZVMScaleSetRoleAssignment | yes | yes | `models.VMScaleSet` + `models.AzureRoleAssignments` |
| AZManagedCluster + AZManagedClusterRoleAssignment | yes | yes | `models.ManagedCluster` + `models.AzureRoleAssignments` |
| AZContainerRegistry + ...RoleAssignment | yes | yes | `models.ContainerRegistry` + `models.AzureRoleAssignments` |
| AZWebApp + ...RoleAssignment | yes | yes | `models.WebApp` (only `kind=="app"`) + `models.AzureRoleAssignments` |
| AZFunctionApp + ...RoleAssignment | yes | yes | `models.FunctionApp` (only `kind=="functionapp"`) + `models.AzureRoleAssignments` |
| AZLogicApp + ...RoleAssignment | yes | yes | `models.LogicApp` + `models.AzureRoleAssignments` |
| AZAutomationAccount + ...RoleAssignment | yes | yes | `models.AutomationAccount` + `models.AzureRoleAssignments` |
| AZStorageAccount / AZStorageAccountRoleAssignment / AZStorageContainer | no (separate subcommands only) | **no** (ignored) | `models.StorageAccount`, `models.StorageContainer` |

### 2.1 Shared sub-shapes

- **ARM RoleAssignment** (`AH:models/azure/role_assignment.go`). `GetPrincipalId()` returns `properties.principalId`.
  ```json
  {"id":"/subscriptions/S/providers/Microsoft.Authorization/roleAssignments/X","name":"X","type":"Microsoft.Authorization/roleAssignments",
   "properties":{"principalId":"<objectId>","roleDefinitionId":"/subscriptions/S/providers/Microsoft.Authorization/roleDefinitions/<guid>","scope":"/subscriptions/S/resourceGroups/RG"}}
  ```
- **AzureRoleAssignments** (`AH:models/azure-role-assignment.go`). Used by every `AZ<Resource>RoleAssignment` kind. Note the JSON key is `assignees`, and inner `roleDefinitionId` is the bare GUID (`path.Base`; `AH:cmd/list-automation-account-role-assignments.go`).
  ```json
  {"objectId":"<resourceId>","assignees":[{"assignee":<RoleAssignment>,"objectId":"<resourceId>","roleDefinitionId":"8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}]}
  ```
- **ManagedIdentity** (`AH:models/azure/managed_identity.go`, `user_assigned_identity.go`). Appears as `identity` on VM, VMSS, WebApp, FunctionApp, LogicApp, AutomationAccount, ContainerRegistry, ManagedCluster and StorageAccount.
  ```json
  "identity":{"type":"SystemAssigned, UserAssigned","principalId":"<sp objectId>","tenantId":"T",
    "userAssignedIdentities":{"/subscriptions/S/resourceGroups/RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai1":{"clientId":"<appId>","principalId":"<sp objectId>"}}}
  ```
- **DirectoryObject** (owners/members raw JSON; `AH:models/azure/directory_object.go`): `{"id":"...","@odata.type":"#microsoft.graph.user"}`. BH recognises only `#microsoft.graph.user`, `#microsoft.graph.group`, `#microsoft.graph.servicePrincipal` and `#microsoft.graph.device` (`ExtractTypeFromDirectoryObject` in `BH:packages/go/ein/azure.go`; constants in `AH:enums/entity.go`). Any other type is skipped and logged.
- Role-filter kinds (`*Owner`, `*Contributor`, `*KVContributor`, `*UserAccessAdmin`, `VMAdminLogin`, `VMAvereContributor`, `VMVMContributor`) are derived from the resource's RBAC assignments, filtered by `path.Base(roleDefinitionId) == <RoleID>` (`AH:cmd/utils.go` filters; `cmd/list-*-owners.go` etc.). RBAC role IDs come from `AH:constants/roles.go`:

| AH constant | GUID |
|---|---|
| OwnerRoleID | `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` |
| ContributorRoleID | `b24988ac-6180-42a0-ab88-20f7382dd24c` |
| UserAccessAdminRoleID | `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` |
| KeyVaultContributorRoleID | `f25e0fa2-a7c8-4377-a976-54943a77a395` |
| VirtualMachineContributorRoleID | `9980e02c-c2be-4d73-94e8-173b1dc7cf3c` |
| VirtualMachineAdministratorLoginRoleID | `1c0163c0-47e6-4577-8991-ea5c82e286e4` |
| AvereContributorRoleID | `4f8fab4f-1852-4a58-a46a-8eaf358af14a` |
| WebsiteContributorRoleID | `de139f84-1756-47ae-9be6-808fbbe84772` |
| LogicAppContributorRoleID | `87a39d53-fc1b-424a-814c-f7e04687dc9e` |
| AutomationContributorRoleID | `f353d9bd-d4a6-484e-a77a-8050b599b867` |
| AKSContributorRole (BH `graphschema/azure/roles.go`) | `ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8` |

### 2.2 Per-kind JSON fields that matter

Field names come from `AH:models/*.go` (wrapper) plus the embedded `AH:models/azure/*.go` struct. Embedded structs flatten into the same object.

| kind | fields used for nodes/edges |
|---|---|
| AZTenant | `id`, `tenantId`, `displayName`, `defaultDomain`, `domains[]`, `tenantType`, `tenantCategory`, `collected` (true only for the tenant being collected; other entries come from `ListAzureADTenants`) (`AH:models/tenant.go`, `models/azure/tenant.go`, `cmd/list-tenants.go`) |
| AZUser | `id`, `displayName`, `userPrincipalName`, `accountEnabled`, `createdDateTime`, `jobTitle`, `lastPasswordChangeDateTime`, `mail`, `onPremisesSecurityIdentifier`, `onPremisesSyncEnabled`, `userType`, `signInActivity.lastSuccessfulSignInDateTime`, `tenantId`, `tenantName`. `$select` list is in `AH:cmd/list-users.go` |
| AZGroup | `id`, `displayName`, `description`, `createdDateTime`, `isAssignableToRole`, `securityEnabled`, `securityIdentifier`, `onPremisesSecurityIdentifier`, `onPremisesSyncEnabled`, `tenantId`, `tenantName` |
| AZGroupMember | `{"groupId":G,"members":[{"groupId":G,"member":{"@odata.type":"#microsoft.graph.user","id":U,...}}]}`. Default member `$select` is `id,displayName,createdDateTime`; Graph still returns `@odata.type` (`AH:cmd/list-group-members.go:40`) |
| AZGroupOwner | `{"groupId":G,"owners":[{"groupId":G,"owner":{DirectoryObject}}]}` |
| AZServicePrincipal | `id` (objectId), `appId`, `displayName`, `accountEnabled`, `appDisplayName`, `appDescription`, `appOwnerOrganizationId`, `loginUrl`, `servicePrincipalType`, `appRoles[]`, `tenantId`, `tenantName` |
| AZServicePrincipalOwner | `{"servicePrincipalId":SP,"owners":[{"servicePrincipalId":SP,"owner":{DirectoryObject}}]}` |
| AZApp | `id` (objectId), `appId` (client id; **this is the BH node id**), `displayName`, `description`, `createdDateTime`, `publisherDomain`, `signInAudience`, `tenantId`, `tenantName` |
| AZAppOwner | `{"appId":<app.appId>,"owners":[{"appId":<app object id>,"owner":{DirectoryObject}}]}`. The top-level `appId` is the client ID; the inner element's `appId` is the object ID and BH ignores it (`AH:cmd/list-app-owners.go:79-90`) |
| AZFederatedIdentityCredential | `{"appId":A,"tenantId":T,"tenantName":N,"fics":[{"appId":A,"fic":{"id","name","issuer","subject","audiences[]","description"}}]}` |
| AZAppRoleAssignment | One record per assignment granted **on** a resource SP: `appRoleId`, `principalId`, `principalType` ("ServicePrincipal"/"User"/"Group"), `principalDisplayName`, `resourceId` (resource SP objectId), `resourceDisplayName`, `appId` (resource SP's appId, raw case), `tenantId`. Only SPs with non-empty `appRoles` are queried (`AH:cmd/list-app-role-assignments.go`) |
| AZDevice | `id`, `deviceId`, `displayName`, `operatingSystem`, `operatingSystemVersion`, `trustType`, `tenantId`, `tenantName` |
| AZRole | `id` (role definition id = template id for built-ins), `templateId`, `displayName`, `description`, `isBuiltIn`, `isEnabled`, `tenantId`, `tenantName` |
| AZRoleAssignment | `{"roleDefinitionId":R,"tenantId":T,"roleAssignments":[{"id","roleDefinitionId","principalId","directoryScopeId","principal":{...},"directoryScope":{...}}]}`. One record per role. AH rewrites any `directoryScopeId != "/"` to `"/" + directoryScope.appId` (`AH:cmd/list-role-assignments.go:105-110`). **(inference)** Non-app scopes such as administrative units have no `appId`, so they become `"/"`, which is the same as tenant-wide |
| AZRoleEligibilityScheduleInstance | `id`, `roleDefinitionId`, `principalId`, `directoryScopeId`, `startDateTime`, `tenantId` |
| AZRoleManagementPolicyAssignment | `id`, `roleDefinitionId`, `tenantId`, `endUserAssignmentRequiresApproval`, `endUserAssignmentUserApprovers[]`, `endUserAssignmentGroupApprovers[]`, `endUserAssignmentRequiresMFA`, `...RequiresJustification`, `...RequiresTicketInformation`, `...RequiresCAPAuthenticationContext`, plus raw `policy` (`AH:models/role-management-policy-assignment.go`, `cmd/list-role-assignment-policies.go`; only `scopeId eq '/' and scopeType eq 'Directory'`) |
| AZSubscription | `id` (`/subscriptions/<guid>`), `subscriptionId`, `displayName`, `tenantId`, `state` |
| AZManagementGroup | `id` (`/providers/Microsoft.Management/managementGroups/<name>`), `name`, `properties.displayName`, `properties.tenantId`, `tenantId` |
| AZManagementGroupDescendant | `id`, `name`, `type` (`Microsoft.Management/managementGroups` or `.../subscriptions`), `properties.displayName`, `properties.parent.id` |
| AZResourceGroup | `id`, `name`, `subscriptionId` (prefixed `/subscriptions/<guid>`), `tenantId` (`AH:cmd/list-resource-groups.go:100-104`) |
| AZKeyVault | `id`, `name`, `resourceGroup` (RG **id**, from `ResourceGroupId()`), `subscriptionId` (bare guid), `tenantId`, `properties.enableRbacAuthorization`, `properties.accessPolicies[]` |
| AZKeyVaultAccessPolicy | `keyVaultId`, `objectId`, `applicationId`, `tenantId`, `permissions.{keys,secrets,certificates,storage}[]` (strings such as `"Get"`, `"List"`) |
| AZVM | `id`, `name`, `properties.vmId`, `properties.storageProfile.osDisk.osType`, `resourceGroupId`, `subscriptionId`, `tenantId`, `identity` |
| AZManagedCluster | `id`, `name`, `resourceGroupId`, `subscriptionId` (v3: `/subscriptions/<guid>`), `tenantId`, `properties.nodeResourceGroup`, `identity` |
| AZVMScaleSet / AZWebApp / AZFunctionApp / AZLogicApp / AZAutomationAccount / AZContainerRegistry | `id`, `name`, `resourceGroupId`, (`resourceGroupName`), `subscriptionId`, `tenantId`, `identity` |
| Role-filter kinds | `{"<parentIdKey>":X,"<arrayKey>":[{"<elemKey>":<ARM RoleAssignment>,"<parentIdKey>":X}]}`. Key table follows |

Role-filter kind keys (`AH:models/*-owner.go`, `*-contributor.go`, ...):

| kind | parentIdKey | arrayKey | elemKey |
|---|---|---|---|
| AZKeyVaultOwner | keyVaultId | owners | owner |
| AZKeyVaultContributor | keyVaultId | contributors | contributor |
| AZKeyVaultKVContributor | keyVaultId | kvContributors | kvContributor |
| AZKeyVaultUserAccessAdmin | keyVaultId | userAccessAdmins | userAccessAdmin |
| AZManagementGroupOwner / Contributor / UserAccessAdmin | managementGroupId | owners / contributors / userAccessAdmins | owner / contributor / userAccessAdmin |
| AZSubscriptionOwner / Contributor / UserAccessAdmin | subscriptionId | owners / contributors / userAccessAdmins | owner / contributor / userAccessAdmin |
| AZResourceGroupOwner / Contributor / UserAccessAdmin | resourceGroupId | owners / contributors / userAccessAdmins | owner / contributor / userAccessAdmin |
| AZVMOwner / AZVMContributor / AZVMUserAccessAdmin | virtualMachineId | owners / contributors / userAccessAdmins | owner / contributor / userAccessAdmin |
| AZVMAdminLogin | virtualMachineId | adminLogins | adminLogin |
| AZVMAvereContributor | virtualMachineId | avereContributors | avereContributor |
| AZVMVMContributor | virtualMachineId | vmContributors | vmContributor |

The intermediate `KeyVaultRoleAssignment` model writes the key vault id under the JSON key `"virtualMachineId"` (`AH:models/key-vault-role-assignment.go`). It is never emitted by `list` or consumed by BH, so this is only a curiosity.

**AH bug in `list` (inference).** `listAllRM` passes the access-type filter `{GetCerts, GetKeys, GetCerts}` (`AH:cmd/list-azure-rm.go:184`). As a result, access policies whose only `Get` permission is on **secrets** are not emitted by `list` / `list az-rm`.

### 2.3 Examples (v3 casing; v2 emits the same keys with raw casing)

```json
{"kind":"AZUser","data":{"id":"6A1B...","displayName":"ALICE","userPrincipalName":"alice@contoso.com","accountEnabled":true,
 "onPremisesSecurityIdentifier":"S-1-5-21-111-222-333-1104","onPremisesSyncEnabled":true,"userType":"Member",
 "signInActivity":{"lastSuccessfulSignInDateTime":"2026-10-01T08:00:00Z"},"tenantId":"9F0C...","tenantName":"CONTOSO"}}

{"kind":"AZGroupMember","data":{"groupId":"0D4E...","members":[{"groupId":"0D4E...","member":{"@odata.type":"#microsoft.graph.user","id":"6A1B...","displayName":"Alice"}}]}}

{"kind":"AZRoleAssignment","data":{"roleDefinitionId":"62E90394-69F5-4237-9190-012177145E10","tenantId":"9F0C...",
 "roleAssignments":[{"id":"lAPpYvVpN0KRkAEhdxReEJ...","roleDefinitionId":"62E90394-69F5-4237-9190-012177145E10","principalId":"6A1B...","directoryScopeId":"/"}]}}

{"kind":"AZServicePrincipal","data":{"id":"5C2D...","appId":"A1B2...","displayName":"MYAPP","appOwnerOrganizationId":"9F0C...","servicePrincipalType":"Application","accountEnabled":true,"tenantId":"9F0C...","tenantName":"CONTOSO"}}

{"kind":"AZAppRoleAssignment","data":{"appRoleId":"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","principalId":"5C2D...","principalType":"ServicePrincipal","principalDisplayName":"MyApp",
 "resourceId":"7E8F...","resourceDisplayName":"Microsoft Graph","appId":"00000003-0000-0000-c000-000000000000","tenantId":"9F0C..."}}

{"kind":"AZVM","data":{"id":"/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM1","name":"vm1",
 "properties":{"vmId":"...","storageProfile":{"osDisk":{"osType":"Windows"}}},
 "identity":{"type":"SystemAssigned","principalId":"3B4C..."},
 "resourceGroupId":"/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG1","subscriptionId":"/SUBSCRIPTIONS/S","tenantId":"9F0C..."}}

{"kind":"AZVMAdminLogin","data":{"virtualMachineId":"/SUBSCRIPTIONS/S/.../VIRTUALMACHINES/VM1","adminLogins":[{"virtualMachineId":"...VM1",
 "adminLogin":{"id":"...","name":"...","properties":{"principalId":"6A1B...","roleDefinitionId":"/subscriptions/S/providers/Microsoft.Authorization/roleDefinitions/1c0163c0-47e6-4577-8991-ea5c82e286e4","scope":"/SUBSCRIPTIONS/S/.../VIRTUALMACHINES/VM1"}}}]}}

{"kind":"AZKeyVaultAccessPolicy","data":{"keyVaultId":"/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/KV1","objectId":"6A1B...","tenantId":"9F0C...",
 "permissions":{"keys":["Get","List"],"secrets":["Get"],"certificates":[]}}}

{"kind":"AZWebAppRoleAssignment","data":{"objectId":"/SUBSCRIPTIONS/S/.../SITES/APP1","assignees":[{"objectId":"/SUBSCRIPTIONS/S/.../SITES/APP1","roleDefinitionId":"de139f84-1756-47ae-9be6-808fbbe84772",
 "assignee":{"properties":{"principalId":"6A1B...","roleDefinitionId":"/subscriptions/S/providers/Microsoft.Authorization/roleDefinitions/de139f84-1756-47ae-9be6-808fbbe84772","scope":"/SUBSCRIPTIONS/S/.../SITES/APP1"}}}]}}

{"kind":"AZManagementGroupDescendant","data":{"id":"/SUBSCRIPTIONS/S","name":"S","type":"Microsoft.Management/managementGroups/subscriptions",
 "properties":{"displayName":"PROD","parent":{"id":"/PROVIDERS/MICROSOFT.MANAGEMENT/MANAGEMENTGROUPS/ROOTMG"}}}}
```

---

## 3. BloodHound CE conversion (ingest-time nodes and edges)

### 3.1 General rules

- **Labels.** Every node and every relationship endpoint is upserted with base kind `AZBase` (`azure.Entity`) merged with the specific kind. Endpoints are matched by `objectid` within `AZBase` (`IngestAzureData` → `IngestNodes/IngestRelationships(batch, azure.Entity, ...)`, `BH:.../graphify/ingest.go:335-343`; `MergeNodeKinds` in `ingestrelationships.go`).
  - An edge whose endpoint does not exist yet creates a stub node.
  - An endpoint typed `AZBase` gets only that label until its own record arrives.
- **Normalisation.** `objectid` = `UPPER(IngestibleNode.ObjectID)` and edge endpoint values are uppercased; `name` and `operatingsystem` are uppercased (`ingestnodes.go:141-175`). The `objectid` set in a converter's PropertyMap (Subscription, Tenant, VM) is **overwritten** by `ObjectID`.
- **Common properties.** Every node gets `tenantid` = `UPPER(tenantId)`, `lastcollected` and `lastseen`. Every edge gets `lastseen`.
- **Edge direction.** "A → B" below means a relationship from A to B. "AZBase(x)" means the endpoint is matched by objectid x with kind AZBase only.

### 3.2 Nodes (`BH:packages/go/ein/azure.go`)

| AH kind | Node kind | objectid source | notable props |
|---|---|---|---|
| AZTenant | AZTenant | `tenantId` | displayname, name=displayName, `collected=true` if set |
| AZUser | AZUser | `id` | name=userPrincipalName, enabled, whencreated, displayname, title, pwdlastset, email, onpremid, onpremsyncenabled, userprincipalname, usertype, lastsuccessfulsignindatetime |
| AZGroup | AZGroup | `id` | name=`displayName@tenantName`, isassignabletorole, onpremid, onpremsyncenabled, securityenabled, securityidentifier, description |
| AZServicePrincipal | AZServicePrincipal (`id`) **and** a stub AZApp (`appId`, displayname=appDisplayName, tenantid=appOwnerOrganizationId) | `id` / `appId` | name=`displayName@tenantName`, enabled, appownerorganizationid, appdisplayname, appdescription, loginurl, serviceprincipaltype |
| AZApp | AZApp | **`appId`** (not object id) | name=`displayName@publisherDomain`, appid, publisherdomain, signinaudience, whencreated |
| AZDevice | AZDevice | `id` | name=`displayName@tenantName`, operatingsystem, operatingsystemversion, deviceid, trusttype |
| AZRole | AZRole | `"<id>@<tenantId>"` | name=`displayName@tenantName`, roletemplateid=`templateId` (raw case), isbuiltin, enabled |
| AZRoleManagementPolicyAssignment | AZRole (upsert props) | `"<roleDefinitionId>@<tenantId>"` | roledefinitionid, enduserassignment* props |
| AZFederatedIdentityCredential | AZFederatedIdentityCredential (+AZBase) | fic `id` | name=`name@tenantName`, issuer, subject, audiences |
| AZAppRoleAssignment | 2 × AZServicePrincipal stubs: principal (`principalId`) and resource (`resourceId`) | — | displayname, tenantid |
| AZSubscription | AZSubscription | `id` (`/subscriptions/<guid>`) | name/displayname=displayName |
| AZManagementGroup | AZManagementGroup | `id` | displayname. `name` is set later in post-processing as `displayName@tenantName` (`FixManagementGroupNames`, `BH:packages/go/analysis/azure/post.go`) |
| AZResourceGroup | AZResourceGroup | `id` | name |
| AZKeyVault | AZKeyVault | `id` | name, enablerbacauthorization |
| AZVM | AZVM | `id` | name, operatingsystem=osDisk.osType |
| AZManagedCluster | AZManagedCluster | `id` | name, noderesourcegroupid |
| AZVMScaleSet, AZWebApp, AZFunctionApp, AZLogicApp, AZAutomationAccount, AZContainerRegistry | same-named kind | `id` | name |

### 3.3 Edges created at ingest

| AH kind | Edge (source → target) | Condition / notes |
|---|---|---|
| AZApp | AZTenant(`tenantId`) –AZContains→ AZApp(`appId`) | |
| AZDevice | AZTenant –AZContains→ AZDevice | |
| AZGroup | AZTenant –AZContains→ AZGroup | |
| AZUser | AZTenant –AZContains→ AZUser | |
| AZRole | AZTenant –AZContains→ AZRole(`id@tenantId`) | |
| AZServicePrincipal | AZApp(`appId`) –**AZRunsAs**→ AZServicePrincipal(`id`); AZTenant(`tenantId`) –AZContains→ SP | |
| AZSubscription | AZTenant(`tenantId`) –AZContains→ AZSubscription(`id`) | |
| AZManagementGroup | AZTenant(`tenantId`) –AZContains→ AZManagementGroup | every MG, not only the root |
| AZManagementGroupDescendant | AZManagementGroup(`properties.parent.id`) –AZContains→ AZBase(`id`) | child MG or subscription |
| AZResourceGroup | AZSubscription(`subscriptionId`) –AZContains→ AZResourceGroup(`id`) | |
| AZKeyVault | AZResourceGroup(`resourceGroup`) –AZContains→ AZKeyVault | |
| AZVM, AZVMScaleSet, AZWebApp, AZFunctionApp, AZLogicApp, AZAutomationAccount, AZContainerRegistry, AZManagedCluster | AZResourceGroup(`resourceGroupId`) –AZContains→ resource | |
| (same resources) | resource –**AZManagedIdentity**→ AZServicePrincipal(`identity.principalId`) | if principalId non-empty (system-assigned) |
| (same resources, except AZManagedCluster) | resource –AZManagedIdentity→ AZServicePrincipal(`userAssignedIdentities[*].principalId`) | only if that entry's `clientId` is non-empty. ManagedCluster emits no ManagedIdentity edges |
| AZManagedCluster | AZManagedCluster –**AZNodeResourceGroup**→ AZResourceGroup(`UPPER(<sub>/resourcegroups/<properties.nodeResourceGroup>)`) | the `/subscriptions/` prefix is normalised (`azure_convertors.go` `convertAzureManagedCluster`) |
| AZGroupMember | member(`member.id`, kind from `@odata.type`) –**AZMemberOf**→ AZGroup(`groupId`) | user, group, servicePrincipal, device only |
| AZGroupOwner / AZServicePrincipalOwner / AZAppOwner | owner(`owner.id`, kind from `@odata.type`) –**AZOwns**→ AZGroup(`groupId`) / AZServicePrincipal(`servicePrincipalId`) / AZApp(top-level `appId`) | |
| AZFederatedIdentityCredential | AZFederatedIdentityCredential(`fic.id`) –**AZAuthenticatesTo**→ AZApp(`appId`) | |
| AZRoleAssignment | default: AZBase(`principalId`) –**AZHasRole**{`scope`}→ AZRole(`UPPER(roleDefinitionId@tenantId)`). `scope` = UPPER(tenantId) if `directoryScopeId=="/"`, else UPPER(`directoryScopeId[1:]`), which is the appId | `ConvertAzureRoleAssignmentToRels` |
| AZRoleAssignment (special case) | if roleDefinitionId ∈ {App Admin `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` → **AZAppAdmin**, Cloud App Admin `158c047a-c907-4556-b7ef-446551a6b5f7` → **AZCloudAppAdmin**} **and** `directoryScopeId != "/"`: AZBase(`principalId`) –AZAppAdmin/AZCloudAppAdmin→ AZBase(scope appId). This replaces the HasRole edge | case-sensitive `==`; see section 0 |
| AZRoleEligibilityScheduleInstance | AZBase(`principalId`) –**AZRoleEligible**→ AZRole(`roleDefinitionId@tenantId`) | only when `directoryScopeId == "/"` |
| AZRoleManagementPolicyAssignment | only if `endUserAssignmentRequiresApproval`: AZUser(each `endUserAssignmentUserApprovers`) –**AZRoleApprover**→ AZRole; AZGroup(each `endUserAssignmentGroupApprovers`) –AZRoleApprover→ AZRole. If both lists are empty: AZRole(PRA `E8611AB8-...@tenant`) and AZRole(GA `62E90394-...@tenant`) –AZRoleApprover→ AZRole | `ConvertAzureRoleManagementPolicyAssignment` |
| AZAppRoleAssignment | AZServicePrincipal(`principalId`) –**AZMG\<perm\>**→ AZServicePrincipal(`resourceId`) | only if `appId == "00000003-0000-0000-c000-000000000000"` (MS Graph), `principalType == "ServicePrincipal"`, and `appRoleId` is in the table in section 4.3 (`azure_convertors.go` `convertAzureAppRoleAssignment`; `identifiers.go`) |
| AZKeyVaultAccessPolicy | AZBase(`objectId`) –**AZGetCertificates** / **AZGetKeys** / **AZGetSecrets**→ AZKeyVault(`keyVaultId`) | one edge per category whose list contains the exact string `"Get"` (`getKeyVaultPermissions`) |
| AZKeyVaultOwner / Contributor / KVContributor / UserAccessAdmin | AZBase(principalId) –**AZOwner / AZContributor / AZKeyVaultContributor / AZUserAccessAdministrator**→ AZKeyVault | `EqualFold(keyVaultId, scope)`: assignment must be **at** the vault scope |
| AZManagementGroupOwner / Contributor / UserAccessAdmin | AZBase –AZOwner / AZContributor / AZUserAccessAdministrator→ AZManagementGroup | scope must equal the MG id |
| AZSubscriptionOwner / Contributor / UserAccessAdmin | AZBase –AZOwner / AZContributor / AZUserAccessAdministrator→ AZSubscription | scope must equal `subscriptionId` (the `/subscriptions/<guid>` form) |
| AZResourceGroupOwner / Contributor / UserAccessAdmin | AZBase –AZOwner / AZContributor / AZUserAccessAdministrator→ AZResourceGroup | scope must equal the RG id |
| AZVMOwner / AZVMContributor / AZVMAvereContributor / AZVMVMContributor / AZVMAdminLogin / AZVMUserAccessAdmin | AZBase –AZOwner / AZContributor / **AZAvereContributor** / **AZVMContributor** / **AZVMAdminLogin** / AZUserAccessAdministrator→ AZVM | `ResourceWithinScope(vmId, scope)`: either an EqualFold match, or `scope` matches regex `` `^[\\w\\d\\-\\/]*/resourceGroups/[0-9a-zA-Z]+$` `` and the VM id starts with that scope. **(inference)** In a Go raw string that character class is literal `\`,`w`,`d`,`-`,`/`, and `resourceGroups` is case-sensitive, so real RG-level scopes almost never match |
| AZVMScaleSetRoleAssignment | AZBase(assignee.principalId) –KindFromRoleId→ AZVMScaleSet(`objectId`) | role ∈ {Owner, UAA, Contributor, VM Contributor}; scope EqualFold objectId |
| AZWebAppRoleAssignment, AZFunctionAppRoleAssignment | → AZWebApp / AZFunctionApp | role ∈ {Owner, UAA, Contributor, Website Contributor → **AZWebsiteContributor**} |
| AZLogicAppRoleAssignment | → AZLogicApp | role ∈ {Owner, UAA, Contributor, Logic App Contributor → **AZLogicAppContributor**} |
| AZAutomationAccountRoleAssignment | → AZAutomationAccount | role ∈ {Owner, UAA, Contributor, Automation Contributor → **AZAutomationContributor**} |
| AZContainerRegistryRoleAssignment | → AZContainerRegistry | role ∈ {Owner, UAA, Contributor} |
| AZManagedClusterRoleAssignment | → AZManagedCluster | role ∈ {Owner, UAA, Contributor, AKS Contributor `ed7f3fbd-...` → **AZAKSContributor**} |
| AZTenant | (none) | |

`KindFromRoleId` maps: Owner → AZOwner, UAA → AZUserAccessAdministrator, Contributor → AZContributor, Website → AZWebsiteContributor, Automation → AZAutomationContributor, LogicApp → AZLogicAppContributor, VMContributor → AZVMContributor, AKS → AZAKSContributor. The role-ID filter is lowercased before matching, but `KindFromRoleId` itself is a case-sensitive switch.

**Inherited RBAC is not expanded at ingest.** An Owner at subscription scope produces only `AZOwner → AZSubscription`. Reachability to child resources comes from the `AZContains` hierarchy (MG → Sub → RG → resource). The BH UI and pathfinding treat AZOwner/AZContributor/AZUserAccessAdministrator together with AZContains as control (`ControlRelationships()` and `FilterControlsRelationships` include AZContains; `BH:packages/go/graphschema/azure/azure.go:452`, `analysis/azure/filters.go`).

**Edges in the schema with no producer in current CE Go code:** `AZScopedTo`, `AZGrant`, `AZGrantSelf`. `AZScopedTo` is only referenced in tests; Grant and GrantSelf are only read, in `RoleMembersWithGrants` and filters (grep over `BH:cmd`, `BH:packages/go`). `AZAddMembers`, `AZAddSecret`, `AZAddOwner`, `AZResetPassword`, `AZGlobalAdmin`, `AZPrivilegedRoleAdmin`, `AZPrivilegedAuthAdmin`, `AZExecuteCommand`, `AZMGAdd*`, `AZMGGrant*`, `SyncedToEntraUser` and `SyncedToADUser` are post-processed (section 4).

---

## 4. Post-processing (`BH:packages/go/analysis/azure/post.go`, `Post()`)

### 4.1 Execution order and definitions

Order:
1. `FixManagementGroupNames`
2. `UserRoleAssignments` (ResetPassword, GlobalAdmin, PrivilegedRoleAdmin, PrivilegedAuthAdmin, AddMembers)
3. `AppRoleAssignments` (AZMG* and AZAddSecret)
4. `ExecuteCommand`
5. `CreateAZAddOwnerEdge`
6. `hybrid.PostHybrid`

Each step deletes and recreates its own edge kinds (tracker plus `FilteredRelationshipSink`). Everything runs per AZTenant node.

Definitions (`BH:packages/go/analysis/azure/tenant.go`, `role.go`):
- **Tenant principals.** AZUser, AZGroup and AZServicePrincipal nodes that are `AZTenant –AZContains→` targets.
- **Tenant roles.** AZRole nodes that are `AZTenant –AZContains→` targets, matched on the `roletemplateid` property.
- **Role members** (`RoleMembers`). Inbound traversal from the role over `AZHasRole` and `AZMemberOf`. A path is kept only if it ends at a User, Group or SP, and passes **at most one group, and that group must have `isassignabletorole == true`** (`roleDescentFilter`; nested groups are rejected).
  - **The `scope` property of AZHasRole is ignored**, so scoped assignments that became HasRole count as tenant-wide.
- **`roleMap[templateId]`.** The set of members for every tenant role.
- **`usersWithoutRoles`.** Tenant users that appear in no role's member set.
- **`UsersWithRolesExclusive(L)`.** Users that hold at least one role in L and no role outside L.
- **`roleAssignableGroupMembership`.** Users with a direct `AZMemberOf` into any tenant group whose `isassignabletorole == true`.

### 4.2 Role-based edges

Role template IDs come from `BH:packages/go/graphschema/azure/roles.go`.

| Edge | Source | Target | Rule |
|---|---|---|---|
| AZGlobalAdmin | each member of Global Administrator `62e90394-69f5-4237-9190-012177145e10` | AZTenant | `postAzureGlobalAdmins` |
| AZPrivilegedRoleAdmin | members of Privileged Role Admin `e8611ab8-c189-46e8-94e1-60213ab1f814` | AZTenant | |
| AZPrivilegedAuthAdmin | members of Privileged Authentication Admin `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` | AZTenant | |
| AZResetPassword | the **AZRole node** (not its members) for each role below | AZUser set below | `postAzureResetPassword`, `resetPasswordEndNodeBitmapForRole` |
| AZAddMembers | **users and SPs** that are members of GA or PRA | **every** tenant group | `postAzureAddMembers` |
| AZAddMembers | users and SPs that are members of Groups Admin `fdd7a751-b60b-444a-984c-02652fe8fa1c`, Directory Writers `9360feb5-f418-4baa-8175-e2a00bac4301`, Identity Governance Admin `45d8d3c5-c802-45c6-b32a-1d70b5e1e86e`, User Admin `fe930be7-5e62-47db-91af-98c3a49a38b1`, Intune Admin `3a2c62db-5318-420d-8d74-23affee5d9d5`, Knowledge Admin `b5a8dcf3-09d5-43a9-a639-8e29ef291470`, Knowledge Manager `744ec460-397e-42ad-a462-8b3f9747a02c` | tenant groups with `isassignabletorole == false` (groups missing the property are skipped) | |
| AZAddSecret | AZRole nodes for App Admin `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` and Cloud App Admin `158c047a-c907-4556-b7ef-446551a6b5f7` | every tenant AZApp and AZServicePrincipal (`AZTenant –AZContains→`) | `postAddSecret` (runs inside the AppRoleAssignments step) |
| AZAddOwner | AZRole nodes for Hybrid Identity Admin `8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2`, Partner Tier1 Support `4ba39ca4-527c-499a-b93d-d9b492c50246`, Partner Tier2 Support `e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8`, Directory Synchronization Accounts `d29b2b05-8046-44ba-8758-1e26182fcf32` | every tenant AZApp and AZServicePrincipal | `postAzureAddOwner` |
| AZExecuteCommand | members of Intune Administrator `3a2c62db-5318-420d-8d74-23affee5d9d5` | tenant AZDevice whose `operatingsystem` contains "windows" (case-insensitive) | `ExecuteCommand` |

AZResetPassword target sets (role → users). "RAG members" means `roleAssignableGroupMembership`:

| Role (template id) | Targets |
|---|---|
| Global Admin `62e90394-...`, Privileged Auth Admin `7be44c8a-...`, Partner Tier2 Support `e00e864a-...` | all tenant users |
| User Admin `fe930be7-...` | (usersWithoutRoles ∪ UsersWithRolesExclusive{User Admin, Reports Reader `4a5d8f65-41da-4de4-8968-e035b65339cf`, Message Center Reader `790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b`, Helpdesk Admin `729827e3-9c14-49f7-bb1b-9608f156bbb8`, Guest Inviter `95e79109-95c0-4d8e-aee3-d01accf2d47b`, Directory Readers `88d8e3e3-8f55-4a1e-953a-9b9898b8876b`, Password Admin `966707d0-3269-4727-9be2-8c3a10f19b9d`, Usage Summary Reports Reader `75934031-6c7e-415a-99d7-48dbd49e875e`, Groups Admin `fdd7a751-...`}) − RAG members |
| Helpdesk Admin `729827e3-...` | (usersWithoutRoles ∪ Exclusive{Reports Reader, Message Center Reader, Helpdesk Admin, Guest Inviter, Directory Readers, Password Admin, Usage Summary Reports Reader}) − RAG members |
| Authentication Admin `c4e39bd9-1100-46d3-8c65-fb160da0071f` | (usersWithoutRoles ∪ Exclusive{Authentication Admin, Reports Reader, Message Center Reader, Guest Inviter, Directory Readers, Password Admin, Usage Summary Reports Reader}) − RAG members |
| Password Admin `966707d0-...` | (usersWithoutRoles ∪ Exclusive{Password Admin, Guest Inviter, Directory Readers}) − RAG members |
| Partner Tier1 Support `4ba39ca4-...` | usersWithoutRoles − RAG members |

Note the AZResetPassword, AZAddSecret and AZAddOwner sources are **AZRole** nodes. Principals reach them via `AZHasRole` (plus `AZMemberOf`). AZGlobalAdmin, AZPrivilegedRoleAdmin, AZPrivilegedAuthAdmin, AZAddMembers and AZExecuteCommand originate from the **principals** themselves.

**Scope rules summary.**
- Only `directoryScopeId == "/"` assignments are truly tenant-wide.
- AH turns other scopes into `/<appId>` (or `/` for non-app scopes; inference).
- App-scoped App Admin and Cloud App Admin become direct `AZAppAdmin`/`AZCloudAppAdmin` edges to the AZApp (by appId).
- All other app-scoped assignments become `AZHasRole{scope=<APPID>}`, and post-processing treats them as tenant-wide.
- AZRoleEligible is only created for `/` scope.

### 4.3 MS Graph app-role (API permission) edges

**Ingest-time edges.** `SP(principal) –AZMG<perm>→ SP(MS Graph resource)`. Only for resource appId `00000003-0000-0000-c000-000000000000` and principalType `ServicePrincipal` (`BH:packages/go/graphschema/azure/identifiers.go`):

| appRoleId | Permission | Ingest edge |
|---|---|---|
| `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9` | Application.ReadWrite.All | AZMGApplication_ReadWrite_All |
| `06b708a9-e830-4db3-a914-8e69da51d44f` | AppRoleAssignment.ReadWrite.All | AZMGAppRoleAssignment_ReadWrite_All |
| `19dbc75e-c2e2-444c-a770-ec69d8559fc7` | Directory.ReadWrite.All | AZMGDirectory_ReadWrite_All |
| `62a82d76-70ea-41e2-9197-370581804d09` | Group.ReadWrite.All | AZMGGroup_ReadWrite_All |
| `dbaae8cf-10b5-4b86-a4a1-f871c94c6695` | GroupMember.ReadWrite.All | AZMGGroupMember_ReadWrite_All |
| `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8` | RoleManagement.ReadWrite.Directory | AZMGRoleManagement_ReadWrite_Directory |
| `89c8469c-83ad-45f7-8ff2-6e3d4285709e` | ServicePrincipalEndpoint.ReadWrite.All | AZMGServicePrincipalEndpoint_ReadWrite_All |

**Post-processed edges** (`postAZMG*` in `post.go`). Source = any AZServicePrincipal that has the ingest edge to *any* SP contained by this tenant (normally the tenant's MS Graph SP):

| Ingest edge | Post edges | Targets |
|---|---|---|
| Application.ReadWrite.All | AZMGAddSecret, AZMGAddOwner | every tenant AZServicePrincipal and AZApp |
| AppRoleAssignment.ReadWrite.All | AZMGGrantAppRoles | the AZTenant |
| Directory.ReadWrite.All | AZMGAddMember, AZMGAddOwner | tenant groups with `isassignabletorole == false` |
| Group.ReadWrite.All | AZMGAddMember, AZMGAddOwner | tenant groups with `isassignabletorole == false` |
| GroupMember.ReadWrite.All | AZMGAddMember | tenant groups with `isassignabletorole == false` |
| RoleManagement.ReadWrite.Directory | AZMGGrantRole | every AZRole contained by the tenant |
| ServicePrincipalEndpoint.ReadWrite.All | AZMGAddOwner | every tenant AZServicePrincipal |

### 4.4 Hybrid links (`BH:packages/go/analysis/hybrid/hybrid.go`)

- For each tenant-contained AZUser with `onpremsyncenabled == true` and a non-empty `onpremid` (from `onPremisesSecurityIdentifier`), find an AD `User` node whose `objectid` equals that SID exactly. Both values are uppercased at ingest.
- Edges created: `User(AD) –SyncedToEntraUser→ AZUser` and `AZUser –SyncedToADUser→ User(AD)`.
- Groups are not linked, even though AZGroup stores `onpremid`.

---

## 5. Tier Zero defaults

### 5.1 Default selectors

Source: `BH:cmd/api/src/database/migration/migrations/00000000000001_init.sql:1228-1300`. Columns are `(name, enabled, allow_disable, cypher, ...)`. A selector with `enabled=false` is inserted with `disabled_at` set, i.e. it ships disabled.

| Selector | Cypher | Default |
|---|---|---|
| Global Administrator | `MATCH (n:AZRole) WHERE n.objectid STARTS WITH '62E90394-69F5-4237-9190-012177145E10@'` | **enabled**, cannot disable |
| Privileged Role Administrator | `... STARTS WITH 'E8611AB8-C189-46E8-94E1-60213AB1F814@'` | **enabled**, cannot disable |
| Privileged Authentication Administrator | `... STARTS WITH '7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13@'` | **enabled**, cannot disable |
| Partner Tier2 Support | `... STARTS WITH 'E00E864A-17C5-4A4B-9C06-F5B95A8D5BD8@'` | **enabled**, cannot disable |
| Azure tenant object | `MATCH (n:AZTenant) RETURN n` | **enabled**, cannot disable |
| Application Administrator | `'9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3@'` | disabled (optional) |
| Knowledge Administrator | `'B5A8DCF3-09D5-43A9-A639-8E29EF291470@'` | disabled (optional) |
| Intune Administrator | `'3A2C62DB-5318-420D-8D74-23AFFEE5D9D5@'` | disabled (optional) |
| Security Administrator | `'194AE4CB-B126-40B2-BD5B-6091B380977D@'` | disabled (optional) |
| AZUREADSSOACC object (AD Computer `samaccountname='AZUREADSSOACC$'`) | AD side | disabled (optional) |

### 5.2 Expansion

Tier-type tags use `AssetGroupExpansionMethodAll` (`BH:cmd/api/src/model/assetgrouptags.go:184`). Expansion is in `BH:packages/go/analysis/agt.go`.

- **Children**, iterated until there are no new nodes (`fetchChildNodes`):
  - AZRole ← `AZHasRole|AZRoleEligible` (depth 1). Role holders and eligible principals become Tier Zero.
  - AZGroup ← `AZMemberOf*` (all members, recursive).
  - AZSubscription, AZResourceGroup and AZManagementGroup → `AZContains*` descendants.
  - AZTenant has **no** child expansion.
- **Parents** (`fetchAzureParentNodes`):
  - Any Azure node's `AZContains*` ancestors of kind Subscription, ResourceGroup or ManagementGroup.
  - For AZServicePrincipal, the AZApp that `AZRunsAs` it.

So by default, Tier Zero = every AZTenant, plus the GA, PRA, PAA and Partner Tier2 role nodes, plus their AZHasRole and AZRoleEligible holders, plus the transitive members of any groups among those holders, plus the AZApps behind any SP holders, plus Contains-ancestors (Sub/RG/MG) of any selected Azure node.

### 5.3 Legacy analysis

`FetchAzureAttackPathRoots` (`BH:packages/go/analysis/azure/queries.go:84`; used by `packages/go/analysis/agi.go`) applies a broader legacy rule:
- tenant
- `admin_tier_0`-tagged nodes
- GA, PRA, PAA and Partner Tier2 roles and their members (including GrantSelf)
- Apps of critical SPs
- VMs that are AD `MemberOf` Tier Zero
- AZRoleEligible user and group sources
- RG → Subscription → MG ancestors
- inbound `AZMemberOf|AZHasRole|AZRunsAs` closure

Whether this path is still active alongside AGT selectors in current CE: **UNVERIFIED**.
