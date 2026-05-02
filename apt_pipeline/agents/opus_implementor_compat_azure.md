## PLATFORM COMPATIBILITY — Azure (azure_native provider)

These rules are derived from live Azure + Windows execution failures and Pulumi azure_native v2 API requirements. They supplement the base compat rules for any emulation targeting Azure.

---

### azure_native vs azure provider — always use azure_native
Use **`pulumi_azure_native`** (azure_native provider), NOT the legacy `pulumi_azure` package.
- `azure_native` maps directly to Azure Resource Manager REST API — it's authoritative and complete
- `pulumi_azure` (Terraform bridge) is deprecated, has schema drift, and missing resources
- Import as: `import pulumi_azure_native as azure_native`
- Resource types: `azure_native.compute.VirtualMachine`, `azure_native.storage.StorageAccount`, etc.

### Resource group is mandatory
Every Azure resource requires a `resource_group_name`. Always create a dedicated resource group first and reference it by `Output`:

```python
rg = azure_native.resources.ResourceGroup(
    "emulation-rg",
    resource_group_name="emulation-rg",
    location="eastus",
)
# All subsequent resources:
vm = azure_native.compute.VirtualMachine(
    "victim-vm",
    resource_group_name=rg.name,
    location=rg.location,
    ...
)
```

Never hardcode the resource group name string in child resources — always use `rg.name` Output.

### Location must be a valid Azure region string
Use the short-form region string, not the display name:
- `"eastus"` not `"East US"`
- `"westeurope"` not `"West Europe"`
- `"australiaeast"` not `"Australia East"`

### Service Principal authentication in attack.py
Use `azure-identity` + `azure-mgmt-*` SDK. Do NOT use `azure-cli` subprocess calls:

```python
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient

cred = ClientSecretCredential(
    tenant_id=os.environ["AZURE_TENANT_ID"],
    client_id=os.environ["AZURE_CLIENT_ID"],
    client_secret=os.environ["AZURE_CLIENT_SECRET"],
)
compute_client = ComputeManagementClient(cred, subscription_id)
```

For stolen tokens (e.g. stolen access token from IMDS or phishing):
```python
from azure.identity import StaticTokenCredential  # azure-identity >= 1.15
# OR use raw bearer token in headers for REST calls
headers = {"Authorization": f"Bearer {stolen_token}"}
```

### RBAC role assignments — use fully qualified role definition IDs
Role assignment `role_definition_id` must be the full ARM resource ID, not a display name:

```python
# CORRECT
role_def_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_uuid}"

# WRONG — display names are not accepted by the API
role_def_id = "Contributor"
```

Common built-in role UUIDs:
| Role | UUID |
|------|------|
| Owner | `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` |
| Contributor | `b24988ac-6180-42a0-ab88-20f7382dd24c` |
| Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` |
| Storage Blob Data Contributor | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` |
| Key Vault Secrets User | `4633458b-17de-408a-b874-0445c86b69e6` |

### Key Vault access policies vs RBAC
Azure Key Vault supports two access models. **Use RBAC** (not legacy access policies) for new vaults:

```python
kv = azure_native.keyvault.Vault(
    "kv",
    resource_group_name=rg.name,
    location=rg.location,
    properties=azure_native.keyvault.VaultPropertiesArgs(
        sku=azure_native.keyvault.SkuArgs(
            family="A", name=azure_native.keyvault.SkuName.STANDARD
        ),
        tenant_id=tenant_id,
        enable_rbac_authorization=True,   # ← use RBAC, not access policies
    ),
)
```

### Storage account naming — lowercase alphanumeric only, 3-24 chars
Azure storage account names must be globally unique, 3-24 characters, lowercase letters and numbers only — no hyphens, underscores, or uppercase:

```python
# CORRECT
storage_account_name = "emullab2024strg"

# WRONG — hyphens and uppercase rejected
storage_account_name = "Emul-Lab-Storage"
```

### Managed Identity for VM — use SystemAssigned
Assign a system-assigned managed identity to VMs used in the attack chain. This is the Azure equivalent of an EC2 instance profile:

```python
identity=azure_native.compute.VirtualMachineIdentityArgs(
    type=azure_native.compute.ResourceIdentityType.SYSTEM_ASSIGNED,
)
```

### Network Security Groups — deny-by-default with explicit allow rules
Azure NSGs are allow-by-default within a VNet. For lab isolation:
- Create an NSG with a catch-all deny rule (priority 4000, direction Inbound, action Deny)
- Add explicit allow rules (priority < 4000) for only what the attack needs
- Attach the NSG to the subnet, not individual NICs

### attack.py — Azure SDK error handling
Azure SDK exceptions are structured differently from boto3:

```python
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

try:
    result = client.some_operation(...)
except ResourceNotFoundError:
    print_err("Resource not found (404)")
except HttpResponseError as e:
    print_err(f"Azure API error {e.status_code}: {e.error.code} - {e.error.message}")
```

### attack.py — token theft from Azure IMDS
Azure Instance Metadata Service endpoint for managed identity tokens:

```python
import requests
resp = requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token",
    params={"api-version": "2018-02-01", "resource": "https://management.azure.com/"},
    headers={"Metadata": "true"},
    timeout=5,
)
token = resp.json()["access_token"]
```

### Pulumi outputs — use apply() for ARM IDs
Many Azure resources compute IDs from the subscription + resource group + resource name combination. Use `pulumi.Output.all()` to construct dependent IDs:

```python
vm_id = pulumi.Output.all(subscription_id, rg.name, vm.name).apply(
    lambda args: f"/subscriptions/{args[0]}/resourceGroups/{args[1]}/providers/Microsoft.Compute/virtualMachines/{args[2]}"
)
```
