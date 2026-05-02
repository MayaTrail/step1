## PLATFORM COMPATIBILITY — GCP (pulumi_gcp provider)

These rules are derived from GCP API requirements and pulumi_gcp v7+ behaviour. They supplement the base compat rules for any emulation targeting Google Cloud Platform.

---

### Always enable required APIs before creating resources
GCP enforces that service APIs are enabled before any resource of that type can be created. Add `gcp.projects.Service` resources at the top of `__main__.py`, before any dependent resources:

```python
import pulumi_gcp as gcp

compute_api  = gcp.projects.Service("compute-api",  service="compute.googleapis.com")
iam_api      = gcp.projects.Service("iam-api",      service="iam.googleapis.com")
storage_api  = gcp.projects.Service("storage-api",  service="storage.googleapis.com")
secret_api   = gcp.projects.Service("secretmgr-api",service="secretmanager.googleapis.com")
cloudtrail_api = gcp.projects.Service("logging-api", service="logging.googleapis.com")

# All subsequent resources must depend_on the relevant API resource:
vm = gcp.compute.Instance(
    "victim-vm",
    opts=pulumi.ResourceOptions(depends_on=[compute_api]),
    ...
)
```

### Project ID is required on every resource
GCP resources require an explicit `project` argument (or it reads from the provider default). Always pass it explicitly to avoid ambiguity:

```python
project = gcp.organizations.get_project().project_id

bucket = gcp.storage.Bucket(
    "data-bucket",
    project=project,
    location="US",
)
```

### Service account authentication in attack.py
Use `google-auth` + `google-cloud-*` SDK. Do NOT use `gcloud` subprocess calls:

```python
from google.oauth2 import service_account
from google.cloud import storage

sa_creds = service_account.Credentials.from_service_account_info(
    json.loads(os.environ["GCP_SA_KEY_JSON"]),
    scopes=["https://www.googleapis.com/auth/cloud-platform"],
)
storage_client = storage.Client(project=project_id, credentials=sa_creds)
```

For stolen tokens (e.g. stolen from Compute metadata server or OIDC phishing):
```python
import google.auth.transport.requests
import google.oauth2.credentials

creds = google.oauth2.credentials.Credentials(token=stolen_access_token)
# Use in API calls:
headers = {"Authorization": f"Bearer {stolen_access_token}"}
```

### IAM bindings — use `gcp.projects.IAMBinding` not `IAMMember` for lab setup
`IAMMember` adds a single member per resource. `IAMBinding` replaces the entire member list for that role — use carefully in labs to avoid locking out existing principals:

```python
# SAFE for labs — add one member, don't affect other bindings
gcp.projects.IAMMember(
    "victim-viewer",
    project=project,
    role="roles/viewer",
    member=f"serviceAccount:{victim_sa.email}",
)
```

Fully qualified role strings — always use the `roles/` prefix:
- `"roles/viewer"`, `"roles/editor"`, `"roles/storage.objectViewer"`
- NOT `"viewer"` or `"Storage Object Viewer"`

### Storage bucket locations — uppercase region strings
GCP Storage bucket locations use uppercase multi-region or region strings:
- `"US"`, `"EU"`, `"ASIA"` (multi-region)
- `"us-central1"`, `"europe-west1"` (regional)
- NOT `"us"` or `"United States"`

### Compute instance metadata server — attack.py token theft
GCP Compute instance metadata endpoint for service account tokens:

```python
import requests

METADATA_URL = "http://metadata.google.internal/computeMetadata/v1"
resp = requests.get(
    f"{METADATA_URL}/instance/service-accounts/default/token",
    headers={"Metadata-Flavor": "Google"},
    timeout=5,
)
token = resp.json()["access_token"]
```

The `Metadata-Flavor: Google` header is **mandatory** — requests without it return 403.

### Secret Manager — versions, not secret values directly
GCP Secret Manager stores secrets as versioned resources. To read a secret in attack.py:

```python
from google.cloud import secretmanager

sm = secretmanager.SecretManagerServiceClient(credentials=creds)
name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
response = sm.access_secret_version(request={"name": name})
payload = response.payload.data.decode("utf-8")
```

### GCP audit log field names — Cloud Logging
GCP audit logs are written to Cloud Logging. The relevant log types for attack detection:
- **Admin Activity**: `logName="projects/{project}/logs/cloudaudit.googleapis.com%2Factivity"`
- **Data Access**: `logName="projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access"`
- **System Event**: `logName="projects/{project}/logs/cloudaudit.googleapis.com%2Fsystem_event"`

Key fields in log entries:
```
protoPayload.methodName      — API method called (e.g. "storage.buckets.list")
protoPayload.authenticationInfo.principalEmail — caller identity
protoPayload.requestMetadata.callerIp          — source IP
protoPayload.serviceName     — GCP service (e.g. "storage.googleapis.com")
protoPayload.resourceName    — full resource path
protoPayload.status.code     — gRPC status code (0=OK, 7=PERMISSION_DENIED)
```

### attack.py — GCP SDK error handling
GCP SDK exceptions use `google.api_core.exceptions`:

```python
from google.api_core.exceptions import PermissionDenied, NotFound, GoogleAPIError

try:
    result = client.some_operation(...)
except PermissionDenied as e:
    print_err(f"Permission denied: {e.message}")
except NotFound as e:
    print_err(f"Resource not found: {e.message}")
except GoogleAPIError as e:
    print_err(f"GCP API error: {e}")
```

### VPC networks — use custom mode, not auto mode
Auto-mode VPC networks create subnets in every region automatically, which is noisy and hard to control. For emulation labs, use custom mode:

```python
vpc = gcp.compute.Network(
    "emulation-vpc",
    project=project,
    auto_create_subnetworks=False,  # custom mode
    opts=pulumi.ResourceOptions(depends_on=[compute_api]),
)
subnet = gcp.compute.Subnetwork(
    "emulation-subnet",
    project=project,
    network=vpc.id,
    region="us-central1",
    ip_cidr_range="10.10.0.0/24",
)
```

### Firewall rules — deny-by-default with explicit ingress allow
GCP VPC has implicit deny-all ingress by default. Add only the necessary allow rules:

```python
gcp.compute.Firewall(
    "allow-ssh-operator",
    project=project,
    network=vpc.id,
    direction="INGRESS",
    allows=[gcp.compute.FirewallAllowArgs(protocol="tcp", ports=["22"])],
    source_ranges=["OPERATOR_IP/32"],  # replace with real operator IP
)
```

### Pulumi exports — use Output.apply for computed values
GCP resource IDs are often computed from project + resource name. Use `apply` to derive them:

```python
bucket_url = bucket.name.apply(lambda n: f"gs://{n}")
pulumi.export("bucket_url", bucket_url)
```
