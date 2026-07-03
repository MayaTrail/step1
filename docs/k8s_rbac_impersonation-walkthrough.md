# k8s_rbac_impersonation — End-to-End Test Walkthrough

Date: 2026-07-02  
Branch: `k8s_emulation`  
Stack deployed to: `ap-south-1`

---

## 1. Start the stack

```bash
docker-compose up --build
```

Wait until the backend prints `Booting worker with pid: ...`.

---

## 2. Create an enterprise user

```bash
docker-compose exec backend python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); u = User.objects.create_user(username='testadmin1', email='test@test1.com', password='testpass123', is_active=True); u.is_enterprise = True; u.save(); print('Created:', u.username, '| enterprise:', u.is_enterprise)"
```

**Output:**
```
Created: testadmin1 | enterprise: True
```

Then mark the user as verified (required by `IsEnterpriseUser` permission):

```bash
docker-compose exec backend python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); u = User.objects.get(username='testadmin1'); u.is_verified = True; u.save(); print('is_verified:', u.is_verified)"
```

**Output:**
```
is_verified: True
```

---

## 3. Get a JWT access token

```powershell
$resp = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/auth/login/" -ContentType "application/json" -Body '{"username": "testadmin1", "password": "testpass123"}'
$TOKEN = $resp.access
$TOKEN
```

**Output:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNz
gyOTk1OTcyLCJpYXQiOjE3ODI5OTIzNzIsImp0aSI6IjMyM2I5MmNmN2Q4YTQ0MGFiNTY4YjIzNGI0
ZGJjYmE4IiwidXNlcl9pZCI6MTAsInVzZXJuYW1lIjoidGVzdGFkbWluMSIsImlzX3ZlcmlmaWVkIjp
mYWxzZSwiaXNfZGVtbyI6ZmFsc2UsImRlbW9fdXNlZCI6ZmFsc2UsImRlbW9fZXhwaXJlc19hdCI6bn
VsbCwiYXV0aF9tZXRob2QiOiJjcmVkZW50aWFscyJ9.4m3etem2az3YaMdXvwqyJUWHtwaeXMnNqa14
M5MJsqc
```

---

## 4. Deploy the emulation stack

```powershell
$deploy = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/emulations/deploy/" -ContentType "application/json" -Headers @{Authorization="Bearer $TOKEN"} -Body '{"emulation_type": "k8s_rbac_impersonation", "stack_name": "k8s-rbac-test1"}'
$STACK_ID = $deploy.stackId
$deploy
```

**Output:**
```
stackId                              stackName
-------                              ---------
2a6c19db-bcb7-4066-9090-2c39f5b7044b k8s-rbac-test1
```

Pulumi provisions: VPC, subnet, internet gateway, route table, security group, EC2 (Amazon Linux 2023, t3.micro), Flask simulator on port 8080.

---

## 5. Poll until ready

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8000/api/stacks/$STACK_ID/" -Headers @{Authorization="Bearer $TOKEN"}
```

**Output (when ready, ~3 min):**
```
id               : 2a6c19db-bcb7-4066-9090-2c39f5b7044b
name             : k8s-rbac-test1
region           : ap-south-1
status           : ready_for_attack
outputs          : @{vuln_instance_ip=13.201.122.179}
owner            : testadmin1
emulation_type   : k8s_rbac_impersonation
expires_at       : 2026-07-02T13:42:21.998321Z
```

Status transitions: `deploying` → `ec2_booting` → `ready_for_attack`

---

## 6. Trigger the attack

```powershell
$run = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/emulations/$STACK_ID/attack/" -Headers @{Authorization="Bearer $TOKEN"} -ContentType "application/json"
$RUN_ID = $run.runId
$run
```

**Output:**
```
runId                                stackId
-----                                -------
caa85015-26f4-4af4-92e4-8e8d499bb7e2 2a6c19db-bcb7-4066-9090-2c39f5b7044b
```

---

## 7. Poll the run result

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8000/api/emulations/$RUN_ID/" -Headers @{Authorization="Bearer $TOKEN"}
```

**Output:**
```
id             : caa85015-26f4-4af4-92e4-8e8d499bb7e2
stack          : 2a6c19db-bcb7-4066-9090-2c39f5b7044b
emulation_type : k8s_rbac_impersonation
status         : completed
phase_current  : 0
phase_total    : 2
stdout         : [*] Waiting for simulator to become ready...
                 [+] Simulator is ready.
                 [*] Phase 1: Self Subject Rules Review (Permission Enumeration)
                 [+] Successfully queried SelfSubjectRulesReviews!
                 [+] Permissions returned: [{'apiGroups': ['*'], 'resources': ['serviceaccounts'], 'verbs': ['impersonate']}, {'apiGroups':
                 ['authorization.k8s.io'], 'resources': ['selfsubjectrulesreviews'], 'verbs': ['create']}]
                 [*] Phase 2: Attempting Privilege Escalation via Impersonation
                 [+] Privilege Escalation Successful!
                 [+] Retrieved Secret: {'items': [{'data': {'password': 'c3VwZXItc2VjcmV0LWszcw=='}, 'metadata': {'name': 'db-credential'}}]}
stderr         :
started_at     : 2026-07-02T11:46:10.182236Z
completed_at   : 2026-07-02T11:46:10.419976Z
```

### Attack phases

| Phase | Technique | Result |
|-------|-----------|--------|
| 1 | T1069 — Permission Groups Discovery via `SelfSubjectRulesReview` | Found `impersonate` verb on service accounts |
| 2 | T1548 — Abuse Elevation Control via `Impersonate-User: admin-sa` + `Impersonate-Group: system:masters` headers | Retrieved secret `db-credential` (`super-secret-k3s`) |

---

## 8. Destroy the stack

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/emulations/$STACK_ID/destroy/" -Headers @{Authorization="Bearer $TOKEN"} -ContentType "application/json"
```

Pulumi tears down all 7 resources. Stack DB record is deleted on success.

---

## Notes

- `IsEnterpriseUser` permission checks `is_verified=True` (not `is_enterprise`) — both flags must be set when creating test users via shell.
- The Flask simulator on the EC2 instance mocks the Kubernetes API; no real cluster is deployed.
- The secret password base64-decodes to `super-secret-k3s`.
- Total wall time deploy→attack→destroy: ~5 minutes. AWS cost per run: ~$0.01.
