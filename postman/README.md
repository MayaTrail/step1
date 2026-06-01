# MayaTrail API — Postman Workspace

This directory holds the MayaTrail API collection in two formats:

- **`backend/MayaTrail.postman_collection.json`** — single-file v2.1 export.
  Use this to import the collection into any Postman workspace.
- **`postman/collections/MayaTrail API/`** — per-request YAML tree written by
  Postman's Git Sync. Use this to review collection changes in PRs.

Both representations describe the same 27 endpoints across 5 folders.

---

## TL;DR

| You are a... | Start here |
|---|---|
| **Backend developer** wanting to test your changes | Section 2 (Setup) → Section 3 (Auth flow) |
| **Security researcher** running emulations against AWS | Section 2 (Setup) → Section 4 (Emulation lifecycle) |
| **Someone updating the collection** itself | Section 6 (Editing the collection) |

---

## 1. What's in the collection

Five folders, 27 endpoints total — every endpoint maps to a real Django view.

| Folder | Count | Purpose |
|--------|-------|---------|
| `Auth` | 10 | Registration, OTP verification, login, refresh, logout, password reset, Google OAuth, profile |
| `Connectors` | 2 | AWS role ARN verification, demo mode activation |
| `Emulations (Enterprise)` | 9 | Catalogue (list, estimate, techniques, detections, playbook), lifecycle (deploy, attack, poll, destroy) |
| `Stacks` | 4 | Read-only stack state (list, get, progress, delete) |
| `Logs` | 2 | Audit log entries |

All folders are listed in the order you'd typically use them: Auth first, then
Connectors to set up enterprise access, then Emulations to drive the platform,
with Stacks and Logs used as observability surfaces during the emulation flow.

---

## 2. Setup

### 2.1 Import the collection

Open Postman → click `Import` → drop in
`backend/MayaTrail.postman_collection.json` → select `Import as new` (or
`Replace existing` if you already have an older version).

If you have access to the MayaTrail Postman workspace, you can connect to it
via Git Sync instead — the YAML tree under `postman/collections/` will appear
automatically.

### 2.2 Configure the `base_url` variable

After import, open the collection root → `Variables` tab → confirm `base_url`
matches your backend:

| Environment | `base_url` |
|-------------|----------|
| Local Django (`python manage.py runserver`) | `http://localhost:8000` |
| Docker Compose with nginx | `http://localhost:80` |
| Staging / production | Set per environment |

The other collection variables (`token`, `refresh_token`, `stack_id`, `run_id`,
`emulation_type`) are populated automatically by the test scripts on requests
that need them — you should not have to set them by hand.

### 2.3 Bring up the backend

```bash
cd backend
cp .env.example .env       # one-time, fill in secrets
docker-compose up --build  # starts db, redis, backend, worker, ui, nginx
```

Wait until the worker logs show it has connected to the `enterprise` queue
before testing emulation endpoints — that worker runs Pulumi.

---

## 3. The Auth flow

Every authenticated request needs a JWT in the `Authorization: Bearer ...`
header. The collection handles this for you via the `token` variable, but you
have to populate it first.

### 3.1 First-time registration

| Step | Request | What it does |
|------|---------|---|
| 1 | `Auth / Register` | Creates an inactive user; sends OTP to email |
| 2 | `Auth / Verify OTP` | Activates the user using the OTP from email |
| 3 | `Auth / Login` | Returns JWT pair; test script stores `token` + `refresh_token` automatically |

After step 3, every other request in the collection will work.

### 3.2 Returning users

Just run `Auth / Login`. If your access token expires (default lifetime: 1 hour),
run `Auth / Refresh Token` — it uses the stored refresh token to mint a new
access token.

### 3.3 Google OAuth (alternative)

Run `Auth / Google OAuth` with an `id_token` from Google Identity Services.
Skips registration + OTP entirely.

### 3.4 Verify your session

Run `Auth / Get Profile (Me)`. The fields to check:

| Field | What it means |
|-------|---------------|
| `is_verified` | Email OTP confirmed |
| `is_enterprise` | Has `aws_role_arn` set — required for all emulation endpoints |
| `is_demo` | Switched to demo mode (mutually exclusive with enterprise) |
| `auth_method` | `password` or `google` |

---

## 4. The Emulation lifecycle (for security researchers)

This is the platform's main use case. It assumes you have a Postman session
authenticated as an enterprise user.

### 4.1 One-time: connect your AWS account

```
POST /api/connectors/aws/verify/
Body: { "role_arn": "arn:aws:iam::<your-account-id>:role/MayaTrailEnterpriseRole" }
```

This sets `aws_role_arn` on your user and flips `is_enterprise=True`. The role
must have a trust policy allowing the MayaTrail server's IAM principal.

### 4.2 Browse the emulation catalogue

| Request | Purpose |
|---------|---------|
| `Emulations / List Emulations` | What's available — currently SCARLETEEL |
| `Emulations / Get Estimate — SCARLETEEL` | Live cost estimate via `pulumi preview` + AWS Pricing API |
| `Emulations / Get Techniques — SCARLETEEL` | MITRE ATT&CK kill chain + technique mappings |
| `Emulations / Get Detections — SCARLETEEL` | SIGMA + KQL detection rules |
| `Emulations / Get Playbook — SCARLETEEL` | IR playbook in markdown |

None of these touch AWS. Run them first to understand what you're about to
deploy and what it'll cost.

### 4.3 Deploy → attack → destroy

```
1. POST /api/emulations/deploy/
   Body: { "emulation_type": "scarleteel", "stack_name": "scar-<initials>" }
   → 202 { stackId, stackName }
   → stack_id is captured automatically
```

Poll progress while it deploys:

```
2. GET  /api/stacks/{{stack_id}}/progress/   every 3–5s
   → watch resources_created climb to total_resources (19 for SCARLETEEL)
   → watch percentage move 0 → 99

3. GET  /api/stacks/{{stack_id}}/            every 5s
   → status: deploying → ec2_booting → ready_for_attack
```

Once `ready_for_attack`:

```
4. POST /api/emulations/{{stack_id}}/attack/
   → 202 { runId }
   → run_id is captured automatically

5. GET  /api/emulations/{{run_id}}/          every 5s
   → status: pending → running → completed (or failed)
   → phase_current climbs 1 → 6
   → stdout contains live attack output
```

When the attack completes, tear it down:

```
6. POST /api/emulations/{{stack_id}}/destroy/
   → 202 { detail: "Destroy queued.", stackId }

7. GET  /api/stacks/{{stack_id}}/   until 404
   → 404 means the record is gone, destroy completed successfully
```

### 4.4 What "completed" looks like for SCARLETEEL

The attack runs 6 MITRE-mapped phases against the deployed infra:

| Phase | Action | What confirms success in `stdout` |
|-------|--------|-----------------------------------|
| 1 — Initial Access | RCE on Flask container via `POST /cmd` | Cryptominer decoy output appears |
| 2 — Credential Access | IMDSv1 credential theft via curl from the container | Access key + secret + session token printed |
| 3 — Discovery | List S3 + Secrets Manager with stolen creds | Bucket and secret names listed |
| 4 — Defense Evasion | `cloudtrail:StopLogging` on the trail | "CloudTrail stopped" message (or graceful skip) |
| 5 — Lateral Movement | `secretsmanager:GetSecretValue` on planted secret | Secret value printed |
| 6 — Persistence | `lambda:CreateFunction` for backdoor | Lambda ARN printed |

### 4.5 Known gotcha — the Lambda backdoor

Phase 6 creates a Lambda function (`mayatrail-scarleteel-backdoor`) using
**boto3 directly** — not via Pulumi. That means `pulumi destroy` doesn't know
about it, and it survives the teardown.

**Today:** delete it manually from the AWS console or via CLI before declaring
your test environment clean. This is tracked as a backlog item — auto-cleanup
in `destroy_emulation_stack` is planned.

### 4.6 Recovering a stuck stack

If a stack gets stuck in `deploying`, `ec2_booting`, `attacking`, or `failed`,
call `Emulations / Destroy Emulation Stack` directly. That endpoint accepts
any status except `destroying`, so it will force-tear-down the stuck stack.

---

## 5. The development workflow (for backend engineers)

### 5.1 Testing your endpoint changes

1. Make your Django changes
2. `docker-compose restart backend worker_enterprise`
3. Run the affected request in Postman
4. Check the test script results in the `Test Results` tab — most requests have
   assertions about response shape

If you've changed the response shape, the test script will fail. Update both
the test script and any downstream requests that consume the changed fields.

### 5.2 Adding a new endpoint to the collection

The canonical source is `backend/MayaTrail.postman_collection.json`. Two paths:

**Path A — Edit in Postman UI (recommended if you have workspace access):**

1. Open the collection in Postman
2. Right-click the relevant folder → `Add Request`
3. Fill in method, URL, headers, body, description
4. Save — Postman writes both the YAML tree and updates its internal state
5. Export the collection: collection menu → `Export` → v2.1 → overwrite
   `backend/MayaTrail.postman_collection.json`
6. Commit both files

**Path B — Edit the JSON directly:**

1. Add the new request object inside the right `item` array in the JSON
2. Validate: `python -c "import json; json.load(open('backend/MayaTrail.postman_collection.json'))"`
3. Re-import into Postman to refresh the YAML tree, OR commit just the JSON
   and let the next person with Postman UI access regenerate the YAML

**What goes in each new request:**

- `method` and full URL using `{{base_url}}` and any `{{stack_id}}`-style vars
- `description` — at minimum, what the endpoint does, expected responses,
  any permission requirements
- Test script (in `event[].script.exec`) that captures response IDs into
  collection variables if downstream requests depend on them

### 5.3 Common test script patterns

**Capture an ID:**
```javascript
if (pm.response.code === 202) {
    const body = pm.response.json();
    pm.collectionVariables.set('stack_id', body.stackId);
}
```

**Assert response shape:**
```javascript
pm.test('Has required fields', () => {
    const body = pm.response.json();
    pm.expect(body).to.have.all.keys('stack_id', 'status', 'percentage');
});
```

---

## 6. Editing the collection — which file is canonical?

Today, **the JSON is canonical** for portability reasons (it works for anyone
without Postman workspace access). The YAML tree is auto-generated by
Postman's Git Sync when the workspace is connected.

| Scenario | What to edit |
|----------|--------------|
| You're modifying the API surface and updating Postman | JSON, then re-import to refresh YAML |
| You only have Postman workspace access (no local clone) | YAML (auto-written), then export JSON for the repo |
| You're reviewing a PR | Read the YAML diff — it's per-request, easier to review |

The YAML diff is the **review surface**; the JSON is the **distribution
artifact**. Keep them in sync — never commit one without the other.

---

## 7. Endpoint quick reference

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/auth/register/` | Create user (inactive) + send OTP |
| POST | `/api/auth/register/verify-otp/` | Activate user via OTP |
| POST | `/api/auth/register/resend-otp/` | Re-send OTP |
| POST | `/api/auth/login/` | Get JWT pair |
| POST | `/api/auth/refresh/` | Refresh access token |
| GET | `/api/auth/me/` | Authenticated user profile |
| POST | `/api/auth/logout/` | Blacklist refresh token |
| POST | `/api/auth/forgot-password/` | Send password-reset OTP |
| POST | `/api/auth/reset-password/` | Reset password with OTP |
| POST | `/api/auth/google/` | Google OAuth single-step login |
| POST | `/api/connectors/aws/verify/` | Verify AWS role ARN via STS |
| POST | `/api/connectors/demo/` | Activate demo mode (one-time) |
| GET | `/api/emulations/` | List available emulations |
| GET | `/api/emulations/{type}/estimate/` | Live cost estimate |
| GET | `/api/emulations/{type}/techniques/` | MITRE ATT&CK mappings |
| GET | `/api/emulations/{type}/detections/` | SIGMA + KQL rules |
| GET | `/api/emulations/{type}/playbook/` | IR playbook markdown |
| POST | `/api/emulations/deploy/` | Deploy an emulation stack |
| POST | `/api/emulations/{stack_id}/attack/` | Trigger attack chain |
| GET | `/api/emulations/{run_id}/` | Poll EmulationRun status |
| POST | `/api/emulations/{stack_id}/destroy/` | Tear down emulation stack |
| GET | `/api/stacks/` | List user's stacks |
| GET | `/api/stacks/{id}/` | Get stack by UUID |
| GET | `/api/stacks/{id}/progress/` | Live deployment progress |
| DELETE | `/api/stacks/{id}/` | Delete stack DB record only |
| GET | `/api/logs/` | Audit log entries |
| GET | `/api/logs/{id}/` | Single audit log entry |

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `401 Unauthorized` on any authenticated request | Access token expired (1 hour lifetime) | Run `Auth / Refresh Token` |
| `403 Forbidden` on emulation endpoints | User is not enterprise (`aws_role_arn` empty) | Run `Connectors / Verify AWS Connector` |
| `409 Conflict` on `Deploy Emulation Stack` | You already have an active emulation stack | Destroy it first, or use the returned `stackId` |
| `404` on `Stack Deployment Progress` after destroy | Stack record was deleted on successful destroy | Expected — stop polling |
| Stack stuck in `deploying` for >5 min, `percentage` not climbing | Celery `enterprise` queue not running | Check `docker-compose logs worker_enterprise` |
| Stack stuck in `ec2_booting` for >15 min | EC2 user-data script failed or container build broken | Check the EC2 instance's system log in AWS console |
| Attack `failed` immediately | IMDSv1 unreachable or vuln-app container not running | Re-deploy; verify EC2 health checks pass |
| `Get Estimate` returns `source: manifest-fallback` | Worker couldn't run `pulumi preview` or AWS Pricing API denied | Check worker logs; fall back is acceptable for testing |
| Postman shows `HTTP Request not found` | Stale tab pointing to a deleted request | Close all tabs, re-import collection |

---

## 9. Where things live

```
step1/
├── backend/
│   └── MayaTrail.postman_collection.json    # canonical JSON export
├── postman/
│   ├── README.md                            # this file
│   ├── collections/MayaTrail API/           # Git Sync YAML tree
│   │   ├── Auth/
│   │   ├── Connectors/
│   │   ├── Emulations (Enterprise)/
│   │   ├── Logs/
│   │   └── Stacks/
│   ├── environments/                        # (reserved — not currently used)
│   ├── flows/                               # (reserved — Postman Flows)
│   ├── globals/                             # (reserved — Postman globals)
│   ├── mocks/                               # (reserved — Postman mocks)
│   └── specs/                               # (reserved — OpenAPI / API specs)
└── CLAUDE.md                                # project-wide conventions
```

---

## 10. When something changes

If you change the API surface:
1. Update Django code
2. Update the Postman collection (JSON + YAML)
3. Update this README's endpoint table if a route was added/removed/renamed
4. Update `backend/changelog.md`
5. Open a PR with both representations of the collection in the same commit

If you're not sure what's canonical, ask before editing — the answer is
currently "JSON is canonical, YAML is auto-generated", but that policy may
evolve.
