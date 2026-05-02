## TASK: IMPLEMENT ATTACK SCRIPT

Generate a SINGLE `attack.py` that implements the complete attack chain with credential chaining.

### Requirements:
- ONE file, ONE main() function, sequential phases matching the attack plan
- Credential chaining: follow the `credential_chain` from the attack plan exactly
  - Steal creds in the designated phase, create a session, use in all subsequent phases
  - If multiple credential pivots exist, manage multiple sessions
- Implement EVERY step from the `attack_chain` in order
- For each `execution_context`, use the appropriate method:
  - `container_attack`: HTTP POST to the vulnerable app endpoint (requests library)
  - `api_attack`: boto3/SDK calls using the stolen session
  - `sso_attack`: SAML/OAuth/OIDC federation flows
  - `saas_attack`: SaaS API calls using stolen tokens
  - `idp_attack`: Identity provider API manipulation
  - `lateral_movement`: Pivoting using harvested credentials
- If the attack plan includes a container/app RCE step, implement wait_for_app() to poll until ready
- op_delay(min, max) between API calls for realistic tempo
- phase_delay() between major phases
- Print progress: [*] for actions, [+] for success, [-] for errors
- Handle expected errors gracefully (AccessDenied, NoSuchEntity, etc.)
- Document tradecraft notes inline (why the real APT did something)
- Return/print a summary at the end listing all events generated

### Structure:
```python
"""
{APT_NAME} — Automated Post-Exploitation Attack Script
Executes a {N}-phase attack chain matching the approved attack plan.
"""
import sys, time, random, json

# Cross-platform UTF-8 output — prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Import SDK libraries as needed: boto3, requests, msal, okta, etc.

def print_step(msg): print(f"\n[*] {msg}")
def op_delay(min_s=2, max_s=6): time.sleep(random.uniform(min_s, max_s))
def phase_delay(): time.sleep(random.uniform(5, 15))

# Add helper functions matching the attack plan's execution contexts:
# - exploit_rce(url, cmd) for container_attack
# - wait_for_app(url, max_wait=300) for app readiness polling
# - SDK session creation for credential pivots

def main(target_info):
    # Phase 1: Initial access + credential theft
    # (Method depends on the attack plan — IMDS, phishing, token theft, etc.)
    
    # Create session from stolen credentials
    stolen_session = create_session_from_stolen_creds(creds)
    
    # Subsequent phases: use stolen_session for all calls
    # Follow the attack_chain step by step
    # ...

if __name__ == '__main__':
    main(sys.argv[1])
```

### IAM backdoor user cleanup (T1070)
When deleting a backdoor IAM user, always enumerate ALL access keys before calling `delete_user` — not just the key captured during creation. Previous crashed runs may leave additional active keys, causing `DeleteConflict`. Pattern:
```python
all_keys = iam.list_access_keys(UserName=USERNAME)["AccessKeyMetadata"]
for key in all_keys:
    iam.delete_access_key(UserName=USERNAME, AccessKeyId=key["AccessKeyId"])
iam.delete_user(UserName=USERNAME)
```
