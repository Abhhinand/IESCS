"""
honeytoken_generator.py
Generates decoy assets (trackable PDFs, bait .env files) whose access
triggers a webhook call back to our FastAPI listener.
"""

import os
import uuid
import random
import string
import socket

from fpdf import FPDF

from database import register_token

GENERATED_DIR = os.path.join(os.path.dirname(__file__), "..", "generated_tokens")
os.makedirs(GENERATED_DIR, exist_ok=True)


def _detect_lan_ip() -> str:
    """
    Best-effort detection of this machine's local network IP (e.g.
    192.168.x.x), so honeytoken canary URLs are reachable from other
    devices (like a phone) on the same WiFi - not just from this machine.
    Falls back to localhost if detection fails (e.g. no network at all).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't actually send data - just asks the OS which local
            # interface/IP would be used to reach an external address.
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "localhost"


# Base URL the canary callback points at.
# Priority: explicit CALLBACK_BASE_URL in .env > auto-detected LAN IP > localhost.
# Using the LAN IP by default means canary URLs work from your phone or any
# other device on the same WiFi network without any manual configuration.
# Set CALLBACK_BASE_URL explicitly in .env to override (e.g. for an ngrok
# public URL, or to force localhost-only for a quick solo test).
if os.environ.get("CALLBACK_BASE_URL"):
    CALLBACK_BASE_URL = os.environ["CALLBACK_BASE_URL"]
else:
    CALLBACK_BASE_URL = f"http://{_detect_lan_ip()}:8000"

print(f"[honeytoken_generator] Canary URLs will use base: {CALLBACK_BASE_URL}")


def _new_token_id() -> str:
    return uuid.uuid4().hex[:12]


def generate_pdf_token(bait_name: str = "Employee_Salary_Report_2026.pdf",
                        location_hint: str = "shared_drive/HR/") -> dict:
    """
    Creates a PDF that embeds a tracking pixel / link pointing at our
    canary endpoint. Opening the PDF (in a viewer that fetches remote
    resources) or clicking the embedded link fires the webhook.
    """
    token_id = _new_token_id()
    canary_url = f"{CALLBACK_BASE_URL}/api/canary/{token_id}"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=14)
    pdf.cell(0, 10, "CONFIDENTIAL - Internal Use Only", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.ln(5)
    pdf.multi_cell(0, 8,
        "This document contains sensitive compensation data for the 2026 "
        "fiscal year. Distribution outside of Human Resources is strictly "
        "prohibited.\n\nClick the verification link below to confirm access "
        "authorization before viewing payroll tables."
    )
    pdf.ln(5)
    pdf.set_text_color(0, 0, 255)
    pdf.cell(0, 10, "Verify Access", ln=True, link=canary_url)

    file_path = os.path.join(GENERATED_DIR, f"{token_id}_{bait_name}")
    pdf.output(file_path)

    register_token(token_id, "pdf", bait_name, location_hint)

    return {
        "token_id": token_id,
        "type": "pdf",
        "file_path": file_path,
        "canary_url": canary_url,
        "bait_name": bait_name,
    }


def _fake_secret(prefix: str, length: int = 32) -> str:
    chars = string.ascii_letters + string.digits
    return prefix + "".join(random.choices(chars, k=length))


def generate_env_token(bait_name: str = ".env", location_hint: str = "app_root/") -> dict:
    """
    Creates a fake .env credentials file. The 'AWS_SECRET_ACCESS_KEY' and
    'DATABASE_URL' are decoys; any use of them against our monitored canary
    endpoint / mock AWS credential validator fires the webhook.
    """
    token_id = _new_token_id()
    canary_url = f"{CALLBACK_BASE_URL}/api/canary/{token_id}"

    fake_access_key = "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    fake_secret_key = _fake_secret("", 40)
    fake_db_password = _fake_secret("Pg_", 20)

    content = f"""# Application Environment Configuration
APP_ENV=production
APP_SECRET_KEY={_fake_secret("sk_")}

DATABASE_URL=postgresql://admin:{fake_db_password}@internal-prod-db.company.local:5432/main

AWS_ACCESS_KEY_ID={fake_access_key}
AWS_SECRET_ACCESS_KEY={fake_secret_key}
AWS_REGION=us-east-1

# Canary verification endpoint - internal monitoring, do not remove
INTEGRITY_CHECK_URL={canary_url}
"""

    file_path = os.path.join(GENERATED_DIR, f"{token_id}_{bait_name}")
    with open(file_path, "w") as f:
        f.write(content)

    register_token(token_id, "env_file", bait_name, location_hint)

    return {
        "token_id": token_id,
        "type": "env_file",
        "file_path": file_path,
        "canary_url": canary_url,
        "bait_name": bait_name,
        "fake_access_key": fake_access_key,
    }


def generate_api_endpoint_token(bait_name: str = "/api/internal/admin-users",
                                 location_hint: str = "api_documentation") -> dict:
    """
    Registers a fake 'hidden' API endpoint token. No file is generated -
    the token is simply documented somewhere enticing (e.g. leaked in a
    JS bundle or fake API doc) and any hit on /api/canary/{token_id}
    is treated as a probe of a nonexistent admin route.
    """
    token_id = _new_token_id()
    canary_url = f"{CALLBACK_BASE_URL}/api/canary/{token_id}"

    register_token(token_id, "endpoint", bait_name, location_hint)

    return {
        "token_id": token_id,
        "type": "endpoint",
        "canary_url": canary_url,
        "bait_name": bait_name,
    }


def generate_source_code_token(bait_name: str = "config.py",
                                location_hint: str = "src/utils/") -> dict:
    """
    Creates a fake source-code file containing a hardcoded decoy secret,
    meant to be committed into a real (or mirror) git repository or
    dropped into a real codebase. Any tool, script, or human that reads
    this file and later uses the embedded credential/canary URL against
    our monitored endpoint fires the webhook.

    This covers the "source-code deception" category: attackers who dump
    repo contents, grep for secrets in git history, or scrape internal
    codebases are the intended targets - legitimate developers have no
    reason to load or execute this specific decoy module.
    """
    token_id = _new_token_id()
    canary_url = f"{CALLBACK_BASE_URL}/api/canary/{token_id}"

    fake_api_key = _fake_secret("sk_live_", 32)
    fake_db_pass = _fake_secret("", 18)

    # Choose a template based on file extension so the bait blends into
    # the surrounding codebase convention (Python vs JS/Node).
    ext = os.path.splitext(bait_name)[1].lower()

    if ext in (".js", ".ts"):
        content = f"""// Internal service configuration - DO NOT COMMIT TO PUBLIC REPOS
// Auto-generated by config bootstrap script

module.exports = {{
  env: "production",
  stripeApiKey: "{fake_api_key}",
  internalDbUrl: "postgres://svc_admin:{fake_db_pass}@db-internal.corp.local:5432/core",

  // Health-check ping used by the deploy pipeline - required, do not remove
  integrityCheckUrl: "{canary_url}",
}};
"""
    else:
        content = f'''"""
config.py - Internal service configuration
DO NOT COMMIT TO PUBLIC REPOSITORIES.
Auto-generated by the internal config bootstrap script.
"""

ENV = "production"

STRIPE_API_KEY = "{fake_api_key}"
INTERNAL_DB_URL = "postgresql://svc_admin:{fake_db_pass}@db-internal.corp.local:5432/core"

# Health-check ping used by the deploy pipeline - required, do not remove.
INTEGRITY_CHECK_URL = "{canary_url}"


def verify_config():
    """Called on service startup to confirm config integrity."""
    import urllib.request
    urllib.request.urlopen(INTEGRITY_CHECK_URL, timeout=3)
'''

    file_path = os.path.join(GENERATED_DIR, f"{token_id}_{bait_name}")
    with open(file_path, "w") as f:
        f.write(content)

    register_token(token_id, "source_code", bait_name, location_hint)

    return {
        "token_id": token_id,
        "type": "source_code",
        "file_path": file_path,
        "canary_url": canary_url,
        "bait_name": bait_name,
        "fake_api_key": fake_api_key,
    }


def generate_cloud_credentials_token(bait_name: str = "aws_credentials",
                                      location_hint: str = "~/.aws/credentials") -> dict:
    """
    Creates a fake cloud-provider credentials file (AWS-style shared
    credentials format) containing decoy access keys and a decoy S3
    bucket reference. This covers the "cloud deception" category:
    attackers who find leaked/exposed cloud credentials (e.g. in a
    misconfigured public repo, exposed .aws folder, or leaked CI
    artifact) and attempt to use them are the intended targets.

    The embedded canary URL simulates a "credential validation" call
    that a real AWS SDK bootstrap might make; any resolution of it is
    treated as an attempted use of the decoy cloud credentials.
    """
    token_id = _new_token_id()
    canary_url = f"{CALLBACK_BASE_URL}/api/canary/{token_id}"

    fake_access_key = "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    fake_secret_key = _fake_secret("", 40)
    fake_bucket = "corp-prod-backups-" + "".join(random.choices(string.digits, k=6))
    fake_account_id = "".join(random.choices(string.digits, k=12))

    content = f"""[default]
aws_access_key_id = {fake_access_key}
aws_secret_access_key = {fake_secret_key}
region = us-east-1

# Decoy resource references (for internal tooling context)
# account_id = {fake_account_id}
# primary_bucket = s3://{fake_bucket}/

# Internal credential-integrity validation endpoint - polled by the
# deploy pipeline on every SDK bootstrap. Do not remove this section.
[integrity_check]
validation_url = {canary_url}
"""

    file_path = os.path.join(GENERATED_DIR, f"{token_id}_{bait_name}")
    with open(file_path, "w") as f:
        f.write(content)

    register_token(token_id, "cloud_credentials", bait_name, location_hint)

    return {
        "token_id": token_id,
        "type": "cloud_credentials",
        "file_path": file_path,
        "canary_url": canary_url,
        "bait_name": bait_name,
        "fake_access_key": fake_access_key,
        "fake_bucket": fake_bucket,
    }
