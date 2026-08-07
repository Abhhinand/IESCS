# Autonomous Deception Intelligence Platform

An active-defense platform that generates honeytokens (decoy credentials,
documents, source-code secrets, and cloud config), detects any interaction
with them through a webhook listener, enriches and triages each event with
an AI agent, and surfaces the result on a live threat dashboard for
analyst review.

The core premise: legitimate users and systems have no reason to ever
touch a decoy asset. Any interaction with one is therefore a high-signal
indicator of compromise — not noise that needs filtering, but a near-zero
false-positive alert.

---

## System Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                          BACKEND (FastAPI)                        │
│                                                                     │
│   honeytoken_generator.py                                          │
│   ─────────────────────────                                        │
│   Creates decoy assets (PDF, .env, source code, cloud creds,       │
│   fake endpoints). Each one embeds a unique canary URL:            │
│   http://<host>:8000/api/canary/{token_id}                         │
│                                                                     │
│                          │ registers token                         │
│                          ▼                                         │
│   database.py  ──────────────────────  SQLite (deception.db)       │
│   Two tables: honeytokens, events                                  │
│                                                                     │
│                          ▲                                         │
│                          │ logs event instantly                    │
│                                                                     │
│   main.py  (FastAPI app / webhook listener)                        │
│   ─────────────────────────────────────────                        │
│   GET/POST /api/canary/{token_id}  ← the trap itself                │
│     1. looks up the token                                          │
│     2. captures IP, headers, user-agent, timestamp                 │
│     3. writes the raw event to SQLite                              │
│     4. returns an innocuous 200 response immediately                │
│     5. schedules background enrichment (does NOT block the reply)  │
│                          │                                          │
│                          ▼ (background task)                       │
│   enrichment.py                     agents.py                      │
│   ───────────────                   ──────────                     │
│   • is_known_benign() — filters      • LangChain + Groq LLM         │
│     known crawler/bot user-agents      chain (llama-3.3-70b)        │
│     before any AI call is made       • scores intent (0-100),       │
│   • enrich_ip() — calls ipapi.co       assigns severity,            │
│     for geolocation/ASN data           writes a triage summary      │
│                                         and a proposed containment   │
│                                         action                      │
│                          │                                          │
│                          ▼                                          │
│   database.py — writes enrichment + AI results back to the event   │
│                                                                     │
│   REST API for the dashboard:                                      │
│   GET  /api/tokens, /api/events, /api/events/{id}                  │
│   POST /api/tokens/*, /api/events/{id}/status                      │
└───────────────────────────────────────────────────────────────────┘
                          ▲
                          │ HTTP requests only (requests library)
                          │ frontend never touches the database directly
                          ▼
┌───────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Streamlit)                       │
│                                                                     │
│   dashboard.py                                                     │
│   • sidebar: generate a new honeytoken (calls POST /api/tokens/*)  │
│   • metrics: active tokens, total events, high/critical alerts     │
│   • map: attacker geolocation (from geo_json)                      │
│   • chart: severity breakdown                                      │
│   • live alert feed: sortable event table                          │
│   • event detail: AI summary + proposed action + Approve/Review/   │
│     Dismiss buttons (POST /api/events/{id}/status)                 │
└───────────────────────────────────────────────────────────────────┘
```

The backend and frontend are two independent processes that only
communicate over HTTP (REST). The frontend never imports or calls
backend Python code directly, and never touches SQLite — this keeps the
UI swappable (e.g. for a different dashboard or a mobile client) without
any backend changes.

---

## End-to-End Workflow

**1. Token generation**
Analyst picks a token type in the dashboard → dashboard sends
`POST /api/tokens/<type>` → `honeytoken_generator.py` builds the decoy
file (or registers a fake endpoint), embeds a unique `canary_url`, and
registers it in the `honeytokens` table via `database.py`.

**2. Deployment**
The generated file is placed wherever the decoy is meant to be
discovered (a shared drive, a fake `.env`, a leaked config file, etc.).
This step is currently manual — see [Known Limitations](#known-limitations).

**3. Trigger**
Anyone or anything that opens the file, reads the fake credentials, or
probes the fake endpoint ends up requesting the embedded `canary_url`.
This hits `main.py`'s `/api/canary/{token_id}` route.

**4. Instant logging, deferred analysis**
The route logs the raw event (IP, user-agent, headers, timestamp) to
SQLite and returns a deliberately unremarkable response
(`{"status": "verified", ...}`) — so the interaction doesn't reveal to
whoever/whatever triggered it that a trap just fired. The expensive work
(IP lookup, AI reasoning) is scheduled as a FastAPI `BackgroundTask`,
which runs *after* the response has already been sent. This keeps the
webhook's response latency low regardless of how slow the AI call is.

**5. Enrichment**
In the background: `enrichment.py` checks the user-agent against a list
of known benign bots/crawlers (skips the AI entirely if matched) and
calls `ipapi.co` to resolve the IP to a city/country/ASN.

**6. AI triage**
`agents.py` sends the event context (token type, IP, geolocation,
user-agent, request frequency) to a Groq-hosted LLM through a LangChain
prompt chain. The model returns a structured JSON verdict: an intent
score (0-100), a severity tier (LOW/MEDIUM/HIGH/CRITICAL), a one-sentence
human-readable summary, and a proposed containment action. Failed calls
retry up to 3 times before falling back to a safe MEDIUM/manual-review
default, so a transient network issue never silently drops an event.

**7. Review**
The dashboard polls `/api/events` and displays the enriched event in the
Live Alert Feed, on the geolocation map, and in the severity chart. The
analyst opens the event detail view, reads the AI's summary and proposed
action, and clicks Approve / Mark Reviewed / Dismiss — which sends
`POST /api/events/{id}/status` and updates the record.

---

## Design Decisions

| Decision | Rationale |
|---|---|
| FastAPI (async) for the webhook | High-throughput, low-latency ingestion even under rapid scanning/probing |
| SQLite | Zero-setup embedded persistence, sufficient for single-instance/demo scale |
| Background tasks instead of a queue | Decouples slow AI inference from the webhook's response time without needing extra infrastructure (Celery/Redis) at this scale |
| Groq as the LLM backend | Fast inference keeps the async triage pipeline from becoming a bottleneck |
| Benign-bot + IP enrichment before AI | Avoids spending an LLM call on traffic that's cheaply identifiable as harmless |
| Frontend talks to backend only via REST | Keeps the two layers independently deployable/replaceable |

---

## Data Model (SQLite)

**`honeytokens`**
`token_id` (PK) · `token_type` · `bait_name` · `created_at` · `location_hint` · `active`

**`events`**
`event_id` (PK) · `token_id` (FK) · `timestamp` · `ip_address` · `user_agent` ·
`headers_json` · `request_path` · `method` · `geo_json` · `intent_score` ·
`severity` · `triage_summary` · `proposed_action` · `status`

---

## Project Structure

```
deception-platform/
├── backend/
│   ├── main.py                  # FastAPI app: webhook + REST API + background pipeline
│   ├── database.py              # SQLite schema + all read/write functions
│   ├── honeytoken_generator.py  # Builds each decoy type + registers its canary token
│   ├── enrichment.py            # Bot filtering + IP geolocation (ipapi.co)
│   └── agents.py                # LangChain + Groq AI triage chain
├── frontend/
│   └── dashboard.py             # Streamlit dashboard (REST client only)
├── generated_tokens/            # Output directory for generated decoy files
├── requirements.txt
├── .env.example
├── start.ps1                    # One-click launcher (Windows/PowerShell)
└── README.md
```

---

## Honeytoken Types Implemented

| Type | File | What it simulates |
|---|---|---|
| Trackable PDF | `generate_pdf_token()` | A confidential document with an embedded verification link |
| Bait `.env` file | `generate_env_token()` | Leaked application secrets (DB password, AWS keys) |
| Fake API endpoint | `generate_api_endpoint_token()` | A hidden/undocumented admin route |
| Source-code secret | `generate_source_code_token()` | A hardcoded API key in a `config.py`/`.js` file, meant to sit in a real codebase |
| Cloud credentials | `generate_cloud_credentials_token()` | A leaked AWS-style `credentials` file with decoy access keys and a decoy S3 bucket |

---

## Known Limitations

- **Canary deployment is manual.** Generated files are written locally
  (`generated_tokens/`); the platform does not yet automatically place
  them on remote file systems, shared drives, or live cloud environments.
- **Containment is analyst-approved, not automatic.** Approving an event
  updates its status; it does not yet call a real firewall/IAM API to
  block an IP or revoke a credential.
- **Single-model triage.** Only one LLM (via Groq) is used — no
  multi-model consensus/voting.
- **SQLite is single-writer.** Sufficient for demo/single-instance use;
  under concurrent high-volume writes this would need to migrate to
  PostgreSQL with connection pooling.

---

## Setup

```bash
python -m venv venv
# Windows: venv\Scripts\Activate.ps1   |   macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in GROQ_API_KEY (https://console.groq.com/keys)

# Terminal 1
cd backend && uvicorn main:app --reload --port 8000

# Terminal 2
cd frontend && streamlit run dashboard.py
```

`.env`'s `CALLBACK_BASE_URL` can be left unset to auto-detect the
machine's LAN IP (so canary URLs work from other devices on the same
network), or set explicitly to `localhost` or a public tunnel URL
(e.g. ngrok) as needed.

On Windows, `start.ps1` launches both servers in separate terminal
windows in one step: `.\start.ps1` from the project root.
