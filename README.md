# Autonomous Deception Intelligence Platform

Honeytoken-based active defense platform: generate decoy assets (trackable
PDFs, bait `.env` files, fake API endpoints), catch any interaction with
them via a FastAPI webhook, enrich + triage the event with a LangChain +
Groq AI agent, and review/approve containment actions from a Streamlit
dashboard.

## Architecture

```
Honeytoken Generator ──creates──▶ PDF / .env / endpoint (embeds canary URL)
                                            │
                          attacker interacts with bait
                                            ▼
                        FastAPI Webhook Listener (/api/canary/{token_id})
                                            │
                              logs raw event to SQLite instantly
                                            │ (background task, non-blocking)
                                            ▼
                    IP Enrichment (ipapi.co) + Groq LLM Triage Agent
                                            │
                         writes intent score / severity / proposed action
                                            ▼
                          Streamlit Dashboard (polls REST API)
                                            │
                        analyst approves / dismisses containment action
```

## Setup

1. **Install dependencies**

   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure environment variables**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set `GROQ_API_KEY` (free tier at https://console.groq.com/keys).
   Then export them into your shell before running (or use `python-dotenv` /
   `direnv` if you prefer auto-loading):

   ```bash
   export $(cat .env | grep -v '^#' | xargs)
   ```

3. **Run the backend**

   ```bash
   cd backend
   uvicorn main:app --reload --port 8000
   ```

   Visit `http://localhost:8000/health` — you should see `{"status": "ok"}`.
   Interactive API docs: `http://localhost:8000/docs`.

4. **Run the dashboard** (in a second terminal)

   ```bash
   cd frontend
   streamlit run dashboard.py
   ```

   Opens at `http://localhost:8501`.

5. **(Optional) Expose publicly for a live demo**

   ```bash
   ngrok http 8000
   ```

   Copy the `https://xxxx.ngrok-free.app` URL into `.env` as
   `CALLBACK_BASE_URL`, restart the backend, and any tokens you generate
   after that will embed the public callback URL instead of localhost.

## Testing the trap end-to-end

1. In the dashboard sidebar, generate a **Bait .env file** token.
2. Note the `canary_url` shown (e.g. `http://localhost:8000/api/canary/ab12cd34ef56`).
3. Open that URL in a browser or `curl` it:

   ```bash
   curl http://localhost:8000/api/canary/ab12cd34ef56
   ```

4. Refresh the dashboard — within a few seconds the event appears in the
   **Live Alert Feed** with a geolocation, AI-generated intent score,
   severity, triage summary, and a proposed containment action you can
   approve, mark reviewed, or dismiss.

## Project structure

```
deception-platform/
├── backend/
│   ├── main.py                  # FastAPI app: webhook + REST API
│   ├── database.py               # SQLite persistence layer
│   ├── honeytoken_generator.py   # PDF / .env / endpoint token creation
│   ├── enrichment.py             # IP OSINT (ipapi.co) + benign-bot filter
│   └── agents.py                 # LangChain + Groq triage agent
├── frontend/
│   └── dashboard.py              # Streamlit threat dashboard
├── generated_tokens/              # Output dir for generated PDF/.env baits
├── requirements.txt
├── .env.example
└── README.md
```

## Known limitations (matches Q5 "Still Planned")

- Containment actions are analyst-approved status changes only; no live
  firewall/API integration is wired up yet.
- Single-model triage (Groq only) — no multi-model consensus loop yet.
- SQLite + in-process background tasks are fine for a demo; see Q3 in the
  pitch doc for the Postgres + Redis/Celery migration path at scale.
