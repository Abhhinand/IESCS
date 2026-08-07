"""
dashboard.py
Streamlit Threat Dashboard - the human-approval UI for the deception
platform. Talks to the FastAPI backend entirely over HTTP (REST API
connections), never touches the database directly.
"""

import os
import time
import json

import requests
import pandas as pd
import streamlit as st

API_BASE = os.environ.get("API_BASE_URL", "http://localhost:8000")

st.set_page_config(page_title="Deception Intelligence Dashboard", layout="wide")

SEVERITY_COLORS = {
    "CRITICAL": "#8b0000",
    "HIGH": "#d64545",
    "MEDIUM": "#e0a020",
    "LOW": "#3a8f3a",
    None: "#888888",
}


# ---------------------- API helpers ----------------------

def api_get(path: str, params: dict = None):
    try:
        r = requests.get(f"{API_BASE}{path}", params=params, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API request failed: {e}")
        return None


def api_post(path: str, payload: dict = None):
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload or {}, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API request failed: {e}")
        return None


# ---------------------- Sidebar: token generation ----------------------

st.sidebar.title("🛡️ Deception Platform")
backend_status = api_get("/health")
if backend_status:
    st.sidebar.success(f"Backend connected · {API_BASE}")
else:
    st.sidebar.error(f"Backend unreachable at {API_BASE}")

st.sidebar.markdown("---")
st.sidebar.subheader("Generate Honeytoken")

token_type = st.sidebar.selectbox("Token type", [
    "Trackable PDF",
    "Bait .env file",
    "Fake API endpoint",
    "Source-code secret",
    "Cloud credentials",
])
bait_name = st.sidebar.text_input("Bait name (optional)", placeholder="e.g. Q4_Payroll_Report.pdf")
location_hint = st.sidebar.text_input("Location hint (optional)", placeholder="e.g. shared_drive/Finance/")

TOKEN_ENDPOINTS = {
    "Trackable PDF": "/api/tokens/pdf",
    "Bait .env file": "/api/tokens/env",
    "Fake API endpoint": "/api/tokens/endpoint",
    "Source-code secret": "/api/tokens/source-code",
    "Cloud credentials": "/api/tokens/cloud-credentials",
}

if st.sidebar.button("Generate Token", use_container_width=True):
    payload = {}
    if bait_name:
        payload["bait_name"] = bait_name
    if location_hint:
        payload["location_hint"] = location_hint

    result = api_post(TOKEN_ENDPOINTS[token_type], payload)

    if result:
        st.sidebar.success(f"Created token `{result['token_id']}`")
        st.sidebar.code(result.get("canary_url", ""), language="text")
        if "file_path" in result:
            st.sidebar.caption(f"File: {result['file_path']}")

st.sidebar.markdown("---")
auto_refresh = st.sidebar.checkbox("Auto-refresh every 10s", value=False)


# ---------------------- Main: overview metrics ----------------------

st.title("Threat Intelligence Dashboard")

events = api_get("/api/events") or []
tokens = api_get("/api/tokens") or []

df = pd.DataFrame(events)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Active Honeytokens", len(tokens))
col2.metric("Total Events", len(df))
if not df.empty:
    critical_count = (df["severity"] == "CRITICAL").sum()
    high_count = (df["severity"] == "HIGH").sum()
    new_count = (df["status"] == "NEW").sum() if "status" in df.columns else 0
else:
    critical_count = high_count = new_count = 0
col3.metric("High / Critical Alerts", int(critical_count + high_count))
col4.metric("Pending Analyst Review", int(new_count))

st.markdown("---")


# ---------------------- Map + severity breakdown ----------------------

map_col, chart_col = st.columns([2, 1])

with map_col:
    st.subheader("Attacker Geolocation")
    if not df.empty and "geo_json" in df.columns:
        coords = []
        for _, row in df.iterrows():
            geo_raw = row.get("geo_json")
            if not geo_raw:
                continue
            try:
                geo = json.loads(geo_raw)
                if geo.get("latitude") and geo.get("longitude"):
                    coords.append({"lat": geo["latitude"], "lon": geo["longitude"]})
            except (json.JSONDecodeError, TypeError):
                continue
        if coords:
            st.map(pd.DataFrame(coords), zoom=1)
        else:
            st.info("No geolocated events yet. Trigger a honeytoken to see activity here.")
    else:
        st.info("No events yet.")

with chart_col:
    st.subheader("Severity Breakdown")
    if not df.empty and "severity" in df.columns and df["severity"].notna().any():
        severity_counts = df["severity"].value_counts()
        st.bar_chart(severity_counts)
    else:
        st.info("No triaged events yet.")

st.markdown("---")


# ---------------------- Event table + drill-down ----------------------

st.subheader("Live Alert Feed")

if df.empty:
    st.info("No honeytoken interactions recorded yet. Generate a token in the sidebar and trigger its canary URL to test.")
else:
    display_cols = ["event_id", "timestamp", "ip_address", "severity", "intent_score",
                     "triage_summary", "status"]
    display_cols = [c for c in display_cols if c in df.columns]
    st.dataframe(
        df[display_cols].sort_values("event_id", ascending=False),
        use_container_width=True,
        height=300,
    )

    st.markdown("### Event Detail & Containment Actions")
    event_ids = df["event_id"].tolist()
    selected_id = st.selectbox("Select an event to review", event_ids)

    detail = api_get(f"/api/events/{selected_id}")
    if detail:
        sev = detail.get("severity")
        color = SEVERITY_COLORS.get(sev, "#888888")

        d1, d2 = st.columns([1, 2])
        with d1:
            st.markdown(f"**Severity:** :{'red' if sev in ('HIGH','CRITICAL') else 'orange' if sev=='MEDIUM' else 'green'}[{sev or 'PENDING'}]")
            st.markdown(f"**Intent Score:** {detail.get('intent_score', 'pending...')}")
            st.markdown(f"**IP Address:** `{detail.get('ip_address')}`")
            st.markdown(f"**Status:** {detail.get('status')}")

            if detail.get("geo_json"):
                geo = json.loads(detail["geo_json"])
                st.markdown(f"**Location:** {geo.get('city','?')}, {geo.get('region','?')}, {geo.get('country','?')}")
                st.markdown(f"**Org/ASN:** {geo.get('org','unknown')} ({geo.get('asn','unknown')})")

        with d2:
            st.markdown("**AI Triage Summary**")
            st.info(detail.get("triage_summary") or "Enrichment in progress — refresh in a few seconds.")
            st.markdown("**Proposed Containment Action**")
            st.warning(detail.get("proposed_action") or "Pending analyst triage.")

            b1, b2, b3 = st.columns(3)
            if b1.button("✅ Approve Action", key=f"approve_{selected_id}"):
                api_post(f"/api/events/{selected_id}/status", {"status": "ACTIONED"})
                st.success("Action approved and marked as ACTIONED.")
                st.rerun()
            if b2.button("👁️ Mark Reviewed", key=f"review_{selected_id}"):
                api_post(f"/api/events/{selected_id}/status", {"status": "REVIEWED"})
                st.rerun()
            if b3.button("🚫 Dismiss", key=f"dismiss_{selected_id}"):
                api_post(f"/api/events/{selected_id}/status", {"status": "DISMISSED"})
                st.rerun()

        with st.expander("Raw request headers"):
            st.code(detail.get("headers_json", "{}"), language="json")

st.markdown("---")

with st.expander("Registered Honeytokens"):
    if tokens:
        st.dataframe(pd.DataFrame(tokens), use_container_width=True)
    else:
        st.info("No honeytokens generated yet.")

if auto_refresh:
    time.sleep(10)
    st.rerun()
