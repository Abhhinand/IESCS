"""
agents.py
Multi-agent AI pipeline (Detection -> Threat Profiling -> Containment
Orchestration) built on LangChain, using Groq as the fast LLM backend
so inference never becomes the bottleneck on the ingestion path.

Requires GROQ_API_KEY to be set in the environment.
"""

import os
import json
import logging
import asyncio

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

logger = logging.getLogger("deception.agents")
logging.basicConfig(level=logging.INFO)

GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

# How many times to retry a failed Groq call before falling back to the
# safe MEDIUM default. Transient network blips are common (see README),
# so a couple of retries meaningfully increases the real-AI success rate.
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2
REQUEST_TIMEOUT_SECONDS = 20

_llm = None


def get_llm():
    global _llm
    if _llm is None:
        if not GROQ_API_KEY:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Load your .env before starting the backend "
                "(see README) - this is required for real AI triage."
            )
        _llm = ChatGroq(
            model=GROQ_MODEL,
            api_key=GROQ_API_KEY,
            temperature=0,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    return _llm


TRIAGE_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are a cybersecurity threat-triage agent for a honeytoken deception "
     "platform. Every event you receive is a real interaction with a decoy "
     "asset that no legitimate user should ever touch. Your job is to score "
     "attacker intent, assign a severity, write a one-sentence human-readable "
     "summary, and propose ONE concrete containment action a security analyst "
     "could approve with one click.\n\n"
     "Respond ONLY with valid JSON, no markdown fences, no preamble, matching "
     "exactly this schema:\n"
     '{{"intent_score": <float 0-100>, "severity": "LOW|MEDIUM|HIGH|CRITICAL", '
     '"triage_summary": "<one sentence>", "proposed_action": "<one sentence, imperative>"}}\n\n'
     "Scoring guidance:\n"
     "- 0-20: near-certainly benign automation (known crawler, monitoring bot)\n"
     "- 21-45: low-signal single touch, ambiguous, worth a passive audit log\n"
     "- 46-70: suspicious - direct token access with no plausible legitimate reason\n"
     "- 71-90: high - rapid/sequential access across multiple tokens, scripted behavior\n"
     "- 91-100: critical - clear active exploitation attempt (credential reuse, scanning burst)"
    ),
    ("human",
     "Honeytoken type: {token_type}\n"
     "Bait name: {bait_name}\n"
     "Attacker IP: {ip_address}\n"
     "Geo/ASN: {geo_summary}\n"
     "User-Agent: {user_agent}\n"
     "Request path: {request_path}\n"
     "HTTP method: {method}\n"
     "Recent event count from this IP (last hour): {recent_count}\n"
     "Known benign bot signature matched: {is_benign}\n"
    ),
])

_parser = JsonOutputParser()


async def run_triage_agent(token_type: str, bait_name: str, ip_address: str,
                            geo: dict, user_agent: str, request_path: str,
                            method: str, recent_count: int, is_benign: bool) -> dict:
    """
    Runs the Detection -> Threat Profiling -> Containment Orchestration
    chain as a single structured-output LLM call (agents are logically
    separated by the prompt's staged instructions; each stage's output
    feeds the schema fields below).
    """
    # Fast-path: known benign bots never need an expensive LLM call.
    if is_benign:
        return {
            "intent_score": 2.0,
            "severity": "LOW",
            "triage_summary": f"Recognized benign crawler/bot ({user_agent[:60]}) touched the token; no action needed.",
            "proposed_action": "Log and suppress alert; no analyst review required.",
        }

    geo_summary = (
        f"{geo.get('city', '?')}, {geo.get('region', '?')}, {geo.get('country', '?')} "
        f"(org: {geo.get('org', 'unknown')}, ASN: {geo.get('asn', 'unknown')})"
    )

    chain = TRIAGE_PROMPT | get_llm() | _parser

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = await chain.ainvoke({
                "token_type": token_type,
                "bait_name": bait_name,
                "ip_address": ip_address,
                "geo_summary": geo_summary,
                "user_agent": user_agent or "unknown",
                "request_path": request_path,
                "method": method,
                "recent_count": recent_count,
                "is_benign": is_benign,
            })
            # Defensive normalization in case the model returns partial JSON
            logger.info("Groq triage succeeded on attempt %d/%d", attempt, MAX_RETRIES)
            return {
                "intent_score": float(result.get("intent_score", 50.0)),
                "severity": result.get("severity", "MEDIUM"),
                "triage_summary": result.get("triage_summary", "Unable to fully parse triage output."),
                "proposed_action": result.get("proposed_action", "Escalate to analyst for manual review."),
            }
        except Exception as exc:
            last_error = exc
            # Print the REAL error to the backend terminal so you can see
            # exactly what's failing (auth, timeout, DNS, bad model name, etc.)
            # instead of only seeing the generic fallback message.
            logger.warning(
                "Groq triage attempt %d/%d failed: %s: %s",
                attempt, MAX_RETRIES, type(exc).__name__, exc,
            )
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY_SECONDS)

    # All retries exhausted - fail safe rather than losing the event.
    logger.error("Groq triage failed after %d attempts, falling back. Last error: %s", MAX_RETRIES, last_error)
    return {
        "intent_score": 50.0,
        "severity": "MEDIUM",
        "triage_summary": f"Auto-triage failed after {MAX_RETRIES} attempts ({last_error}); flagged for manual analyst review.",
        "proposed_action": "Manually review raw event telemetry.",
    }
