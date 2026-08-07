"""
enrichment.py
Geospatial / ASN enrichment of attacker IP addresses via ipapi.co,
plus lightweight known-benign-bot filtering (Q2's first filtering stage).
"""

import httpx

# A small set of well-known benign crawler / monitoring UA substrings.
# In production this would be a maintained list or a third-party
# bot-detection API (e.g. IPQualityScore).
KNOWN_BENIGN_UA_SUBSTRINGS = [
    "googlebot", "bingbot", "pingdom", "uptimerobot", "slackbot",
    "facebookexternalhit", "ahrefsbot", "semrushbot", "statuscake",
]


def is_known_benign(user_agent: str) -> bool:
    if not user_agent:
        return False
    ua = user_agent.lower()
    return any(sig in ua for sig in KNOWN_BENIGN_UA_SUBSTRINGS)


async def enrich_ip(ip_address: str) -> dict:
    """
    Calls ipapi.co for geolocation + ASN info on the attacker's IP.
    Falls back gracefully if the API is unreachable or rate-limited.
    """
    if not ip_address or ip_address in ("127.0.0.1", "testclient", "localhost"):
        return {
            "ip": ip_address,
            "city": "local/dev",
            "region": "",
            "country": "",
            "org": "local",
            "asn": "",
            "error": None,
        }

    url = f"https://ipapi.co/{ip_address}/json/"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            return {
                "ip": ip_address,
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country_name", ""),
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "error": None,
            }
    except Exception as exc:
        return {
            "ip": ip_address,
            "city": "", "region": "", "country": "", "org": "", "asn": "",
            "error": str(exc),
        }
