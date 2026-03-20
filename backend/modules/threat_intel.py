"""
threat_intel.py
Aggregates threat intelligence from:
- AlienVault OTX (pulses, malware families)
- AbuseIPDB (IP abuse reports, confidence score)
- ThreatFox (C2, malware droppers, IOCs)
- GreyNoise (internet scanners, mass exploit tools)
- URLhaus (malware distribution URLs)
"""

import httpx
import asyncio
import os

OTX_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
GREYNOISE_KEY = os.getenv("GREYNOISE_KEY")
URLHAUS_KEY = os.getenv("URLHAUS_KEY")


async def _otx(domain: str) -> dict:
    try:
        headers = {"X-OTX-API-KEY": OTX_KEY}
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers=headers,
            )
            data = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            malware_families = list({
                p.get("malware_families", [{}])[0].get("display_name", "")
                for p in pulses
                if p.get("malware_families")
            })
            tags = list({tag for p in pulses for tag in p.get("tags", [])})[:10]

            return {
                "available": True,
                "pulse_count": pulse_count,
                "malware_families": malware_families,
                "tags": tags,
                "flagged": pulse_count > 0,
            }
    except Exception as e:
        return {"available": False, "error": str(e), "flagged": False}


async def _abuseipdb(ip: str) -> dict:
    if not ip:
        return {"available": False, "reason": "No IP", "flagged": False}
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
            )
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return {
                "available": True,
                "abuse_score": score,
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt"),
                "is_tor": d.get("isTor", False),
                "usage_type": d.get("usageType", ""),
                "isp": d.get("isp", ""),
                "flagged": score > 20,
            }
    except Exception as e:
        return {"available": False, "error": str(e), "flagged": False}


async def _threatfox(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": domain},
            )
            data = r.json()
            found = data.get("query_status") == "ok" and data.get("data")
            iocs = data.get("data", []) or []
            return {
                "available": True,
                "flagged": bool(found),
                "ioc_count": len(iocs),
                "threat_types": list({i.get("threat_type", "") for i in iocs}),
                "malware": list({i.get("malware", "") for i in iocs}),
            }
    except Exception as e:
        return {"available": False, "error": str(e), "flagged": False}


async def _greynoise(ip: str) -> dict:
    if not ip:
        return {"available": False, "reason": "No IP", "flagged": False}
    try:
        headers = {"key": GREYNOISE_KEY} if GREYNOISE_KEY else {}
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers,
            )
            if r.status_code == 404:
                return {"available": True, "flagged": False, "noise": False, "riot": False, "classification": "unknown"}
            data = r.json()
            return {
                "available": True,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", ""),
                "flagged": data.get("noise", False) and data.get("classification") == "malicious",
            }
    except Exception as e:
        return {"available": False, "error": str(e), "flagged": False}


async def _urlhaus(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                headers={"Auth-Key": URLHAUS_KEY} if URLHAUS_KEY else {},
            )
            data = r.json()
            flagged = data.get("query_status") == "is_listed"
            urls = data.get("urls", []) or []
            return {
                "available": True,
                "flagged": flagged,
                "url_count": len(urls),
                "tags": list({tag for u in urls for tag in (u.get("tags") or [])}),
            }
    except Exception as e:
        return {"available": False, "error": str(e), "flagged": False}


async def threat_intel(domain: str, ip: str = None) -> dict:
    otx, abuseipdb, tfox, gnoise, urlhaus = await asyncio.gather(
        _otx(domain),
        _abuseipdb(ip),
        _threatfox(domain),
        _greynoise(ip),
        _urlhaus(domain),
        return_exceptions=False,
    )

    engines = {
        "otx": otx,
        "abuseipdb": abuseipdb,
        "threatfox": tfox,
        "greynoise": gnoise,
        "urlhaus": urlhaus,
    }

    flagged_count = sum(1 for e in engines.values() if e.get("flagged"))

    if flagged_count >= 2:
        verdict = "MALICIOUS"
    elif flagged_count == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "available": True,
        "verdict": verdict,
        "flagged_by": flagged_count,
        "engines": engines,
    }
