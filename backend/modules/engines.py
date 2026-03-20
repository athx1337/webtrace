import httpx
import asyncio
import os

GSB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY")
CF_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")

async def check_google_safe_browsing(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            payload = {
                "client": {"clientId": "trace-tool", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            r = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
                json=payload
            )
            data = r.json()
            flagged = bool(data.get("matches"))
            return {
                "name": "GOOGLE_SAFEBROWSING",
                "verdict": "MALICIOUS" if flagged else "CLEAN",
                "flagged": flagged,
                "detail": data.get("matches", [{}])[0].get("threatType", "") if flagged else "No threats found",
                "available": True
            }
    except Exception as e:
        return {"name": "GOOGLE_SAFEBROWSING", "verdict": "UNAVAILABLE", "flagged": False, "available": False}


async def check_urlhaus(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": URLHAUS_KEY}
            )
            data = r.json()
            flagged = data.get("query_status") == "is_blacklisted"
            return {
                "name": "URLHAUS",
                "verdict": "MALICIOUS" if flagged else "CLEAN",
                "flagged": flagged,
                "detail": data.get("threat", "Not in URLhaus database") if flagged else "Not in URLhaus database",
                "available": True
            }
    except Exception as e:
        return {"name": "URLHAUS", "verdict": "UNAVAILABLE", "flagged": False, "available": False}


async def check_cloudflare(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Submit scan
            headers = {"Authorization": f"Bearer {CF_TOKEN}", "Content-Type": "application/json"}
            r = await client.post(
                "https://api.cloudflare.com/client/v4/accounts/scan/v1/",
                json={"url": url},
                headers=headers
            )
            data = r.json()
            if not data.get("success"):
                return {"name": "CLOUDFLARE", "verdict": "UNAVAILABLE", "flagged": False, "available": False}

            result = data.get("result", {})
            verdicts = result.get("verdicts", {})
            overall = verdicts.get("overall", {})
            flagged = overall.get("malicious", False)

            return {
                "name": "CLOUDFLARE",
                "verdict": "MALICIOUS" if flagged else "CLEAN",
                "flagged": flagged,
                "detail": ", ".join(overall.get("categories", [])) or "Clean",
                "available": True
            }
    except Exception as e:
        return {"name": "CLOUDFLARE", "verdict": "UNAVAILABLE", "flagged": False, "available": False}


async def run_all_engines(url: str) -> dict:
    results = await asyncio.gather(
        check_google_safe_browsing(url),
        check_urlhaus(url),
        check_cloudflare(url),
        return_exceptions=False
    )

    flagged_count = sum(1 for r in results if r.get("flagged"))
    available_count = sum(1 for r in results if r.get("available"))

    # Verdict: malicious if 2+ engines flag
    if flagged_count >= 2:
        aggregate = "MALICIOUS"
    elif flagged_count == 1:
        aggregate = "SUSPICIOUS"
    else:
        aggregate = "CLEAN"

    return {
        "available": True,
        "engines": results,
        "flagged_count": flagged_count,
        "available_engines": available_count,
        "aggregate_verdict": aggregate
    }
