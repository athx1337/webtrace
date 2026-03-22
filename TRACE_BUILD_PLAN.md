# TRACE — Complete Copy-Paste Build Plan

---

## STEP 0 — Get Your API Keys First

Do this before writing a single line of code.

| Service | URL | What to do |
|---|---|---|
| Google Safe Browsing | console.cloud.google.com | Create project → Enable "Safe Browsing API" → Create API Key |
| URLhaus | auth.abuse.ch | Register → Get Auth-Key from dashboard |
| Cloudflare URL Scanner | dash.cloudflare.com | My Profile → API Tokens → Create Token → "Read" URL Scanner permission |
| IP2WHOIS | ip2whois.com | Sign up → Dashboard → Copy API Key |
| Gemini | aistudio.google.com | Sign in → Get API Key |

Save all 5 keys. You'll put them in `.env` in Step 2.

---

## STEP 1 — Create Folder Structure

Run this in your terminal:

```bash
mkdir trace && cd trace
mkdir -p backend/modules backend/utils frontend
cd backend
```

Your structure will be:
```
trace/
├── backend/
│   ├── main.py
│   ├── .env
│   ├── requirements.txt
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── url_analysis.py
│   │   ├── dns_analysis.py
│   │   ├── domain_info.py
│   │   ├── engines.py
│   │   ├── trust_score.py
│   │   └── ai_explanation.py
│   └── utils/
│       ├── __init__.py
│       └── normalizer.py
└── frontend/               ← you build this later
```

---

## STEP 2 — requirements.txt

Create `backend/requirements.txt`:

```
fastapi
uvicorn[standard]
httpx
dnspython
python-whois
python-dotenv
slowapi
google-generativeai
```

Install:
```bash
pip install -r requirements.txt
```

---

## STEP 3 — .env File

Create `backend/.env`:

```env
GOOGLE_SAFE_BROWSING_KEY=your_key_here
URLHAUS_AUTH_KEY=your_key_here
CLOUDFLARE_API_TOKEN=your_key_here
IP2WHOIS_KEY=your_key_here
GEMINI_API_KEY=your_key_here
```

---

## STEP 4 — utils/normalizer.py

```python
import re
import socket
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".click", ".loan", ".work", ".party",
    ".win", ".download", ".stream", ".gdn"
}

KNOWN_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "instagram", "twitter", "whatsapp",
    "linkedin", "youtube", "gmail", "outlook", "office"
]

def normalize_url(raw: str) -> dict:
    raw = raw.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw

    parsed = urlparse(raw)
    uses_https = parsed.scheme == "https"
    hostname = parsed.hostname or ""

    # Check if IP-based
    is_ip = False
    try:
        socket.inet_aton(hostname)
        is_ip = True
    except:
        pass

    # Extract parts
    parts = hostname.split(".")
    tld = "." + parts[-1] if len(parts) >= 2 else ""
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomains = parts[:-2] if len(parts) > 2 else []

    # Suspicious chars in full URL
    full_url = raw
    suspicious_chars = []
    if "@" in full_url:
        suspicious_chars.append("@")
    if "%" in full_url:
        suspicious_chars.append("%")
    if "//" in parsed.path:
        suspicious_chars.append("//")

    # Typosquatting check
    typosquat_target = None
    for brand in KNOWN_BRANDS:
        if brand in domain and domain != brand + tld:
            typosquat_target = brand
            break

    return {
        "raw": raw,
        "domain": domain,
        "hostname": hostname,
        "tld": tld,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "is_ip": is_ip,
        "uses_https": uses_https,
        "url_length": len(raw),
        "suspicious_chars": suspicious_chars,
        "typosquat_target": typosquat_target,
        "is_suspicious_tld": tld in SUSPICIOUS_TLDS,
        "path": parsed.path,
        "query": parsed.query,
    }
```

---

## STEP 5 — modules/url_analysis.py

```python
from utils.normalizer import normalize_url

def analyze_url(raw: str) -> dict:
    try:
        parsed = normalize_url(raw)
        flags = []

        if parsed["url_length"] > 100:
            flags.append("URL is unusually long")
        if parsed["is_ip"]:
            flags.append("URL uses raw IP address instead of domain")
        if parsed["subdomain_count"] > 2:
            flags.append(f"Excessive subdomains ({parsed['subdomain_count']})")
        if parsed["suspicious_chars"]:
            flags.append(f"Suspicious characters found: {', '.join(parsed['suspicious_chars'])}")
        if parsed["typosquat_target"]:
            flags.append(f"Possible typosquatting of '{parsed['typosquat_target']}'")
        if parsed["is_suspicious_tld"]:
            flags.append(f"High-risk TLD: {parsed['tld']}")
        if not parsed["uses_https"]:
            flags.append("No HTTPS — plain HTTP connection")

        return {
            "available": True,
            "url_length": parsed["url_length"],
            "subdomain_count": parsed["subdomain_count"],
            "is_ip_based": parsed["is_ip"],
            "uses_https": parsed["uses_https"],
            "suspicious_chars": parsed["suspicious_chars"],
            "typosquat_target": parsed["typosquat_target"],
            "suspicious_tld": parsed["is_suspicious_tld"],
            "flags": flags
        }
    except Exception as e:
        return {"available": False, "error": str(e), "flags": []}
```

---

## STEP 6 — modules/dns_analysis.py

```python
import dns.resolver

def analyze_dns(domain: str) -> dict:
    try:
        records = {}
        flags = []

        record_types = ["A", "AAAA", "MX", "TXT", "NS"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []

        # Flag checks
        if not records.get("MX"):
            flags.append("No MX records — domain may not handle email legitimately")

        has_spf = any("v=spf1" in r for r in records.get("TXT", []))
        if not has_spf:
            flags.append("No SPF record found in TXT — email spoofing possible")

        has_dmarc = any("v=DMARC1" in r for r in records.get("TXT", []))
        if not has_dmarc:
            flags.append("No DMARC policy found")

        if not records.get("NS"):
            flags.append("No nameserver records found — unusual")

        return {
            "available": True,
            "records": records,
            "flags": flags,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
        }
    except Exception as e:
        return {"available": False, "error": str(e), "records": {}, "flags": []}
```

---

## STEP 7 — modules/domain_info.py

```python
import httpx
import whois
import os
from datetime import datetime, timezone

IP2WHOIS_KEY = os.getenv("IP2WHOIS_KEY")

async def get_domain_info(domain: str) -> dict:
    try:
        # WHOIS via IP2WHOIS
        whois_data = {}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    f"https://api.ip2whois.com/v2",
                    params={"key": IP2WHOIS_KEY, "domain": domain}
                )
                data = r.json()
                create_date = data.get("create_date", "")
                expire_date = data.get("expire_date", "")
                registrar = data.get("registrar", {}).get("name", "Unknown")

                # Calculate domain age
                age_days = None
                if create_date:
                    try:
                        created = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - created).days
                    except:
                        pass

                whois_data = {
                    "registrar": registrar,
                    "created": create_date,
                    "expires": expire_date,
                    "age_days": age_days,
                }
        except:
            # Fallback to python-whois
            try:
                w = whois.whois(domain)
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                age_days = (datetime.now() - created).days if created else None
                whois_data = {
                    "registrar": w.registrar or "Unknown",
                    "created": str(created),
                    "expires": str(w.expiration_date),
                    "age_days": age_days,
                }
            except:
                whois_data = {"registrar": "Unknown", "created": None, "expires": None, "age_days": None}

        # IP Geolocation via ip-api.com
        geo_data = {}
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"http://ip-api.com/json/{domain}?fields=country,city,isp,as,query")
                g = r.json()
                geo_data = {
                    "ip": g.get("query"),
                    "country": g.get("country"),
                    "city": g.get("city"),
                    "isp": g.get("isp"),
                    "asn": g.get("as"),
                }
        except:
            geo_data = {"ip": None, "country": None, "city": None, "isp": None, "asn": None}

        return {
            "available": True,
            **whois_data,
            **geo_data,
        }

    except Exception as e:
        return {"available": False, "error": str(e)}
```

---

## STEP 8 — modules/engines.py

```python
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
```

---

## STEP 9 — modules/trust_score.py

```python
import ssl
import socket

def check_ssl(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")
            return {
                "valid": True,
                "issuer": issuer.get("organizationName", "Unknown"),
                "expires": not_after,
                "common_name": dict(x[0] for x in cert.get("subject", [])).get("commonName", ""),
            }
    except:
        return {"valid": False, "issuer": None, "expires": None, "common_name": None}


def calculate_trust_score(url_analysis: dict, dns_analysis: dict, domain_info: dict, engines: dict, hostname: str) -> dict:
    score = 100
    deductions = []

    # Domain age
    age_days = domain_info.get("age_days")
    if age_days is not None:
        if age_days < 30:
            score -= 30
            deductions.append({"reason": "Domain less than 30 days old", "points": -30})
        elif age_days < 180:
            score -= 10
            deductions.append({"reason": "Domain less than 6 months old", "points": -10})

    # Suspicious TLD
    if url_analysis.get("suspicious_tld"):
        score -= 20
        deductions.append({"reason": "High-risk TLD detected", "points": -20})

    # Blacklist hits
    flagged = engines.get("flagged_count", 0)
    if flagged >= 2:
        score -= 40
        deductions.append({"reason": f"{flagged} engines flagged this URL", "points": -40})
    elif flagged == 1:
        score -= 20
        deductions.append({"reason": "1 engine flagged this URL", "points": -20})

    # No HTTPS
    if not url_analysis.get("uses_https"):
        score -= 15
        deductions.append({"reason": "No HTTPS", "points": -15})

    # SSL check
    ssl_info = check_ssl(hostname)
    if not ssl_info["valid"]:
        score -= 15
        deductions.append({"reason": "Invalid or missing SSL certificate", "points": -15})

    # Excessive subdomains
    if url_analysis.get("subdomain_count", 0) > 2:
        score -= 10
        deductions.append({"reason": "Excessive subdomains", "points": -10})

    # IP-based URL
    if url_analysis.get("is_ip_based"):
        score -= 20
        deductions.append({"reason": "URL uses raw IP address", "points": -20})

    # Typosquatting
    if url_analysis.get("typosquat_target"):
        score -= 25
        deductions.append({"reason": f"Possible typosquatting of {url_analysis['typosquat_target']}", "points": -25})

    # Suspicious chars
    if url_analysis.get("suspicious_chars"):
        score -= 10
        deductions.append({"reason": "Suspicious characters in URL", "points": -10})

    # No MX records
    if "No MX" in " ".join(dns_analysis.get("flags", [])):
        score -= 5
        deductions.append({"reason": "No MX records", "points": -5})

    score = max(0, min(100, score))

    if score >= 70:
        verdict = "SAFE"
        risk = "LOW"
    elif score >= 40:
        verdict = "SUSPICIOUS"
        risk = "MEDIUM"
    else:
        verdict = "MALICIOUS"
        risk = "HIGH"

    return {
        "score": round(score, 1),
        "verdict": verdict,
        "risk": risk,
        "deductions": deductions,
        "ssl": ssl_info
    }
```

---

## STEP 10 — modules/ai_explanation.py

```python
import google.generativeai as genai
import os
import json

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

async def generate_explanation(scan_result: dict) -> str:
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")

        trust = scan_result.get("trust_score", {})
        engines = scan_result.get("engines", {})
        url_info = scan_result.get("url_analysis", {})
        domain = scan_result.get("domain_info", {})

        prompt = f"""
You are a cybersecurity analyst. Based on the scan results below, write a 2-3 sentence plain-English explanation of the domain's security status.
Be specific about what signals were found. Do not use bullet points. Be concise and authoritative.

Trust Score: {trust.get('score')}/100 — {trust.get('verdict')}
Engine Results: {engines.get('flagged_count', 0)} of {engines.get('available_engines', 0)} engines flagged this URL
Aggregate Engine Verdict: {engines.get('aggregate_verdict')}
Deductions: {json.dumps(trust.get('deductions', []))}
URL Flags: {url_info.get('flags', [])}
Domain Age: {domain.get('age_days')} days
SSL Valid: {trust.get('ssl', {}).get('valid')}
"""

        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return None
```

---

## STEP 11 — main.py (FastAPI App)

```python
import asyncio
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

from utils.normalizer import normalize_url
from modules.url_analysis import analyze_url
from modules.dns_analysis import analyze_dns
from modules.domain_info import get_domain_info
from modules.engines import run_all_engines
from modules.trust_score import calculate_trust_score
from modules.ai_explanation import generate_explanation

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="TRACE — Domain Intelligence API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock this down to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/api/ping")
async def ping():
    return {"status": "online", "tool": "TRACE", "version": "1.0"}


@app.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    raw_url = body.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Normalize
    parsed = normalize_url(raw_url)
    domain = parsed["domain"]
    hostname = parsed["hostname"]
    full_url = parsed["raw"]

    # Run all modules concurrently
    url_result, dns_result, domain_result, engine_result = await asyncio.gather(
        asyncio.coroutine(lambda: analyze_url(raw_url))(),
        asyncio.coroutine(lambda: analyze_dns(domain))(),
        get_domain_info(domain),
        run_all_engines(full_url),
        return_exceptions=False
    )

    # Trust score (sync — fast)
    trust_result = calculate_trust_score(url_result, dns_result, domain_result, engine_result, hostname)

    # Aggregate result for AI
    full_result = {
        "url": full_url,
        "domain": domain,
        "trust_score": trust_result,
        "engines": engine_result,
        "url_analysis": url_result,
        "domain_info": domain_result,
        "dns_records": dns_result,
    }

    # AI explanation (last — depends on everything else)
    explanation = await generate_explanation(full_result)
    full_result["ai_explanation"] = explanation

    return full_result
```

> **Note on asyncio.coroutine:** The url_analysis and dns_analysis modules are sync functions. Wrap them with `asyncio.get_event_loop().run_in_executor(None, fn)` if you run into issues, or just convert them to async.

---

## STEP 12 — Empty __init__.py Files

Create these empty files so Python treats folders as modules:

```bash
touch backend/modules/__init__.py
touch backend/utils/__init__.py
```

---

## STEP 13 — Run the Backend

```bash
cd backend
uvicorn main:app --reload --port 8000
```

Test it:
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "google.com"}'
```

Test the ping:
```bash
curl http://localhost:8000/api/ping
```

---

## STEP 14 — Frontend Connection (When Ready)

Your React frontend just needs to hit:

```javascript
const response = await fetch("http://localhost:8000/api/analyze", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url: inputValue })
});
const data = await response.json();
```

The response shape is:
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "trust_score": {
    "score": 94.2,
    "verdict": "SAFE",
    "risk": "LOW",
    "deductions": [],
    "ssl": { "valid": true, "issuer": "DigiCert", "expires": "..." }
  },
  "engines": {
    "engines": [
      { "name": "GOOGLE_SAFEBROWSING", "verdict": "CLEAN", "flagged": false },
      { "name": "URLHAUS", "verdict": "CLEAN", "flagged": false },
      { "name": "CLOUDFLARE", "verdict": "CLEAN", "flagged": false }
    ],
    "flagged_count": 0,
    "aggregate_verdict": "CLEAN"
  },
  "url_analysis": { "flags": [], "uses_https": true, ... },
  "domain_info": { "registrar": "...", "age_days": 10873, "country": "US", ... },
  "dns_records": { "records": { "A": [...], "MX": [...] }, "flags": [] },
  "ai_explanation": "This domain has maintained a consistent presence since 1995..."
}
```

---

## STEP 15 — Testing Checklist

| Test | Expected Result |
|---|---|
| `google.com` | Score 85+, all engines CLEAN |
| `example.com` | Score 80+, no flags |
| An IP address like `192.168.1.1` | Score drops, IP-based flag triggered |
| A `.tk` domain | Suspicious TLD flag, score drops |
| Kill your internet mid-scan | Each module should return `available: false`, not crash |
| Hit `/api/analyze` 11 times in a minute | 429 rate limit response on 11th |

---

## Common Issues & Fixes

| Problem | Fix |
|---|---|
| CORS error from frontend | Check `allow_origins` in main.py |
| WHOIS returns no data | Normal due to GDPR — fallback to python-whois kicks in |
| Cloudflare scan times out | Increase timeout to 20s or make it async non-blocking |
| Gemini returns None | Already handled — `ai_explanation` will be null in response |
| Rate limit on ip-api.com | Add a 1.5s sleep between calls or upgrade to pro |
| Module import errors | Make sure `__init__.py` files exist in both module folders |

---

## What To Build Next (After This Works)

1. **Scan history** — store results in SQLite with `aiosqlite`, show last 10 scans on frontend
2. **Bulk scan** — accept a list of URLs, scan all, return CSV
3. **VirusTotal integration** — free tier, 4 requests/minute, massive signal boost
4. **RDAP fallback** — more reliable than WHOIS for domain age
5. **Screenshot** — use Playwright to screenshot the domain and show it in the UI
