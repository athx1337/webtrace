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
from modules.address_lookup import address_lookup
from modules.whois_domain import whois_domain
from modules.whois_network import whois_network
from modules.dns_records import dns_records
from modules.ssl_analysis import ssl_analysis
from modules.infrastructure import infrastructure_scan
from modules.subdomains import subdomains
from modules.threat_intel import threat_intel
from modules.historical import historical_lookup
from modules.ai_explanation import generate_explanation

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="TRACE — Domain Intelligence API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str


@app.get("/api/ping")
async def ping():
    return {"status": "online", "tool": "TRACE", "version": "2.0"}


@app.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    raw_url = body.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL is required")

    # --- Normalize input ---
    parsed = normalize_url(raw_url)
    domain = parsed["domain"]
    hostname = parsed["hostname"]

    # --- Step 1: Address lookup first — everything else needs the IPs ---
    addr_result = await asyncio.to_thread(address_lookup, hostname)
    primary_ip = addr_result.get("ipv4", [None])[0]

    # --- Step 2: Run all independent modules concurrently ---
    (
        whois_domain_result,
        dns_result,
        ssl_result,
        subdomain_result,
        historical_result,
    ) = await asyncio.gather(
        whois_domain(domain),
        asyncio.to_thread(dns_records, domain),
        asyncio.to_thread(ssl_analysis, hostname),
        subdomains(domain),
        historical_lookup(domain),
        return_exceptions=False,
    )

    # --- Step 3: IP-dependent modules (need primary_ip from step 1) ---
    whois_net_result, infra_result, threat_result = await asyncio.gather(
        whois_network(primary_ip) if primary_ip else _unavailable("whois_network"),
        infrastructure_scan(primary_ip) if primary_ip else _unavailable("infrastructure"),
        threat_intel(domain, primary_ip),
        return_exceptions=False,
    )

    # --- Step 4: Assemble full result ---
    full_result = {
        "domain": domain,
        "address_lookup": addr_result,
        "whois_domain": whois_domain_result,
        "whois_network": whois_net_result,
        "dns_records": dns_result,
        "ssl": ssl_result,
        "infrastructure": infra_result,
        "subdomains": subdomain_result,
        "threat_intel": threat_result,
        "historical": historical_result,
    }

    # --- Step 5: AI explanation last (needs everything above) ---
    full_result["ai_explanation"] = await generate_explanation(full_result)

    return full_result


def _unavailable(module_name: str) -> dict:
    """Returns a coroutine that resolves to an unavailable placeholder."""
    async def _inner():
        return {"available": False, "reason": "No primary IP resolved", "module": module_name}
    return _inner()
