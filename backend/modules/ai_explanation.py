"""
ai_explanation.py
Generates a concise researcher-focused summary using Gemini 1.5 Flash.
Takes the full scan result and returns a 3-4 sentence plain-English brief.
"""

import google.generativeai as genai
import os
import json

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


async def generate_explanation(scan: dict) -> dict | None:
    try:
        model = genai.GenerativeModel("gemini-2.5-flash")

        domain = scan.get("domain", "unknown")
        addr = scan.get("address_lookup", {})
        whois = scan.get("whois_domain", {})
        net = scan.get("whois_network", {})
        ssl = scan.get("ssl", {})
        infra = scan.get("infrastructure", {})
        threat = scan.get("threat_intel", {})
        subs = scan.get("subdomains", {})
        hist = scan.get("historical", {})
        dns = scan.get("dns_records", {})

        prompt = f"""
You are a senior cybersecurity analyst writing a brief for a security researcher.
Based on the structured scan data below, write a 3-4 sentence technical summary.
Be specific — mention actual findings (CDN, CVEs, threat intel hits, cert age, subdomain count, domain age).
Do not use bullet points. Do not be vague. Treat the researcher as an expert.

Domain: {domain}
CDN Detected: {addr.get("cdn_detected")} | Real IP Hidden: {addr.get("real_ip_hidden")}
Domain Age: {whois.get("age_days")} days | Registrar: {whois.get("registrar")} | DNSSEC: {whois.get("dnssec")}
Network Owner: {net.get("org")} | ASN: {net.get("asn")} | Country: {net.get("country")}
SSL: Valid={ssl.get("valid")} | Issuer={ssl.get("issuer_org")} | Age={ssl.get("cert_age_days")} days | Expires in {ssl.get("days_remaining")} days | Free CA={ssl.get("is_free_ca")}
SSL Flags: {ssl.get("flags", [])}
Open Ports: {infra.get("ports", [])} | CVEs: {infra.get("vulns", [])} | Tags: {infra.get("tags", [])}
Threat Intel Verdict: {threat.get("verdict")} | Flagged by {threat.get("flagged_by", 0)} engines
OTX Pulses: {threat.get("engines", {}).get("otx", {}).get("pulse_count", 0)}
AbuseIPDB Score: {threat.get("engines", {}).get("abuseipdb", {}).get("abuse_score", 0)}%
ThreatFox IOCs: {threat.get("engines", {}).get("threatfox", {}).get("ioc_count", 0)}
DNS Flags: {dns.get("flags", [])}
Subdomains Found: {subs.get("total", 0)} | Notable: {subs.get("notable", [])}
Wayback Available: {hist.get("wayback", {}).get("available")} | Snapshots: {hist.get("wayback", {}).get("snapshot_count")}
"""

        response = model.generate_content(prompt)
        text = response.text.strip()

        return {
            "available": True,
            "summary": text,
            "engine": "gemini-2.5-flash",
        }

    except Exception as e:
        return {"available": False, "error": str(e)}
