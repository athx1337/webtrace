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
