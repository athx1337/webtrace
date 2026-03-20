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
