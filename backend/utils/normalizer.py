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
