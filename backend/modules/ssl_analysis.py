"""
ssl_analysis.py
Deep SSL/TLS certificate analysis.
Issuer, expiry, SANs, age, days remaining, free CA detection.
"""

import ssl
import socket
from datetime import datetime, timezone


FREE_CAS = ["let's encrypt", "zerossl", "buypass", "ssl.com free"]


def ssl_analysis(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(7)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        common_name = subject.get("commonName", "")

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_org = issuer.get("organizationName", "Unknown")
        issuer_cn = issuer.get("commonName", "")

        # Dates
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        cert_age_days = (now - not_before).days
        days_remaining = (not_after - now).days
        is_expired = days_remaining < 0
        is_new = cert_age_days < 7  # Brand new cert — phishing signal

        # SANs (Subject Alternative Names)
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_value)

        # Is free CA?
        is_free_ca = any(ca in issuer_org.lower() or ca in issuer_cn.lower() for ca in FREE_CAS)

        # Domain match check
        domain_match = any(
            hostname == s or s.startswith("*.") and hostname.endswith(s[2:])
            for s in sans
        ) or hostname == common_name

        return {
            "available": True,
            "valid": True,
            "common_name": common_name,
            "issuer_org": issuer_org,
            "issuer_cn": issuer_cn,
            "is_free_ca": is_free_ca,
            "issued": not_before.isoformat(),
            "expires": not_after.isoformat(),
            "cert_age_days": cert_age_days,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "is_new_cert": is_new,
            "sans": sans,
            "san_count": len(sans),
            "domain_match": domain_match,
            "flags": _ssl_flags(is_expired, is_new, days_remaining, is_free_ca, domain_match, len(sans)),
        }

    except ssl.SSLCertVerificationError as e:
        return {"available": True, "valid": False, "error": str(e), "flags": ["SSL certificate verification failed"]}
    except ConnectionRefusedError:
        return {"available": True, "valid": False, "error": "Port 443 refused — no HTTPS", "flags": ["No HTTPS available"]}
    except Exception as e:
        return {"available": False, "valid": False, "error": str(e), "flags": []}


def _ssl_flags(is_expired, is_new, days_remaining, is_free_ca, domain_match, san_count):
    flags = []
    if is_expired:
        flags.append("Certificate is expired")
    if is_new:
        flags.append("Certificate issued less than 7 days ago — phishing signal")
    if days_remaining < 14 and not is_expired:
        flags.append(f"Certificate expiring in {days_remaining} days")
    if is_free_ca:
        flags.append("Free CA used (Let's Encrypt / ZeroSSL) — combined with other signals, may indicate phishing")
    if not domain_match:
        flags.append("Certificate domain mismatch — cert not issued for this hostname")
    if san_count > 50:
        flags.append(f"Certificate covers {san_count} domains — shared hosting or CDN")
    return flags
