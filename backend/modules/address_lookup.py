"""
address_lookup.py
Resolves canonical name, all IPv4/IPv6 addresses, and reverse DNS (PTR) for each IP.
Detects CDN/proxy presence.
"""

import socket
import dns.resolver
import dns.reversename

CDN_ORGS = [
    "cloudflare", "akamai", "fastly", "amazon", "cloudfront",
    "incapsula", "sucuri", "imperva", "maxcdn", "stackpath",
]


def address_lookup(hostname: str) -> dict:
    try:
        ipv4 = []
        ipv6 = []
        canonical = hostname
        ptr_records = {}

        # Canonical + IPv4
        try:
            info = socket.getaddrinfo(hostname, None)
            for item in info:
                addr = item[4][0]
                if ":" in addr and addr not in ipv6:
                    ipv6.append(addr)
                elif ":" not in addr and addr not in ipv4:
                    ipv4.append(addr)
        except Exception:
            pass

        # CNAME chain
        try:
            answers = dns.resolver.resolve(hostname, "CNAME", lifetime=5)
            canonical = str(answers[0].target).rstrip(".")
        except Exception:
            canonical = hostname

        # PTR (reverse DNS) for each IPv4
        for ip in ipv4:
            try:
                rev = dns.reversename.from_address(ip)
                ptr = dns.resolver.resolve(rev, "PTR", lifetime=5)
                ptr_records[ip] = str(ptr[0]).rstrip(".")
            except Exception:
                ptr_records[ip] = None

        # CDN detection — check if any PTR or hostname hints at a CDN
        cdn_detected = None
        all_text = " ".join(
            filter(None, [canonical] + list(ptr_records.values()))
        ).lower()
        for cdn in CDN_ORGS:
            if cdn in all_text:
                cdn_detected = cdn.capitalize()
                break

        # Also check if all IPs fall in known Cloudflare ranges (basic check)
        if not cdn_detected:
            for ip in ipv4:
                if ip.startswith("172.6") or ip.startswith("104.1") or ip.startswith("103."):
                    cdn_detected = "Cloudflare (likely)"
                    break

        return {
            "available": True,
            "canonical": canonical,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "ptr": ptr_records,
            "cdn_detected": cdn_detected,
            "real_ip_hidden": cdn_detected is not None,
        }

    except Exception as e:
        return {"available": False, "error": str(e)}
