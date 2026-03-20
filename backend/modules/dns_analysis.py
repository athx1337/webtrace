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
