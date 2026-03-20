"""
dns_records.py
Full DNS record dump queried directly from authoritative nameservers.
Flags missing/misconfigured records.
"""

import dns.resolver
import dns.rdatatype


RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA"]


def dns_records(domain: str) -> dict:
    try:
        records = {}
        flags = []

        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                return {
                    "available": False,
                    "error": "Domain does not exist (NXDOMAIN)",
                    "records": {},
                    "flags": ["Domain returned NXDOMAIN"],
                }
            except Exception:
                records[rtype] = []

        # --- SPF ---
        txt_records = records.get("TXT", [])
        spf = next((r for r in txt_records if "v=spf1" in r), None)
        has_spf = spf is not None

        # --- DMARC ---
        dmarc_record = None
        try:
            dmarc_ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
            dmarc_record = str(dmarc_ans[0])
        except Exception:
            pass
        has_dmarc = dmarc_record is not None

        # --- DKIM (common selectors) ---
        dkim_found = False
        for selector in ["default", "google", "k1", "dkim", "mail", "smtp"]:
            try:
                dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=3)
                dkim_found = True
                break
            except Exception:
                continue

        # --- Flags ---
        if not records.get("MX"):
            flags.append("No MX records — domain not configured to receive email")
        if not has_spf:
            flags.append("No SPF record — domain vulnerable to email spoofing")
        if not has_dmarc:
            flags.append("No DMARC policy — no protection against spoofed email")
        if not dkim_found:
            flags.append("No DKIM record found (checked common selectors)")
        if not records.get("CAA"):
            flags.append("No CAA record — any CA can issue certs for this domain")

        return {
            "available": True,
            "records": records,
            "spf": spf,
            "dmarc": dmarc_record,
            "dkim_found": dkim_found,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "flags": flags,
        }

    except Exception as e:
        return {"available": False, "error": str(e), "records": {}, "flags": []}
