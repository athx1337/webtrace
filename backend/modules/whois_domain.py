"""
whois_domain.py
Fetches structured domain WHOIS via RDAP (IANA).
Falls back to python-whois if RDAP fails.
"""

import httpx
import whois
from datetime import datetime, timezone


def _parse_date(date_str: str):
    """Robustly parse RDAP date strings across Python versions and formats."""
    if not date_str:
        return None
    try:
        clean = date_str.strip().replace("Z", "+00:00")
        # Strip microseconds — fromisoformat chokes on them in Python < 3.11
        if "." in clean and "+" in clean:
            clean = clean[:clean.index(".")] + clean[clean.index("+"):]
        elif "." in clean:
            clean = clean.split(".")[0] + "+00:00"
        return datetime.fromisoformat(clean)
    except Exception:
        return None


async def whois_domain(domain: str) -> dict:
    # Try RDAP first
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://rdap.org/domain/{domain}",
                follow_redirects=True,
            )
            if r.status_code != 200:
                raise ValueError(f"RDAP returned {r.status_code}")

            data = r.json()

            created, expires, updated = None, None, None
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action == "registration":
                    created = date
                elif action == "expiration":
                    expires = date
                elif action == "last changed":
                    updated = date

            registrar = None
            registrant_org = None
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])[1]
                org = next((v[3] for v in vcard if v[0] == "org"), None)
                name = next((v[3] for v in vcard if v[0] == "fn"), None)
                if "registrar" in roles:
                    registrar = org or name
                if "registrant" in roles:
                    registrant_org = org or name

            if not registrar:
                registrar = data.get("port43") or "Unknown"

            nameservers = [
                ns.get("ldhName", "").lower()
                for ns in data.get("nameservers", [])
            ]

            dnssec_signed = data.get("secureDNS", {}).get("delegationSigned", False)
            dnssec = "SIGNED" if dnssec_signed else "UNSIGNED"

            age_days = None
            dt = _parse_date(created)
            if dt:
                age_days = (datetime.now(timezone.utc) - dt).days

            return {
                "available": True,
                "source": "RDAP",
                "registrar": registrar,
                "registrant_org": registrant_org,
                "created": created,
                "expires": expires,
                "updated": updated,
                "age_days": age_days,
                "nameservers": nameservers,
                "dnssec": dnssec,
            }

    except Exception:
        pass

    # Fallback: python-whois
    try:
        w = whois.whois(domain)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]

        age_days = None
        if created:
            try:
                if created.tzinfo is None:
                    age_days = (datetime.now() - created).days
                else:
                    age_days = (datetime.now(timezone.utc) - created).days
            except Exception:
                pass

        dnssec_raw = getattr(w, "dnssec", None)
        dnssec = "SIGNED" if dnssec_raw and str(dnssec_raw).lower() not in ("unsigned", "none", "") else "UNSIGNED"

        return {
            "available": True,
            "source": "python-whois",
            "registrar": w.registrar or "Unknown",
            "registrant_org": w.org,
            "created": str(created) if created else None,
            "expires": str(expires) if expires else None,
            "updated": str(updated) if updated else None,
            "age_days": age_days,
            "nameservers": list(w.name_servers or []),
            "dnssec": dnssec,
        }

    except Exception as e:
        return {"available": False, "error": str(e)}