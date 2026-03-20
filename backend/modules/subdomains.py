"""
subdomains.py
Enumerates subdomains via Certificate Transparency logs (crt.sh).
Free, no key, no rate limit. Goldmine for finding hidden infrastructure.
"""

import httpx
import asyncio


NOTABLE_SUBDOMAINS = [
    "admin", "mail", "vpn", "api", "dev", "staging", "test",
    "beta", "portal", "dashboard", "login", "secure", "ftp",
    "remote", "internal", "corp", "manage", "backup", "old",
]


async def subdomains(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"Accept": "application/json"},
            )

            if r.status_code != 200:
                return {"available": False, "error": f"crt.sh returned {r.status_code}"}

            data = r.json()

            # Deduplicate and clean subdomains
            seen = set()
            unique_subs = []
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name and name not in seen and name.endswith(domain):
                        seen.add(name)
                        unique_subs.append({
                            "subdomain": name,
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                        })

            # Sort — root domain last, subdomains alphabetically
            unique_subs.sort(key=lambda x: x["subdomain"])

            # Flag notable/sensitive subdomains
            notable_found = []
            for sub in unique_subs:
                subdomain_part = sub["subdomain"].replace(f".{domain}", "").replace(domain, "")
                if any(n in subdomain_part for n in NOTABLE_SUBDOMAINS):
                    notable_found.append(sub["subdomain"])

            return {
                "available": True,
                "total": len(unique_subs),
                "subdomains": unique_subs[:100],  # Cap at 100 for response size
                "notable": notable_found,
                "flags": [
                    f"Sensitive subdomain found: {s}" for s in notable_found
                ] if notable_found else [],
            }

    except Exception as e:
        return {"available": False, "error": str(e)}
