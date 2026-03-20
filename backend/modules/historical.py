"""
historical.py
Checks historical presence via:
- Wayback Machine (first archived, snapshot count)
- ViewDNS IP history (what IPs this domain previously resolved to)
"""

import httpx
import os

VIEWDNS_KEY = os.getenv("VIEWDNS_KEY")


async def historical_lookup(domain: str) -> dict:
    wayback = await _wayback(domain)
    ip_history = await _ip_history(domain)

    return {
        "available": True,
        "wayback": wayback,
        "ip_history": ip_history,
    }


async def _wayback(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"http://archive.org/wayback/available?url={domain}"
            )
            data = r.json()
            snapshot = data.get("archived_snapshots", {}).get("closest", {})
            available = snapshot.get("available", False)

            # Also get total snapshot count via CDX API
            count = 0
            try:
                cdx = await client.get(
                    f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp&fastLatest=true"
                )
                # Count via summary endpoint
                cdx_count = await client.get(
                    f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=0&showNumPages=true"
                )
                try:
                    count = int(cdx_count.text.strip())
                except Exception:
                    count = None
            except Exception:
                count = None

            return {
                "available": available,
                "first_snapshot": snapshot.get("timestamp"),
                "closest_url": snapshot.get("url"),
                "snapshot_count": count,
                "flag": "No Wayback Machine history — domain may be very new" if not available else None,
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _ip_history(domain: str) -> dict:
    if not VIEWDNS_KEY:
        return {"available": False, "reason": "VIEWDNS_KEY not set"}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://api.viewdns.info/iphistory/",
                params={
                    "domain": domain,
                    "apikey": VIEWDNS_KEY,
                    "output": "json",
                },
            )
            data = r.json()
            records = data.get("response", {}).get("records", [])
            return {
                "available": True,
                "history": [
                    {
                        "ip": rec.get("ip"),
                        "location": rec.get("location"),
                        "owner": rec.get("owner"),
                        "last_seen": rec.get("lastseen"),
                    }
                    for rec in records
                ],
            }
    except Exception as e:
        return {"available": False, "error": str(e)}
