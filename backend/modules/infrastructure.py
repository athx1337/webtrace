"""
infrastructure.py
Queries Shodan InternetDB (free, no key) for open ports,
software fingerprints (CPEs), known CVEs, and tags on the IP.
Replaces the active service scan Domain Dossier does.
"""

import httpx


async def infrastructure_scan(ip: str) -> dict:
    if not ip:
        return {"available": False, "reason": "No IP provided"}

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(f"https://internetdb.shodan.io/{ip}")

            if r.status_code == 404:
                return {
                    "available": True,
                    "ip": ip,
                    "ports": [],
                    "cpes": [],
                    "vulns": [],
                    "hostnames": [],
                    "tags": [],
                    "flags": ["No data in Shodan InternetDB for this IP"],
                }

            data = r.json()

            ports = data.get("ports", [])
            cpes = data.get("cpes", [])
            vulns = data.get("vulns", [])
            hostnames = data.get("hostnames", [])
            tags = data.get("tags", [])

            flags = []
            if vulns:
                flags.append(f"{len(vulns)} known CVE(s) on exposed services: {', '.join(vulns)}")
            if "tor" in tags:
                flags.append("IP is a known Tor exit node")
            if "vpn" in tags:
                flags.append("IP is associated with a VPN service")
            if "scanner" in tags:
                flags.append("IP is a known internet scanner")
            if "malware" in tags:
                flags.append("IP tagged as malware-related in Shodan")

            # Flag unusual ports
            unusual = [p for p in ports if p not in (80, 443, 22, 21, 25, 587, 993, 995, 53, 8080, 8443)]
            if unusual:
                flags.append(f"Unusual open ports detected: {', '.join(map(str, unusual))}")

            return {
                "available": True,
                "ip": ip,
                "ports": ports,
                "cpes": cpes,
                "vulns": vulns,
                "hostnames": hostnames,
                "tags": tags,
                "flags": flags,
            }

    except Exception as e:
        return {"available": False, "error": str(e)}
