"""
whois_network.py
Fetches network/IP block WHOIS via ARIN RDAP.
Tells you who OWNS the IP block — the ISP/org, not the website owner.
"""

import httpx


async def whois_network(ip: str) -> dict:
    if not ip:
        return {"available": False, "reason": "No IP provided"}

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://rdap.arin.net/registry/ip/{ip}",
                headers={"Accept": "application/json"},
                follow_redirects=True,
            )
            data = r.json()

            # IP range
            start = data.get("startAddress", "")
            end = data.get("endAddress", "")
            cidr = data.get("cidr0_cidrs", [{}])[0]
            cidr_str = f"{cidr.get('v4prefix', cidr.get('v6prefix', ''))}/{cidr.get('length', '')}"

            net_name = data.get("name", "")
            net_type = data.get("type", "")
            country = data.get("country", "")

            # Org name from entities
            org_name = None
            abuse_email = None
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])[1]
                name = next((v[3] for v in vcard if v[0] == "fn"), None)
                email = next((v[3] for v in vcard if v[0] == "email"), None)
                if "registrant" in roles and name:
                    org_name = name
                if "abuse" in roles and email:
                    abuse_email = email

            # ASN from originAutnums
            asn = None
            autnums = data.get("arin_originas0_originautnums", [])
            if autnums:
                asn = f"AS{autnums[0]}"

            return {
                "available": True,
                "ip": ip,
                "network": cidr_str,
                "range": f"{start} - {end}",
                "net_name": net_name,
                "net_type": net_type,
                "org": org_name or "Unknown",
                "country": country,
                "asn": asn,
                "abuse_email": abuse_email,
            }

    except Exception as e:
        return {"available": False, "error": str(e)}
