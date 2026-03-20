import httpx
import whois
import os
from datetime import datetime, timezone

IP2WHOIS_KEY = os.getenv("IP2WHOIS_KEY")

async def get_domain_info(domain: str) -> dict:
    try:
        # WHOIS via IP2WHOIS
        whois_data = {}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    f"https://api.ip2whois.com/v2",
                    params={"key": IP2WHOIS_KEY, "domain": domain}
                )
                r.raise_for_status()
                data = r.json()
                if "error" in data:
                    raise Exception("IP2WHOIS Error")
                create_date = data.get("create_date", "")
                expire_date = data.get("expire_date", "")
                registrar = data.get("registrar", {}).get("name", "Unknown")

                # Calculate domain age
                age_days = None
                if create_date:
                    try:
                        created = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - created).days
                    except:
                        pass

                whois_data = {
                    "registrar": registrar,
                    "created": create_date,
                    "expires": expire_date,
                    "age_days": age_days,
                }
        except:
            # Fallback to python-whois
            try:
                w = whois.whois(domain)
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                
                age_days = None
                if created:
                    try:
                        if created.tzinfo:
                            age_days = (datetime.now(timezone.utc) - created).days
                        else:
                            age_days = (datetime.now() - created).days
                    except:
                        pass
                
                def get_w(field):
                    val = getattr(w, field, None)
                    return val[0] if isinstance(val, list) and len(val) > 0 else val
                
                whois_data = {
                    "registrar": w.registrar or "Unknown",
                    "created": str(created) if created else None,
                    "expires": str(get_w("expiration_date")) if get_w("expiration_date") else None,
                    "age_days": age_days,
                    "registrant_name": get_w("name"),
                    "registrant_org": get_w("org"),
                    "registrant_emails": get_w("emails"),
                    "registrant_state": get_w("state"),
                    "registrant_country": get_w("country"),
                    "dnssec": get_w("dnssec")
                }
            except:
                whois_data = {"registrar": "Unknown", "created": None, "expires": None, "age_days": None}

        # IP Geolocation via ip-api.com
        geo_data = {}
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"http://ip-api.com/json/{domain}?fields=country,city,isp,as,query")
                g = r.json()
                geo_data = {
                    "ip": g.get("query"),
                    "country": g.get("country"),
                    "city": g.get("city"),
                    "isp": g.get("isp"),
                    "asn": g.get("as"),
                }
        except:
            geo_data = {"ip": None, "country": None, "city": None, "isp": None, "asn": None}

        return {
            "available": True,
            **whois_data,
            **geo_data,
        }

    except Exception as e:
        return {"available": False, "error": str(e)}
