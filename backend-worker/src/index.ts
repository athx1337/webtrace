import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface Env {
	OTX_API_KEY: string;
	ABUSEIPDB_KEY: string;
	GREYNOISE_KEY: string;
	URLHAUS_KEY: string;
	VIEWDNS_KEY: string;
	GEMINI_API_KEY: string;
}

const app = new Hono<{ Bindings: Env }>();

// Enable CORS for all routes
app.use(
	'*',
	cors({
		origin: (origin) => {
			if (!origin) return '*';
			if (
				origin.endsWith('.vercel.app') ||
				origin.startsWith('http://localhost:') ||
				origin.startsWith('https://localhost:')
			) {
				return origin;
			}
			return origin;
		},
		allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
		allowHeaders: ['Content-Type', 'Authorization'],
		exposeHeaders: ['Content-Length'],
		maxAge: 600,
		credentials: true,
	})
);

// --- Helpers & Service Modules ---

const SUSPICIOUS_TLDS = new Set([
	'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
	'.top', '.click', '.loan', '.work', '.party',
	'.win', '.download', '.stream', '.gdn'
]);

const KNOWN_BRANDS = [
	'google', 'facebook', 'apple', 'microsoft', 'amazon',
	'paypal', 'netflix', 'instagram', 'twitter', 'whatsapp',
	'linkedin', 'youtube', 'gmail', 'outlook', 'office'
];

function normalizeUrl(raw: string) {
	raw = raw.trim();
	let urlWithScheme = raw;
	if (!raw.startsWith('http://') && !raw.startsWith('https://')) {
		urlWithScheme = 'https://' + raw;
	}

	const parsed = new URL(urlWithScheme);
	const hostname = parsed.hostname;
	const usesHttps = parsed.protocol === 'https:';

	// Check if IP-based
	const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
	const isIp = ipPattern.test(hostname);

	// TLD and domain extraction
	const parts = hostname.split('.');
	let tld = '';
	let domain = hostname;
	let subdomains: string[] = [];
	if (!isIp && parts.length > 1) {
		tld = '.' + parts[parts.length - 1];
		const last2 = parts.slice(-2).join('.');
		const doubleSuffixes = [
			'co.uk', 'org.uk', 'com.br', 'gov.br', 'com.au',
			'net.au', 'co.in', 'org.in', 'net.in'
		];
		if (doubleSuffixes.includes(last2) && parts.length >= 3) {
			tld = '.' + last2;
			domain = parts[parts.length - 3] + '.' + last2;
			subdomains = parts.slice(0, parts.length - 3);
		} else {
			domain = parts[parts.length - 2] + '.' + parts[parts.length - 1];
			subdomains = parts.slice(0, parts.length - 2);
		}
	}

	// Suspicious chars
	const suspiciousChars: string[] = [];
	if (raw.includes('@')) suspiciousChars.push('@');
	if (raw.includes('%')) suspiciousChars.push('%');
	if (parsed.pathname.includes('//')) suspiciousChars.push('//');

	// Typosquatting check
	let typosquatTarget: string | null = null;
	for (const brand of KNOWN_BRANDS) {
		if (domain.includes(brand) && domain !== brand + tld) {
			typosquatTarget = brand;
			break;
		}
	}

	return {
		raw,
		domain,
		hostname,
		tld,
		subdomains,
		subdomain_count: subdomains.length,
		is_ip: isIp,
		uses_https: usesHttps,
		url_length: raw.length,
		suspicious_chars: suspiciousChars,
		typosquat_target: typosquatTarget,
		is_suspicious_tld: SUSPICIOUS_TLDS.has(tld),
		path: parsed.pathname,
		query: parsed.search.slice(1),
	};
}

async function queryDNS(name: string, type: string): Promise<string[]> {
	try {
		const res = await fetch(
			`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
			{ headers: { accept: 'application/dns-json' } }
		);
		if (!res.ok) return [];
		const data: any = await res.json();
		if (!data.Answer) return [];
		return data.Answer.map((ans: any) => ans.data.replace(/"/g, ''));
	} catch {
		return [];
	}
}

function getPtrName(ip: string): string {
	if (ip.includes(':')) return ''; // Basic IPv4 reverse lookup mapping
	return ip.split('.').reverse().join('.') + '.in-addr.arpa';
}

const CDN_ORGS = [
	'cloudflare', 'akamai', 'fastly', 'amazon', 'cloudfront',
	'incapsula', 'sucuri', 'imperva', 'maxcdn', 'stackpath'
];

async function addressLookup(hostname: string) {
	try {
		const ipv4Promise = queryDNS(hostname, 'A');
		const ipv6Promise = queryDNS(hostname, 'AAAA');
		const cnamePromise = queryDNS(hostname, 'CNAME');

		const [ipv4, ipv6, cnames] = await Promise.all([ipv4Promise, ipv6Promise, cnamePromise]);
		const canonical = cnames.length ? cnames[0] : hostname;

		const ptrRecords: Record<string, string | null> = {};
		await Promise.all(
			ipv4.map(async (ip) => {
				const ptrName = getPtrName(ip);
				if (ptrName) {
					const ptr = await queryDNS(ptrName, 'PTR');
					ptrRecords[ip] = ptr.length ? ptr[0] : null;
				} else {
					ptrRecords[ip] = null;
				}
			})
		);

		// CDN detection
		let cdnDetected: string | null = null;
		const allText = [canonical, ...Object.values(ptrRecords).filter(Boolean)].join(' ').toLowerCase();
		for (const cdn of CDN_ORGS) {
			if (allText.includes(cdn)) {
				cdnDetected = cdn.charAt(0).toUpperCase() + cdn.slice(1);
				break;
			}
		}

		if (!cdnDetected) {
			for (const ip of ipv4) {
				if (ip.startsWith('172.6') || ip.startsWith('104.1') || ip.startsWith('103.')) {
					cdnDetected = 'Cloudflare (likely)';
					break;
				}
			}
		}

		return {
			available: true,
			canonical,
			ipv4,
			ipv6,
			ptr: ptrRecords,
			cdn_detected: cdnDetected,
			real_ip_hidden: cdnDetected !== null,
		};
	} catch (e: any) {
		return { available: false, error: e.message };
	}
}

async function whoisDomain(domain: string) {
	try {
		const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
			headers: { 'Accept': 'application/json' },
			redirect: 'follow',
		});
		if (res.status !== 200) {
			return { available: false, error: `RDAP returned status ${res.status}` };
		}
		const data: any = await res.json();

		let created = null;
		let expires = null;
		let updated = null;

		for (const event of data.events || []) {
			const action = event.eventAction || '';
			const date = event.eventDate || '';
			if (action === 'registration') created = date;
			else if (action === 'expiration') expires = date;
			else if (action === 'last changed') updated = date;
		}

		let registrar = null;
		let registrantOrg = null;

		for (const entity of data.entities || []) {
			const roles = entity.roles || [];
			const vcardArray = entity.vcardArray || [null, []];
			const vcard = vcardArray[1] || [];
			const orgValue = vcard.find((v: any) => v[0] === 'org');
			const fnValue = vcard.find((v: any) => v[0] === 'fn');

			const org = orgValue ? orgValue[3] : null;
			const name = fnValue ? fnValue[3] : null;

			if (roles.includes('registrar')) {
				registrar = org || name;
			}
			if (roles.includes('registrant')) {
				registrantOrg = org || name;
			}
		}

		if (!registrar) {
			registrar = data.port43 || 'Unknown';
		}

		const nameservers = (data.nameservers || []).map((ns: any) => (ns.ldhName || '').toLowerCase());
		const dnssecSigned = data.secureDNS?.delegationSigned || false;
		const dnssec = dnssecSigned ? 'SIGNED' : 'UNSIGNED';

		let ageDays = null;
		if (created) {
			const createdDate = new Date(created);
			if (!isNaN(createdDate.getTime())) {
				ageDays = Math.floor((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24));
			}
		}

		return {
			available: true,
			source: 'RDAP',
			registrar,
			registrant_org: registrantOrg,
			created,
			expires,
			updated,
			age_days: ageDays,
			nameservers,
			dnssec,
		};
	} catch (err: any) {
		return { available: false, error: err.message };
	}
}

async function whoisNetwork(ip: string) {
	try {
		const res = await fetch(`https://rdap.arin.net/registry/ip/${ip}`, {
			headers: { 'Accept': 'application/json' },
			redirect: 'follow',
		});
		if (!res.ok) return { available: false, error: `ARIN RDAP returned ${res.status}` };
		const data: any = await res.json();

		const start = data.startAddress || '';
		const end = data.endAddress || '';
		const cidr = data.cidr0_cidrs?.[0] || {};
		const cidr_str = `${cidr.v4prefix || cidr.v6prefix || ''}/${cidr.length || ''}`;

		const net_name = data.name || '';
		const net_type = data.type || '';
		const country = data.country || '';

		let org_name = null;
		let abuse_email = null;

		for (const entity of data.entities || []) {
			const roles = entity.roles || [];
			const vcard = entity.vcardArray?.[1] || [];
			const fnVal = vcard.find((v: any) => v[0] === 'fn');
			const emailVal = vcard.find((v: any) => v[0] === 'email');
			const name = fnVal ? fnVal[3] : null;
			const email = emailVal ? emailVal[3] : null;

			if (roles.includes('registrant') && name) {
				org_name = name;
			}
			if (roles.includes('abuse') && email) {
				abuse_email = email;
			}
		}

		const autnums = data.arin_originas0_originautnums || [];
		const asn = autnums.length ? `AS${autnums[0]}` : null;

		return {
			available: true,
			ip,
			network: cidr_str,
			range: `${start} - ${end}`,
			net_name,
			net_type,
			org: org_name || 'Unknown',
			country,
			asn,
			abuse_email,
		};
	} catch (err: any) {
		return { available: false, error: err.message };
	}
}

async function dnsRecords(domain: string) {
	try {
		const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CAA'];
		const records: Record<string, string[]> = {};

		await Promise.all(
			RECORD_TYPES.map(async (rtype) => {
				records[rtype] = await queryDNS(domain, rtype);
			})
		);

		// SPF
		const txtRecords = records['TXT'] || [];
		const spf = txtRecords.find((r) => r.includes('v=spf1')) || null;
		const hasSpf = spf !== null;

		// DMARC
		const dmarcAns = await queryDNS(`_dmarc.${domain}`, 'TXT');
		const dmarcRecord = dmarcAns.length ? dmarcAns[0] : null;
		const hasDmarc = dmarcRecord !== null;

		// DKIM
		const selectors = ['default', 'google', 'k1', 'dkim', 'mail', 'smtp'];
		const dkimResults = await Promise.all(
			selectors.map(async (selector) => {
				const ans = await queryDNS(`${selector}._domainkey.${domain}`, 'TXT');
				return ans.length > 0;
			})
		);
		const dkimFound = dkimResults.some((res) => res);

		const flags: string[] = [];
		if (!records['MX'] || records['MX'].length === 0) {
			flags.push('No MX records — domain not configured to receive email');
		}
		if (!hasSpf) {
			flags.push('No SPF record — domain vulnerable to email spoofing');
		}
		if (!hasDmarc) {
			flags.push('No DMARC policy — no protection against spoofed email');
		}
		if (!dkimFound) {
			flags.push('No DKIM record found (checked common selectors)');
		}
		if (!records['CAA'] || records['CAA'].length === 0) {
			flags.push('No CAA record — any CA can issue certs for this domain');
		}

		return {
			available: true,
			records,
			spf,
			dmarc: dmarcRecord,
			dkim_found: dkimFound,
			has_spf: hasSpf,
			has_dmarc: hasDmarc,
			flags,
		};
	} catch (e: any) {
		return { available: false, error: e.message, records: {}, flags: [] };
	}
}

async function sslAnalysis(domain: string) {
	try {
		const res = await fetch(
			`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&limit=1&expand=issuer&expand=dns_names`
		);
		if (!res.ok) {
			return { available: false, error: `CertSpotter returned status ${res.status}` };
		}
		const list: any = await res.json();
		if (!Array.isArray(list) || list.length === 0) {
			return {
				available: true,
				valid: false,
				error: 'No certificates found in CT logs',
				flags: ['No TLS certificate found in logs'],
			};
		}

		const cert = list[0];
		const notBefore = new Date(cert.not_before);
		const notAfter = new Date(cert.not_after);
		const now = new Date();

		const certAgeDays = Math.floor((now.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24));
		const daysRemaining = Math.floor((notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

		const isExpired = daysRemaining < 0;
		const isNew = certAgeDays < 7;

		const issuerName = cert.issuer?.name || '';
		const issuerOrgMatch = issuerName.match(/O=([^,]+)/);
		const issuerOrg = issuerOrgMatch ? issuerOrgMatch[1] : cert.issuer?.friendly_name || 'Unknown';
		const issuerCnMatch = issuerName.match(/CN=([^,]+)/);
		const issuerCn = issuerCnMatch ? issuerCnMatch[1] : '';

		const sans = cert.dns_names || [];
		const sanCount = sans.length;

		const isFreeCa = ['let\'s encrypt', 'zerossl', 'buypass', 'ssl.com free'].some(
			(ca) => issuerOrg.toLowerCase().includes(ca) || issuerCn.toLowerCase().includes(ca)
		);

		const hostname = domain;
		const domainMatch = sans.some((s: string) => {
			if (hostname === s) return true;
			if (s.startsWith('*.')) {
				return hostname.endsWith(s.slice(2));
			}
			return false;
		});

		const flags: string[] = [];
		if (isExpired) {
			flags.push('Certificate is expired');
		}
		if (isNew) {
			flags.push('Certificate issued less than 7 days ago — phishing signal');
		}
		if (daysRemaining < 14 && !isExpired) {
			flags.push(`Certificate expiring in ${daysRemaining} days`);
		}
		if (isFreeCa) {
			flags.push(
				'Free CA used (Let\'s Encrypt / ZeroSSL) — combined with other signals, may indicate phishing'
			);
		}
		if (!domainMatch) {
			flags.push('Certificate domain mismatch — cert not issued for this hostname');
		}
		if (sanCount > 50) {
			flags.push(`Certificate covers ${sanCount} domains — shared hosting or CDN`);
		}

		return {
			available: true,
			valid: !isExpired,
			common_name: sans[0] || '',
			issuer_org: issuerOrg,
			issuer_cn: issuerCn,
			is_free_ca: isFreeCa,
			issued: notBefore.toISOString(),
			expires: notAfter.toISOString(),
			cert_age_days: certAgeDays,
			days_remaining: daysRemaining,
			is_expired: isExpired,
			is_new_cert: isNew,
			sans,
			san_count: sanCount,
			domain_match: domainMatch,
			flags,
		};
	} catch (err: any) {
		return { available: false, valid: false, error: err.message, flags: [] };
	}
}

async function infrastructureScan(ip: string) {
	if (!ip) return { available: false, reason: 'No IP provided' };
	try {
		const res = await fetch(`https://internetdb.shodan.io/${ip}`);
		if (res.status === 404) {
			return {
				available: true,
				ip,
				ports: [],
				cpes: [],
				vulns: [],
				hostnames: [],
				tags: [],
				flags: ['No data in Shodan InternetDB for this IP'],
			};
		}
		if (!res.ok) return { available: false, error: `Shodan returned status ${res.status}` };
		const data: any = await res.json();

		const ports = data.ports || [];
		const cpes = data.cpes || [];
		const vulns = data.vulns || [];
		const hostnames = data.hostnames || [];
		const tags = data.tags || [];

		const flags: string[] = [];
		if (vulns.length) {
			flags.push(`${vulns.length} known CVE(s) on exposed services: ${vulns.join(', ')}`);
		}
		if (tags.includes('tor')) flags.push('IP is a known Tor exit node');
		if (tags.includes('vpn')) flags.push('IP is associated with a VPN service');
		if (tags.includes('scanner')) flags.push('IP is a known internet scanner');
		if (tags.includes('malware')) flags.push('IP tagged as malware-related in Shodan');

		const unusual = ports.filter(
			(p: number) => ![80, 443, 22, 21, 25, 587, 993, 995, 53, 8080, 8443].includes(p)
		);
		if (unusual.length) {
			flags.push(`Unusual open ports detected: ${unusual.join(', ')}`);
		}

		return {
			available: true,
			ip,
			ports,
			cpes,
			vulns,
			hostnames,
			tags,
			flags,
		};
	} catch (err: any) {
		return { available: false, error: err.message };
	}
}

async function subdomains(domain: string) {
	try {
		const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
			headers: { 'Accept': 'application/json' },
		});
		if (!res.ok) return { available: false, error: `crt.sh returned status ${res.status}` };
		const data: any = await res.json();
		if (!Array.isArray(data)) return { available: false, error: 'Invalid crt.sh response' };

		const seen = new Set<string>();
		const uniqueSubs: any[] = [];
		for (const entry of data) {
			const names = (entry.name_value || '').split('\n');
			for (let name of names) {
				name = name.trim().toLowerCase().replace(/^\*\./, '');
				if (name && !seen.has(name) && name.endsWith(domain)) {
					seen.add(name);
					uniqueSubs.push({
						subdomain: name,
						issuer: entry.issuer_name || '',
						not_before: entry.not_before || '',
						not_after: entry.not_after || '',
					});
				}
			}
		}

		uniqueSubs.sort((a, b) => a.subdomain.localeCompare(b.subdomain));

		const NOTABLE_SUBDOMAINS = [
			'admin', 'mail', 'vpn', 'api', 'dev', 'staging', 'test',
			'beta', 'portal', 'dashboard', 'login', 'secure', 'ftp',
			'remote', 'internal', 'corp', 'manage', 'backup', 'old',
		];

		const notableFound: string[] = [];
		for (const sub of uniqueSubs) {
			const part = sub.subdomain.replace(`.${domain}`, '').replace(domain, '');
			if (NOTABLE_SUBDOMAINS.some((n) => part.includes(n))) {
				notableFound.push(sub.subdomain);
			}
		}

		return {
			available: true,
			total: uniqueSubs.length,
			subdomains: uniqueSubs.slice(0, 100),
			notable: notableFound,
			flags: notableFound.map((s) => `Sensitive subdomain found: ${s}`),
		};
	} catch (err: any) {
		return { available: false, error: err.message };
	}
}

async function threatIntel(domain: string, ip?: string, keys: Record<string, string> = {}) {
	const otxKey = keys.OTX_API_KEY;
	const abuseipdbKey = keys.ABUSEIPDB_KEY;
	const greynoiseKey = keys.GREYNOISE_KEY;
	const urlhausKey = keys.URLHAUS_KEY;

	const otxPromise = (async () => {
		try {
			const headers: Record<string, string> = {};
			if (otxKey) headers['X-OTX-API-KEY'] = otxKey;
			const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, { headers });
			if (!res.ok) return { available: false, flagged: false };
			const data: any = await res.json();
			const pulse_count = data.pulse_info?.count || 0;
			const pulses = data.pulse_info?.pulses || [];
			const malware_families = Array.from(
				new Set(pulses.map((p: any) => p.malware_families?.[0]?.display_name).filter(Boolean))
			);
			const tags = Array.from(new Set(pulses.flatMap((p: any) => p.tags || []))).slice(0, 10);
			return {
				available: true,
				pulse_count,
				malware_families,
				tags,
				flagged: pulse_count > 0,
			};
		} catch (err: any) {
			return { available: false, flagged: false, error: err.message };
		}
	})();

	const abuseipdbPromise = (async () => {
		if (!ip || !abuseipdbKey) return { available: false, flagged: false, reason: 'No IP or API key' };
		try {
			const res = await fetch(
				`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
				{ headers: { 'Key': abuseipdbKey, 'Accept': 'application/json' } }
			);
			if (!res.ok) return { available: false, flagged: false };
			const body: any = await res.json();
			const d = body.data || {};
			const score = d.abuseConfidenceScore || 0;
			return {
				available: true,
				abuse_score: score,
				total_reports: d.totalReports || 0,
				last_reported: d.lastReportedAt,
				is_tor: d.isTor || false,
				usage_type: d.usageType || '',
				isp: d.isp || '',
				flagged: score > 20,
			};
		} catch (err: any) {
			return { available: false, flagged: false, error: err.message };
		}
	})();

	const threatfoxPromise = (async () => {
		try {
			const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ query: 'search_ioc', search_term: domain }),
			});
			if (!res.ok) return { available: false, flagged: false };
			const data: any = await res.json();
			const found = data.query_status === 'ok' && data.data;
			const iocs = data.data || [];
			return {
				available: true,
				flagged: !!found,
				ioc_count: iocs.length,
				threat_types: Array.from(new Set(iocs.map((i: any) => i.threat_type).filter(Boolean))),
				malware: Array.from(new Set(iocs.map((i: any) => i.malware).filter(Boolean))),
			};
		} catch (err: any) {
			return { available: false, flagged: false, error: err.message };
		}
	})();

	const greynoisePromise = (async () => {
		if (!ip) return { available: false, flagged: false };
		try {
			const headers: Record<string, string> = {};
			if (greynoiseKey) headers['key'] = greynoiseKey;
			const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, { headers });
			if (res.status === 404) {
				return { available: true, flagged: false, noise: false, riot: false, classification: 'unknown' };
			}
			if (!res.ok) return { available: false, flagged: false };
			const data: any = await res.json();
			return {
				available: true,
				noise: data.noise || false,
				riot: data.riot || false,
				classification: data.classification || 'unknown',
				name: data.name || '',
				flagged: (data.noise || false) && data.classification === 'malicious',
			};
		} catch (err: any) {
			return { available: false, flagged: false, error: err.message };
		}
	})();

	const urlhausPromise = (async () => {
		try {
			const body = new URLSearchParams();
			body.append('host', domain);
			const headers: Record<string, string> = {};
			if (urlhausKey) headers['Auth-Key'] = urlhausKey;
			const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
				method: 'POST',
				headers,
				body,
			});
			if (!res.ok) return { available: false, flagged: false };
			const data: any = await res.json();
			const flagged = data.query_status === 'ok';
			const urls = data.urls || [];
			return {
				available: true,
				flagged,
				url_count: urls.length,
				tags: Array.from(new Set(urls.flatMap((u: any) => u.tags || []))),
			};
		} catch (err: any) {
			return { available: false, flagged: false, error: err.message };
		}
	})();

	const [otx, abuseipdb, tfox, gnoise, urlhaus] = await Promise.all([
		otxPromise,
		abuseipdbPromise,
		threatfoxPromise,
		greynoisePromise,
		urlhausPromise,
	]);

	const engines = { otx, abuseipdb, threatfox: tfox, greynoise: gnoise, urlhaus };
	const flaggedCount = Object.values(engines).filter((e) => e.flagged).length;

	let verdict = 'CLEAN';
	if (flaggedCount >= 2) verdict = 'MALICIOUS';
	else if (flaggedCount === 1) verdict = 'SUSPICIOUS';

	return {
		available: true,
		verdict,
		flagged_by: flaggedCount,
		engines,
	};
}

async function historicalLookup(domain: string, viewDnsKey?: string) {
	const waybackPromise = (async () => {
		try {
			const res = await fetch(`http://archive.org/wayback/available?url=${encodeURIComponent(domain)}`);
			if (!res.ok) return { available: false };
			const data: any = await res.json();
			const snapshot = data.archived_snapshots?.closest || {};
			const available = snapshot.available || false;

			let count: number | null = null;
			try {
				const cdxCountRes = await fetch(
					`http://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=0&showNumPages=true`
				);
				if (cdxCountRes.ok) {
					const txt = await cdxCountRes.text();
					const parsed = parseInt(txt.trim());
					if (!isNaN(parsed)) count = parsed;
				}
			} catch {}

			return {
				available,
				first_snapshot: snapshot.timestamp || null,
				closest_url: snapshot.url || null,
				snapshot_count: count,
				flag: !available ? 'No Wayback Machine history — domain may be very new' : null,
			};
		} catch (err: any) {
			return { available: false, error: err.message };
		}
	})();

	const ipHistoryPromise = (async () => {
		if (!viewDnsKey) return { available: false, reason: 'VIEWDNS_KEY not set' };
		try {
			const res = await fetch(
				`https://api.viewdns.info/iphistory/?domain=${encodeURIComponent(domain)}&apikey=${viewDnsKey}&output=json`
			);
			if (!res.ok) return { available: false };
			const data: any = await res.json();
			const records = data.response?.records || [];
			return {
				available: true,
				history: records.map((rec: any) => ({
					ip: rec.ip,
					location: rec.location,
					owner: rec.owner,
					last_seen: rec.lastseen,
				})),
			};
		} catch (err: any) {
			return { available: false, error: err.message };
		}
	})();

	const [wayback, ip_history] = await Promise.all([waybackPromise, ipHistoryPromise]);
	return { available: true, wayback, ip_history };
}

async function generateExplanation(scan: any, geminiKey?: string) {
	if (!geminiKey) return { available: false, error: 'GEMINI_API_KEY not set' };
	try {
		const domain = scan.domain || 'unknown';
		const addr = scan.address_lookup || {};
		const whois = scan.whois_domain || {};
		const net = scan.whois_network || {};
		const ssl = scan.ssl || {};
		const infra = scan.infrastructure || {};
		const threat = scan.threat_intel || {};
		const subs = scan.subdomains || {};
		const hist = scan.historical || {};
		const dns = scan.dns_records || {};

		const prompt = `You are a senior cybersecurity analyst writing a brief for a security researcher.
Based on the structured scan data below, write a 3-4 sentence technical summary.
Be specific — mention actual findings (CDN, CVEs, threat intel hits, cert age, subdomain count, domain age).
Do not use bullet points. Do not be vague. Treat the researcher as an expert.

Domain: ${domain}
CDN Detected: ${addr.cdn_detected || 'None'} | Real IP Hidden: ${addr.real_ip_hidden || false}
Domain Age: ${whois.age_days || 'Unknown'} days | Registrar: ${whois.registrar || 'Unknown'} | DNSSEC: ${whois.dnssec || 'UNSIGNED'}
Network Owner: ${net.org || 'Unknown'} | ASN: ${net.asn || 'Unknown'} | Country: ${net.country || 'Unknown'}
SSL: Valid=${ssl.valid} | Issuer=${ssl.issuer_org || 'Unknown'} | Age=${ssl.cert_age_days || 'Unknown'} days | Expires in ${ssl.days_remaining || 'Unknown'} days | Free CA=${ssl.is_free_ca}
SSL Flags: ${JSON.stringify(ssl.flags || [])}
Open Ports: ${JSON.stringify(infra.ports || [])} | CVEs: ${JSON.stringify(infra.vulns || [])} | Tags: ${JSON.stringify(infra.tags || [])}
Threat Intel Verdict: ${threat.verdict || 'CLEAN'} | Flagged by ${threat.flagged_by || 0} engines
OTX Pulses: ${threat.engines?.otx?.pulse_count || 0}
AbuseIPDB Score: ${threat.engines?.abuseipdb?.abuse_score || 0}%
ThreatFox IOCs: ${threat.engines?.threatfox?.ioc_count || 0}
DNS Flags: ${JSON.stringify(dns.flags || [])}
Subdomains Found: ${subs.total || 0} | Notable: ${JSON.stringify(subs.notable || [])}
Wayback Available: ${hist.wayback?.available || false} | Snapshots: ${hist.wayback?.snapshot_count || 0}`;

		const res = await fetch(
			`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					contents: [{ parts: [{ text: prompt }] }],
				}),
			}
		);
		if (!res.ok) return { available: false, error: `Gemini API returned status ${res.status}` };
		const data: any = await res.json();
		const text = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';

		return {
			available: true,
			summary: text,
			engine: 'gemini-2.5-flash',
		};
	} catch (err: any) {
		return { available: false, error: err.message };
	}
}

// --- Endpoints ---

// Ping endpoint
app.get('/api/ping', (c) => {
	return c.json({
		status: 'online',
		tool: 'TRACE',
		version: '2.0',
	});
});

// Mock /api/data endpoint
app.get('/api/data', (c) => {
	return c.json({
		status: 'success',
		provider: 'Cloudflare Workers via Antigravity',
	});
});

// Full scan /api/analyze endpoint
app.post('/api/analyze', async (c) => {
	try {
		const body = await c.req.json().catch(() => null);
		if (!body || !body.url) {
			return c.json({ error: 'URL is required' }, 400);
		}

		const rawUrl = body.url.trim();
		if (!rawUrl) {
			return c.json({ error: 'URL is required' }, 400);
		}

		// Normalize input
		const parsed = normalizeUrl(rawUrl);
		const domain = parsed.domain;
		const hostname = parsed.hostname;

		// Address lookup first — everything else needs the IPs
		const addrResult = await addressLookup(hostname);
		const primaryIp = addrResult.ipv4?.[0] || null;

		// Run independent modules concurrently
		const [whoisDomainResult, dnsResult, sslResult, subdomainResult, historicalResult] = await Promise.all([
			whoisDomain(domain),
			dnsRecords(domain),
			sslAnalysis(domain),
			subdomains(domain),
			historicalLookup(domain, c.env.VIEWDNS_KEY),
		]);

		// IP-dependent modules
		const whoisNetResult = primaryIp
			? await whoisNetwork(primaryIp)
			: { available: false, reason: 'No primary IP resolved', module: 'whois_network' };
		const infraResult = primaryIp
			? await infrastructureScan(primaryIp)
			: { available: false, reason: 'No primary IP resolved', module: 'infrastructure' };
		const threatResult = await threatIntel(domain, primaryIp, {
			OTX_API_KEY: c.env.OTX_API_KEY,
			ABUSEIPDB_KEY: c.env.ABUSEIPDB_KEY,
			GREYNOISE_KEY: c.env.GREYNOISE_KEY,
			URLHAUS_KEY: c.env.URLHAUS_KEY,
		});

		// Assemble full result
		const fullResult: any = {
			domain,
			address_lookup: addrResult,
			whois_domain: whoisDomainResult,
			whois_network: whoisNetResult,
			dns_records: dnsResult,
			ssl: sslResult,
			infrastructure: infraResult,
			subdomains: subdomainResult,
			threat_intel: threatResult,
			historical: historicalResult,
		};

		// AI explanation last
		fullResult.ai_explanation = await generateExplanation(fullResult, c.env.GEMINI_API_KEY);

		return c.json(fullResult);
	} catch (err: any) {
		return c.json({ error: err.message }, 500);
	}
});

export default app;
