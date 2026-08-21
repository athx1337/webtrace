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
		exposeHeaders: ['Content-Length', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
		maxAge: 600,
		credentials: true,
	})
);

// --- In-Worker Rate Limiting (Token Bucket per IP) ---
const ipRateLimit = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string, limit = 20, windowMs = 60000): { allowed: boolean; remaining: number } {
	const now = Date.now();
	
	// Lazy cleanup of expired records if map gets large
	if (ipRateLimit.size > 200) {
		for (const [key, data] of ipRateLimit.entries()) {
			if (now > data.resetAt) ipRateLimit.delete(key);
		}
	}

	const record = ipRateLimit.get(ip);

	if (!record || now > record.resetAt) {
		ipRateLimit.set(ip, { count: 1, resetAt: now + windowMs });
		return { allowed: true, remaining: limit - 1 };
	}

	if (record.count >= limit) {
		return { allowed: false, remaining: 0 };
	}

	record.count += 1;
	return { allowed: true, remaining: limit - record.count };
}

// --- SSRF Firewall & Validation ---

export function isPrivateOrBlockedIp(ipOrHost: string): boolean {
	let clean = ipOrHost.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
	
	// Handle IPv6 bracket notation [::1]:80
	if (clean.startsWith('[') && clean.includes(']')) {
		clean = clean.slice(1, clean.indexOf(']'));
	} else if (!clean.includes('::') && (clean.match(/:/g) || []).length === 1) {
		// Single colon implies host:port or ipv4:port
		clean = clean.split(':')[0];
	}

	// Hostname blacklists
	const blockedHosts = [
		'localhost',
		'localhost.localdomain',
		'ip6-localhost',
		'ip6-loopback',
		'metadata.google.internal',
		'metadata.internal',
		'169.254.169.254',
		'instance-data',
	];
	if (blockedHosts.includes(clean)) return true;

	// IPv6 loopback and private
	if (
		clean === '::1' ||
		clean === '::' ||
		clean.startsWith('fd') ||
		clean.startsWith('fe80:') ||
		clean.startsWith('fc00:')
	) {
		return true;
	}

	// IPv4 regex and range verification
	const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (ipv4Match) {
		const octets = ipv4Match.slice(1).map(Number);
		if (octets.some((o) => o > 255 || o < 0)) return true; // Invalid IP

		const [o1, o2] = octets;

		// 0.0.0.0/8 (Current network)
		if (o1 === 0) return true;

		// 10.0.0.0/8 (Private)
		if (o1 === 10) return true;

		// 127.0.0.0/8 (Loopback)
		if (o1 === 127) return true;

		// 169.254.0.0/16 (Link-Local / AWS/GCP Metadata)
		if (o1 === 169 && o2 === 254) return true;

		// 172.16.0.0/12 (Private)
		if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;

		// 192.168.0.0/16 (Private)
		if (o1 === 192 && o2 === 168) return true;

		// 100.64.0.0/10 (Shared Carrier-Grade NAT)
		if (o1 === 100 && o2 >= 64 && o2 <= 127) return true;

		// 224.0.0.0/4 (Multicast)
		if (o1 >= 224 && o1 <= 239) return true;

		// 240.0.0.0/4 (Reserved)
		if (o1 >= 240) return true;
	}

	return false;
}

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

export function normalizeUrl(raw: string) {
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
			'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.br', 'gov.br', 'com.au',
			'net.au', 'org.au', 'co.in', 'org.in', 'net.in', 'gen.in', 'firm.in',
			'ind.in', 'gov.in', 'edu.in', 'mil.in', 'res.in', 'nic.in', 'com.sg',
			'edu.sg', 'gov.sg', 'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp'
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

export async function queryDNS(name: string, type: string): Promise<string[]> {
	try {
		const res = await fetch(
			`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
			{
				headers: {
					accept: 'application/dns-json',
					'User-Agent': 'WebTrace-OSINT/2.0'
				}
			}
		);
		if (!res.ok) return [];
		const data: any = await res.json();
		if (!data.Answer) return [];
		return data.Answer.map((ans: any) => ans.data.replace(/"/g, ''));
	} catch {
		return [];
	}
}

export function getPtrName(ip: string): string {
	if (ip.includes(':')) return '';
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
			headers: {
				'Accept': 'application/json',
				'User-Agent': 'WebTrace-OSINT/2.0 (Security-Recon-Tool)'
			},
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
		const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
			headers: {
				'Accept': 'application/json',
				'User-Agent': 'WebTrace-OSINT/2.0 (Security-Recon-Tool)'
			},
			redirect: 'follow',
		});
		if (!res.ok) return { available: false, error: `IP RDAP returned status ${res.status}` };
		const data: any = await res.json();

		const start = data.startAddress || '';
		const end = data.endAddress || '';
		const cidr = data.cidr0_cidrs?.[0] || {};
		const cidr_str = cidr.v4prefix ? `${cidr.v4prefix}/${cidr.length}` : (data.handle || '');

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
			range: start && end ? `${start} - ${end}` : (data.handle || 'Unknown'),
			net_name,
			net_type,
			org: org_name || data.name || 'Unknown',
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
			`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&limit=1&expand=issuer&expand=dns_names`,
			{
				headers: { 'User-Agent': 'WebTrace-OSINT/2.0' }
			}
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
		const res = await fetch(`https://internetdb.shodan.io/${ip}`, {
			headers: { 'User-Agent': 'WebTrace-OSINT/2.0' }
		});
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

// --- Active DoH Subdomain Brute-Force Probe + CT Log Aggregator ---
const COMMON_SUBDOMAIN_WORDLIST = [
	'admin', 'vpn', 'api', 'dev', 'staging', 'portal', 'mail', 'corp',
	'internal', 'remote', 'gateway', 'auth', 'app', 'test', 'demo', 'cdn',
	'beta', 'sso', 'git', 'jenkins', 'k8s', 'grafana', 'db', 'cpanel',
	'webmail', 'monitor', 'status', 'bastion', 'vault', 'identity', 'ns1',
	'ns2', 'mx', 'direct', 'server'
];

async function subdomains(domain: string) {
	try {
		// 1. Passive CT Log query (crt.sh)
		const ctPromise = (async () => {
			try {
				const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
					headers: {
						'Accept': 'application/json',
						'User-Agent': 'WebTrace-OSINT/2.0'
					},
				});
				if (!res.ok) return [];
				const data: any = await res.json();
				if (!Array.isArray(data)) return [];
				return data;
			} catch {
				return [];
			}
		})();

		// 2. Active DoH Wordlist Probe (Parallel DNS A queries)
		const activeDohPromise = (async () => {
			const activeFound: Array<{ subdomain: string; ip: string; source: string }> = [];
			await Promise.all(
				COMMON_SUBDOMAIN_WORDLIST.map(async (prefix) => {
					const targetHost = `${prefix}.${domain}`;
					try {
						const ips = await queryDNS(targetHost, 'A');
						if (ips.length > 0) {
							activeFound.push({
								subdomain: targetHost,
								ip: ips[0],
								source: 'ACTIVE_DOH'
							});
						}
					} catch {}
				})
			);
			return activeFound;
		})();

		const [ctEntries, activeEntries] = await Promise.all([ctPromise, activeDohPromise]);

		const seen = new Set<string>();
		const uniqueSubs: any[] = [];

		// Add active entries first
		for (const act of activeEntries) {
			seen.add(act.subdomain);
			uniqueSubs.push({
				subdomain: act.subdomain,
				issuer: 'ACTIVE_RESOLVED',
				not_before: '',
				not_after: '',
				source: 'ACTIVE_DOH',
				ip: act.ip
			});
		}

		// Merge with CT entries
		for (const entry of ctEntries) {
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
						source: 'CT_LOG',
					});
				}
			}
		}

		uniqueSubs.sort((a, b) => a.subdomain.localeCompare(b.subdomain));

		const NOTABLE_SUBDOMAINS = [
			'admin', 'mail', 'vpn', 'api', 'dev', 'staging', 'test',
			'beta', 'portal', 'dashboard', 'login', 'secure', 'ftp',
			'remote', 'internal', 'corp', 'manage', 'backup', 'old',
			'k8s', 'jenkins', 'grafana', 'vault', 'cpanel'
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
			active_probed: activeEntries.length,
			subdomains: uniqueSubs.slice(0, 100),
			notable: notableFound,
			flags: notableFound.map((s) => `Sensitive subdomain found: ${s}`),
		};
	} catch (err: any) {
		return { available: false, error: err.message };
	}
}

// --- Tech Stack Fingerprinting & Security Headers Audit ---
async function techStackAndSecurityHeaders(domain: string) {
	try {
		const targetUrl = `https://${domain}`;
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 6000);

		const res = await fetch(targetUrl, {
			method: 'GET',
			headers: {
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WebTrace/2.0',
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
			},
			redirect: 'follow',
			signal: controller.signal
		}).catch(() => null);

		clearTimeout(timeout);

		if (!res) {
			return {
				available: false,
				error: 'Target host did not respond to HTTPS probe',
				security_headers: {},
				tech_stack: []
			};
		}

		const headers = res.headers;
		const serverHeader = headers.get('server') || null;
		const poweredBy = headers.get('x-powered-by') || null;
		const via = headers.get('via') || null;
		const cfRay = headers.get('cf-ray') || null;
		const vercelId = headers.get('x-vercel-id') || null;

		// Security Headers Audit
		const hsts = headers.get('strict-transport-security');
		const csp = headers.get('content-security-policy');
		const xfo = headers.get('x-frame-options');
		const xcto = headers.get('x-content-type-options');
		const permissionsPolicy = headers.get('permissions-policy');
		const referrerPolicy = headers.get('referrer-policy');

		const security_headers = {
			hsts: { present: !!hsts, value: hsts },
			csp: { present: !!csp, value: csp ? (csp.length > 60 ? csp.slice(0, 60) + '...' : csp) : null },
			x_frame_options: { present: !!xfo, value: xfo },
			x_content_type_options: { present: !!xcto, value: xcto },
			permissions_policy: { present: !!permissionsPolicy, value: permissionsPolicy },
			referrer_policy: { present: !!referrerPolicy, value: referrerPolicy },
		};

		// Heuristic Tech Stack Detection
		const stack = new Set<string>();
		if (serverHeader) stack.add(`Server: ${serverHeader}`);
		if (poweredBy) stack.add(`Powered-By: ${poweredBy}`);
		if (cfRay || (serverHeader && serverHeader.toLowerCase().includes('cloudflare'))) stack.add('Cloudflare Edge');
		if (vercelId) stack.add('Vercel Platform');
		if (via && via.toLowerCase().includes('cloudfront')) stack.add('AWS CloudFront');

		// Read HTML snippet for script signatures
		try {
			const htmlText = (await res.text()).slice(0, 100000).toLowerCase();
			if (htmlText.includes('wp-content') || htmlText.includes('wp-includes')) stack.add('WordPress');
			if (htmlText.includes('__next') || htmlText.includes('/_next/')) stack.add('Next.js');
			if (htmlText.includes('react') || htmlText.includes('react-dom') || htmlText.includes('reactjs')) stack.add('React');
			if (htmlText.includes('vue') || htmlText.includes('vue.js')) stack.add('Vue.js');
			if (htmlText.includes('angular') || htmlText.includes('ng-version')) stack.add('Angular');
			if (htmlText.includes('shopify') || htmlText.includes('cdn.shopify.com')) stack.add('Shopify');
			if (htmlText.includes('laravel') || htmlText.includes('csrf-token')) stack.add('Laravel');
			if (htmlText.includes('bootstrap') || htmlText.includes('bootstrap.min.css')) stack.add('Bootstrap');
			if (htmlText.includes('tailwind') || htmlText.includes('tailwindcss')) stack.add('TailwindCSS');
		} catch {}

		return {
			available: true,
			status_code: res.status,
			server: serverHeader,
			powered_by: poweredBy,
			security_headers,
			tech_stack: Array.from(stack),
		};
	} catch (err: any) {
		return { available: false, error: err.message, security_headers: {}, tech_stack: [] };
	}
}

async function threatIntel(domain: string, ip?: string, keys: Record<string, string> = {}) {
	const otxKey = keys.OTX_API_KEY;
	const abuseipdbKey = keys.ABUSEIPDB_KEY;
	const greynoiseKey = keys.GREYNOISE_KEY;
	const urlhausKey = keys.URLHAUS_KEY;

	const otxPromise = (async () => {
		try {
			const headers: Record<string, string> = { 'User-Agent': 'WebTrace-OSINT/2.0' };
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
				{ headers: { 'Key': abuseipdbKey, 'Accept': 'application/json', 'User-Agent': 'WebTrace-OSINT/2.0' } }
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
				headers: {
					'Content-Type': 'application/json',
					'User-Agent': 'WebTrace-OSINT/2.0'
				},
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
			const headers: Record<string, string> = { 'User-Agent': 'WebTrace-OSINT/2.0' };
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
			const headers: Record<string, string> = { 'User-Agent': 'WebTrace-OSINT/2.0' };
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
			const res = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(domain)}`, {
				headers: { 'User-Agent': 'WebTrace-OSINT/2.0' }
			});
			if (!res.ok) return { available: false };
			const data: any = await res.json();
			const snapshot = data.archived_snapshots?.closest || {};
			const available = snapshot.available || false;

			let count: number | null = null;
			try {
				const cdxCountRes = await fetch(
					`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=0&showNumPages=true`,
					{ headers: { 'User-Agent': 'WebTrace-OSINT/2.0' } }
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

	// Passive DNS from AlienVault OTX
	const passiveDnsPromise = (async () => {
		try {
			const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`, {
				headers: { 'User-Agent': 'WebTrace-OSINT/2.0' }
			});
			if (!res.ok) return [];
			const data: any = await res.json();
			const records = (data.passive_dns || []).slice(0, 10).map((r: any) => ({
				ip: r.address,
				first_seen: r.first,
				last_seen: r.last,
				hostname: r.hostname,
				record_type: r.record_type
			}));
			return records;
		} catch {
			return [];
		}
	})();

	const ipHistoryPromise = (async () => {
		if (!viewDnsKey) return { available: false, reason: 'VIEWDNS_KEY not set' };
		try {
			const res = await fetch(
				`https://api.viewdns.info/iphistory/?domain=${encodeURIComponent(domain)}&apikey=${viewDnsKey}&output=json`,
				{ headers: { 'User-Agent': 'WebTrace-OSINT/2.0' } }
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

	const [wayback, passive_dns, ip_history] = await Promise.all([waybackPromise, passiveDnsPromise, ipHistoryPromise]);
	return { available: true, wayback, passive_dns, ip_history };
}

// Structured 3-Part Pentest AI Briefing
async function generateExplanation(scan: any, geminiKey?: string) {
	if (!geminiKey) return { available: false, error: 'GEMINI_API_KEY not set' };

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
	const tech = scan.tech_stack || {};

	const prompt = `You are a Lead Penetration Tester and Cyber Threat Intelligence Analyst writing a structured executive assessment.
Analyze the target telemetry below and structure your response into EXACTLY 3 sections with clear markdown headers:

### 🌐 Perimeter & Attack Surface Overview
(Provide a concise 1-2 sentence assessment of hosting architecture, CDN protection, domain age, and overall perimeter posture).

### ⚠️ Critical Findings & Exposure
(Identify specific open database/management ports, CVE vulnerabilities, missing SPF/DMARC/DKIM/DNSSEC email posture, SSL lifespan/CA anomalies, and threat feed indicators).

### 🛡️ Prioritized Remediation Roadmap
(Provide 2-3 specific, actionable technical recommendations for security engineers).

Telemetry Data:
Domain: ${domain}
Canonical: ${addr.canonical || 'None'} | CDN Detected: ${addr.cdn_detected || 'None (Direct Origin Exposed)'}
Domain Age: ${whois.age_days || 'Unknown'} days | Registrar: ${whois.registrar || 'Unknown'} | DNSSEC: ${whois.dnssec || 'UNSIGNED'}
Network Owner: ${net.org || 'Unknown'} | ASN: ${net.asn || 'Unknown'} | Country: ${net.country || 'Unknown'}
Tech Stack: ${JSON.stringify(tech.tech_stack || [])}
Server Header: ${tech.server || 'None'}
HSTS Enabled: ${tech.security_headers?.hsts?.present || false} | CSP Configured: ${tech.security_headers?.csp?.present || false}
SSL: Valid=${ssl.valid} | Issuer=${ssl.issuer_org || 'Unknown'} | Age=${ssl.cert_age_days || 'Unknown'} days | Days Left=${ssl.days_remaining || 'Unknown'} | Free CA=${ssl.is_free_ca}
Open Ports: ${JSON.stringify(infra.ports || [])}
CVEs: ${JSON.stringify(infra.vulns || [])}
Threat Intel Verdict: ${threat.verdict || 'CLEAN'} | Flagged Engines: ${threat.flagged_by || 0}
SPF: ${dns.has_spf} | DMARC: ${dns.has_dmarc} | DKIM: ${dns.dkim_found}
Subdomains Found: ${subs.total || 0} (Active DoH Probed: ${subs.active_probed || 0}) | Notable: ${JSON.stringify(subs.notable || [])}`;

	const models = ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-flash-latest', 'gemini-3.5-flash'];

	for (const model of models) {
		try {
			const res = await fetch(
				`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
				{
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						contents: [{ parts: [{ text: prompt }] }],
					}),
				}
			);
			if (res.ok) {
				const data: any = await res.json();
				const text = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
				if (text) {
					return {
						available: true,
						summary: text,
						engine: model,
					};
				}
			}
		} catch {}
	}

	return { available: false, error: 'AI summary generation temporarily unavailable' };
}

// --- Endpoints ---

// Ping endpoint
app.get('/api/ping', (c) => {
	return c.json({
		status: 'online',
		tool: 'TRACE',
		version: '2.0',
		security: 'SSRF_PROTECTED_RATE_LIMITED'
	});
});

// Full scan /api/analyze endpoint
app.post('/api/analyze', async (c) => {
	try {
		// 1. Rate Limiting Check
		const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || '127.0.0.1';
		const { allowed, remaining } = checkRateLimit(clientIp);
		c.header('X-RateLimit-Limit', '20');
		c.header('X-RateLimit-Remaining', String(remaining));

		if (!allowed) {
			return c.json({ error: 'Rate limit exceeded: Maximum 20 scans per minute. Please retry shortly.' }, 429);
		}

		const body = await c.req.json().catch(() => null);
		if (!body || !body.url) {
			return c.json({ error: 'URL or Domain is required' }, 400);
		}

		const rawUrl = body.url.trim();
		if (!rawUrl) {
			return c.json({ error: 'URL is required' }, 400);
		}

		// 2. Strict SSRF Protection Check on Input
		if (isPrivateOrBlockedIp(rawUrl)) {
			return c.json({
				error: 'SSRF Protection Triggered: Access to private IP networks, loopback addresses, and cloud metadata endpoints is strictly blocked.',
				code: 'SSRF_BLOCKED'
			}, 400);
		}

		// Normalize input
		const parsed = normalizeUrl(rawUrl);
		const domain = parsed.domain;
		const hostname = parsed.hostname;

		// 3. SSRF Protection Check on Hostname
		if (isPrivateOrBlockedIp(hostname) || isPrivateOrBlockedIp(domain)) {
			return c.json({
				error: 'SSRF Protection Triggered: Target resolves to an internal/private infrastructure address.',
				code: 'SSRF_BLOCKED'
			}, 400);
		}

		// Address lookup first
		const addrResult = await addressLookup(hostname);
		const primaryIp = addrResult.ipv4?.[0] || null;

		// 4. SSRF Defense on Resolved IP
		if (primaryIp && isPrivateOrBlockedIp(primaryIp)) {
			return c.json({
				error: 'SSRF Protection Triggered: Domain resolves to private or metadata network address.',
				code: 'SSRF_RESOLVED_INTERNAL'
			}, 400);
		}

		// Run independent modules concurrently
		const [whoisDomainResult, dnsResult, sslResult, subdomainResult, historicalResult, techResult] = await Promise.all([
			whoisDomain(domain),
			dnsRecords(domain),
			sslAnalysis(domain),
			subdomains(domain),
			historicalLookup(domain, c.env.VIEWDNS_KEY),
			techStackAndSecurityHeaders(domain),
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

		// Visual screenshot URL
		const screenshotUrl = `https://image.thum.io/get/width/600/crop/800/https://${domain}`;

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
			tech_stack: techResult,
			threat_intel: threatResult,
			historical: historicalResult,
			visual_recon: {
				screenshot_url: screenshotUrl,
			}
		};

		// AI explanation
		fullResult.ai_explanation = await generateExplanation(fullResult, c.env.GEMINI_API_KEY);

		return c.json(fullResult);
	} catch (err: any) {
		return c.json({ error: err.message }, 500);
	}
});

export default app;
