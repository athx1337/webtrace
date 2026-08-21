import { describe, it, expect } from 'vitest';
import { isPrivateOrBlockedIp, normalizeUrl, getPtrName } from '../src/index';

describe('SSRF Protection Engine', () => {
	it('should block RFC 1918 private IPv4 ranges (10.x, 172.16.x, 192.168.x)', () => {
		expect(isPrivateOrBlockedIp('10.0.0.1')).toBe(true);
		expect(isPrivateOrBlockedIp('10.255.255.254')).toBe(true);
		expect(isPrivateOrBlockedIp('172.16.0.5')).toBe(true);
		expect(isPrivateOrBlockedIp('172.31.255.255')).toBe(true);
		expect(isPrivateOrBlockedIp('192.168.1.1')).toBe(true);
		expect(isPrivateOrBlockedIp('192.168.0.254')).toBe(true);
	});

	it('should block loopback, localhost, and local IPv6 addresses', () => {
		expect(isPrivateOrBlockedIp('127.0.0.1')).toBe(true);
		expect(isPrivateOrBlockedIp('127.0.1.1')).toBe(true);
		expect(isPrivateOrBlockedIp('localhost')).toBe(true);
		expect(isPrivateOrBlockedIp('localhost.localdomain')).toBe(true);
		expect(isPrivateOrBlockedIp('::1')).toBe(true);
		expect(isPrivateOrBlockedIp('fe80::1')).toBe(true);
	});

	it('should block AWS / GCP cloud metadata service IP endpoints', () => {
		expect(isPrivateOrBlockedIp('169.254.169.254')).toBe(true);
		expect(isPrivateOrBlockedIp('http://169.254.169.254/latest/meta-data/')).toBe(true);
		expect(isPrivateOrBlockedIp('metadata.google.internal')).toBe(true);
	});

	it('should allow legitimate public domains and public IP addresses', () => {
		expect(isPrivateOrBlockedIp('google.com')).toBe(false);
		expect(isPrivateOrBlockedIp('cloudflare.com')).toBe(false);
		expect(isPrivateOrBlockedIp('8.8.8.8')).toBe(false);
		expect(isPrivateOrBlockedIp('1.1.1.1')).toBe(false);
		expect(isPrivateOrBlockedIp('93.184.215.14')).toBe(false);
	});
});

describe('URL Normalization & Domain Extraction', () => {
	it('should correctly parse standard domain names', () => {
		const res = normalizeUrl('https://example.com/path?arg=1');
		expect(res.domain).toBe('example.com');
		expect(res.hostname).toBe('example.com');
		expect(res.uses_https).toBe(true);
	});

	it('should correctly parse multi-level TLDs (co.uk, org.in, ac.in)', () => {
		const resUk = normalizeUrl('https://sub.company.co.uk');
		expect(resUk.domain).toBe('company.co.uk');
		expect(resUk.tld).toBe('.co.uk');
		expect(resUk.subdomains).toEqual(['sub']);

		const resIn = normalizeUrl('http://portal.gov.in');
		expect(resIn.domain).toBe('portal.gov.in');
		expect(resIn.tld).toBe('.gov.in');

		const resJain = normalizeUrl('https://jainuniversity.ac.in');
		expect(resJain.domain).toBe('jainuniversity.ac.in');
		expect(resJain.tld).toBe('.ac.in');
		expect(resJain.subdomains).toEqual([]);

		const resOx = normalizeUrl('https://cs.ox.ac.uk');
		expect(resOx.domain).toBe('ox.ac.uk');
		expect(resOx.tld).toBe('.ac.uk');
		expect(resOx.subdomains).toEqual(['cs']);
	});

	it('should detect suspicious typosquatting signals', () => {
		const res = normalizeUrl('https://google-secure-login.com');
		expect(res.typosquat_target).toBe('google');
	});
});

describe('Reverse DNS (PTR) Formatting', () => {
	it('should correctly reverse IPv4 octets into in-addr.arpa format', () => {
		expect(getPtrName('1.1.1.1')).toBe('1.1.1.1.in-addr.arpa');
		expect(getPtrName('8.8.4.4')).toBe('4.4.8.8.in-addr.arpa');
		expect(getPtrName('43.255.154.115')).toBe('115.154.255.43.in-addr.arpa');
	});
});
