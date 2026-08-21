/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Activity,
  Search,
  ShieldAlert,
  Network,
  Brain,
  Loader2,
  Globe,
  Database,
  History,
  AlertTriangle,
  Server,
  X,
  Copy,
  Check,
  Download,
  Terminal,
  Layers,
  FileCode,
  ShieldCheck,
  ShieldX,
  ExternalLink,
  Camera,
  RefreshCw,
  Sparkles,
  GitCompare
} from 'lucide-react';

// ---------- Interfaces ----------
interface AnalyzeResponse {
  domain: string;

  address_lookup: {
    available: boolean;
    canonical?: string;
    ipv4?: string[];
    ipv6?: string[];
    cdn_detected?: string | null;
    real_ip_hidden?: boolean;
    ptr?: Record<string, string | null>;
    error?: string;
  };

  whois_domain: {
    available: boolean;
    source?: string;
    registrar?: string;
    registrant_org?: string;
    created?: string;
    expires?: string;
    updated?: string;
    age_days?: number | null;
    nameservers?: string[];
    dnssec?: string;
    error?: string;
  };

  whois_network: {
    available: boolean;
    ip?: string;
    network?: string;
    range?: string;
    net_name?: string;
    net_type?: string;
    org?: string;
    country?: string;
    asn?: string | null;
    abuse_email?: string | null;
    error?: string;
  };

  dns_records: {
    available: boolean;
    records?: Record<string, string[]>;
    spf?: string | null;
    dmarc?: string | null;
    dkim_found?: boolean;
    has_spf?: boolean;
    has_dmarc?: boolean;
    flags?: string[];
    error?: string;
  };

  ssl: {
    available: boolean;
    valid?: boolean;
    common_name?: string;
    issuer_org?: string;
    issuer_cn?: string;
    is_free_ca?: boolean;
    issued?: string;
    expires?: string;
    cert_age_days?: number;
    days_remaining?: number;
    is_expired?: boolean;
    is_new_cert?: boolean;
    sans?: string[];
    san_count?: number;
    domain_match?: boolean;
    flags?: string[];
    error?: string;
  };

  infrastructure: {
    available: boolean;
    ip?: string;
    ports?: number[];
    cpes?: string[];
    vulns?: string[];
    hostnames?: string[];
    tags?: string[];
    flags?: string[];
    error?: string;
  };

  subdomains: {
    available: boolean;
    total?: number;
    active_probed?: number;
    subdomains?: Array<{
      subdomain: string;
      issuer: string;
      not_before: string;
      not_after: string;
      source?: string;
      ip?: string;
    }>;
    notable?: string[];
    flags?: string[];
    error?: string;
  };

  tech_stack?: {
    available: boolean;
    status_code?: number;
    server?: string | null;
    powered_by?: string | null;
    security_headers?: {
      hsts?: { present: boolean; value: string | null };
      csp?: { present: boolean; value: string | null };
      x_frame_options?: { present: boolean; value: string | null };
      x_content_type_options?: { present: boolean; value: string | null };
      permissions_policy?: { present: boolean; value: string | null };
      referrer_policy?: { present: boolean; value: string | null };
    };
    tech_stack?: string[];
    error?: string;
  };

  threat_intel: {
    available: boolean;
    verdict?: string;
    flagged_by?: number;
    engines?: {
      otx?: { available: boolean; pulse_count: number; malware_families: string[]; tags: string[]; flagged: boolean };
      abuseipdb?: { available: boolean; abuse_score: number; total_reports: number; last_reported: string; is_tor: boolean; usage_type: string; isp: string; flagged: boolean };
      threatfox?: { available: boolean; flagged: boolean; ioc_count?: number; threat_types?: string[]; malware?: string[] };
      greynoise?: { available: boolean; noise: boolean; riot: boolean; classification: string; name: string; flagged: boolean };
      urlhaus?: { available: boolean; flagged: boolean; url_count: number; tags: string[] };
    };
    error?: string;
  };

  historical: {
    available: boolean;
    wayback?: {
      available: boolean;
      first_snapshot?: string | null;
      closest_url?: string | null;
      snapshot_count?: number | null;
      flag?: string | null;
    };
    passive_dns?: Array<{
      ip: string;
      first_seen: string;
      last_seen: string;
      hostname: string;
      record_type: string;
    }>;
    ip_history?: {
      available: boolean;
      history?: Array<{
        ip: string;
        location: string;
        owner: string;
        last_seen: string;
      }>;
      error?: string;
    };
    error?: string;
  };

  visual_recon?: {
    screenshot_url?: string;
  };

  ai_explanation?: {
    available: boolean;
    summary?: string;
    engine?: string;
    error?: string;
  };
}

// ---------- Helper: Risk Score Calculation ----------
function computeRiskScore(data: AnalyzeResponse) {
  let score = 100;
  const penalties: Array<{ reason: string; deduction: number }> = [];

  // Threat Intel
  if (data.threat_intel?.verdict === 'MALICIOUS') {
    score -= 40;
    penalties.push({ reason: 'Flagged malicious by threat feeds', deduction: 40 });
  } else if (data.threat_intel?.verdict === 'SUSPICIOUS') {
    score -= 20;
    penalties.push({ reason: 'Suspicious reputation signals', deduction: 20 });
  }

  // CVEs & Vulnerabilities
  const cveCount = data.infrastructure?.vulns?.length || 0;
  if (cveCount > 0) {
    const deduction = Math.min(cveCount * 4, 30);
    score -= deduction;
    penalties.push({ reason: `${cveCount} known CVE(s) exposed`, deduction });
  }

  // Exposed Database or Sensitive Ports
  const sensitivePorts = [21, 23, 25, 110, 143, 3306, 5432, 27017, 6379];
  const openSensitive = (data.infrastructure?.ports || []).filter(p => sensitivePorts.includes(p));
  if (openSensitive.length > 0) {
    const deduction = Math.min(openSensitive.length * 5, 20);
    score -= deduction;
    penalties.push({ reason: `Exposed ports (${openSensitive.join(', ')})`, deduction });
  }

  // SSL Issues
  if (data.ssl?.available && !data.ssl.valid) {
    score -= 20;
    penalties.push({ reason: 'Invalid or missing SSL certificate', deduction: 20 });
  } else if (data.ssl?.days_remaining && data.ssl.days_remaining < 14) {
    score -= 10;
    penalties.push({ reason: 'SSL certificate expiring soon', deduction: 10 });
  }

  // Email Security
  if (data.dns_records?.available) {
    if (!data.dns_records.has_spf) {
      score -= 5;
      penalties.push({ reason: 'Missing SPF record', deduction: 5 });
    }
    if (!data.dns_records.has_dmarc) {
      score -= 5;
      penalties.push({ reason: 'Missing DMARC policy', deduction: 5 });
    }
  }

  // Security Headers
  if (data.tech_stack?.available && data.tech_stack.security_headers) {
    if (!data.tech_stack.security_headers.hsts?.present) {
      score -= 5;
      penalties.push({ reason: 'HSTS header missing', deduction: 5 });
    }
    if (!data.tech_stack.security_headers.csp?.present) {
      score -= 5;
      penalties.push({ reason: 'Content-Security-Policy missing', deduction: 5 });
    }
  }

  score = Math.max(0, Math.min(100, score));

  let label = 'HARDENED / SECURE';
  let color = 'text-primary-container';
  let border = 'border-primary-container';
  let bg = 'bg-primary-container/10';

  if (score < 50) {
    label = 'CRITICAL RISK / VULNERABLE';
    color = 'text-error';
    border = 'border-error';
    bg = 'bg-error/10';
  } else if (score < 80) {
    label = 'MODERATE EXPOSURE';
    color = 'text-yellow-400';
    border = 'border-yellow-400';
    bg = 'bg-yellow-400/10';
  }

  return { score, label, color, border, bg, penalties };
}

// ---------- Copy Button Helper ----------
const CopyBtn = ({ text, title }: { text?: string | null; title?: string }) => {
  const [copied, setCopied] = useState(false);
  if (!text) return null;

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      title={title || `Copy "${text}"`}
      className="p-1 hover:text-primary-container text-on-surface/40 transition-colors inline-flex items-center cursor-pointer"
    >
      {copied ? <Check className="w-3 h-3 text-primary-container" /> : <Copy className="w-3 h-3" />}
    </button>
  );
};

// ---------- Static Navigation ----------
const TopNav = ({ onOpenTopology, hasData }: { onOpenTopology?: () => void; hasData?: boolean }) => (
  <nav className="flex justify-between items-center w-full px-6 py-3 bg-surface-container-lowest border-b border-primary-container/20 shadow-[0_4px_16px_rgba(0,255,156,0.06)] z-50 shrink-0 relative">
    <div className="flex items-center gap-3">
      <img
        src="/navbar-logo.png"
        alt="WEBTRACE"
        className="h-8 md:h-9 w-auto object-contain"
        style={{ filter: 'drop-shadow(0 0 10px rgba(0, 255, 156, 0.45))' }}
      />
    </div>
    <div className="flex items-center gap-4">
      {hasData && onOpenTopology && (
        <button
          onClick={onOpenTopology}
          className="flex items-center gap-2 font-label text-[10px] uppercase tracking-widest text-primary-container border border-primary-container/30 px-3 py-1.5 hover:bg-primary-container/10 transition-all cursor-pointer"
        >
          <Network className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Attack Surface Map</span>
        </button>
      )}
      <div className="font-label text-[9px] uppercase tracking-widest text-primary-container/80 flex items-center gap-2 border border-primary-container/20 px-2.5 py-1 bg-surface-container">
        <span className="w-1.5 h-1.5 rounded-full bg-primary-container animate-pulse"></span>
        v2.5 PENTEST_GRADE
      </div>
    </div>
  </nav>
);

const Footer = ({
  serverStatus,
  onPrivacyClick,
  onTermsClick
}: {
  serverStatus: 'checking' | 'waking' | 'awake' | 'offline';
  onPrivacyClick: () => void;
  onTermsClick: () => void;
}) => {
  const statusConfig = {
    awake: { text: 'EDGE: ONLINE', dotColor: 'bg-primary-container', textColor: 'text-primary-container', pulse: true },
    waking: { text: 'EDGE: INITIALIZING', dotColor: 'bg-yellow-400', textColor: 'text-yellow-400', pulse: true },
    checking: { text: 'EDGE: CONNECTING...', dotColor: 'bg-on-surface/50', textColor: 'text-on-surface/50', pulse: true },
    offline: { text: 'EDGE: OFFLINE', dotColor: 'bg-error', textColor: 'text-error', pulse: false }
  };
  const config = statusConfig[serverStatus] || statusConfig.checking;

  return (
    <footer className="bg-surface-container-lowest border-t border-outline-variant/20 px-6 py-2 flex justify-between items-center font-label text-[9px] uppercase tracking-widest text-on-surface/40 shrink-0 z-50 relative">
      <div className="flex gap-4 items-center">
        <span className={`${config.textColor} flex items-center gap-1 font-bold tracking-widest transition-colors duration-500`}>
          <span className={`w-1.5 h-1.5 rounded-full ${config.dotColor} ${config.pulse ? 'animate-pulse' : ''}`}></span>
          {config.text}
        </span>
        <span className="hidden sm:inline">defense: SSRF_FIREWALL_ACTIVE</span>
        <span className={serverStatus === 'awake' ? 'text-primary-container/70' : 'text-on-surface/30'}>
          latency: {serverStatus === 'awake' ? '12ms' : '--- '}
        </span>
      </div>
      <div className="flex gap-3 items-center">
        <button onClick={onPrivacyClick} className="hover:text-primary-container transition-colors cursor-pointer">
          PRIVACY
        </button>
        <button onClick={onTermsClick} className="hover:text-primary-container transition-colors cursor-pointer">
          TERMS
        </button>
        <span className="hidden sm:inline ml-2">© 2026 WEBTRACE // OSINT_PENTEST_SUITE</span>
      </div>
    </footer>
  );
};

const SectionHeader = ({ title, icon: Icon, error = false, badge }: { title: string; icon: any; error?: boolean; badge?: string }) => (
  <div className={`flex items-center justify-between mb-4 font-label ${error ? 'text-error/80' : 'text-primary-container'}`}>
    <div className="flex items-center gap-2">
      <Icon className="w-4 h-4" />
      <h3 className="text-xs md:text-sm font-bold tracking-widest uppercase">{title}</h3>
    </div>
    {badge && (
      <span className="text-[9px] px-2 py-0.5 border border-primary-container/30 bg-primary-container/10 font-mono tracking-wider">
        {badge}
      </span>
    )}
  </div>
);

// ---------- Topology Modal ----------
const TopologyModal = ({ data, onClose }: { data: AnalyzeResponse; onClose: () => void }) => {
  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/85 backdrop-blur-md p-4" onClick={onClose}>
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-surface border border-primary-container/40 p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto relative shadow-[0_0_50px_rgba(0,255,156,0.2)] font-mono"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center border-b border-primary-container/30 pb-3 mb-6">
          <div className="flex items-center gap-2 text-primary-container font-label text-sm uppercase tracking-widest font-bold">
            <Network className="w-5 h-5" /> Attack Surface Topology Map: {data.domain}
          </div>
          <button onClick={onClose} className="text-on-surface/60 hover:text-primary-container">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-6 text-xs uppercase">
          {/* Target Root */}
          <div className="border border-primary-container bg-primary-container/10 p-4 flex items-center justify-between">
            <div>
              <span className="text-primary-container font-bold text-base tracking-wider">{data.domain}</span>
              <div className="text-[10px] text-on-surface/60 mt-1">Registrar: {data.whois_domain?.registrar || 'UNKNOWN'} • Age: {data.whois_domain?.age_days || 0}d</div>
            </div>
            <div className="text-right">
              <span className="px-2 py-1 bg-surface border border-primary-container/30 text-primary-container text-[10px]">ROOT TARGET</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* IP Nodes */}
            <div className="border border-outline-variant p-4 bg-surface-container space-y-2">
              <div className="text-primary-container font-bold text-[11px] flex items-center gap-1.5 border-b border-outline/20 pb-1">
                <Globe className="w-3.5 h-3.5" /> IP & Network Nodes
              </div>
              <div className="space-y-1 text-[11px]">
                {data.address_lookup?.ipv4?.map((ip, i) => (
                  <div key={i} className="text-primary-container flex justify-between">
                    <span>{ip}</span>
                    <CopyBtn text={ip} />
                  </div>
                )) || <div className="text-on-surface/40">No IP</div>}
                {data.whois_network?.network && (
                  <div className="text-[10px] text-on-surface/60 pt-2 border-t border-outline/10">
                    CIDR: {data.whois_network.network} ({data.whois_network.org})
                  </div>
                )}
              </div>
            </div>

            {/* Exposed Ports & CVEs */}
            <div className="border border-outline-variant p-4 bg-surface-container space-y-2">
              <div className="text-primary-container font-bold text-[11px] flex items-center gap-1.5 border-b border-outline/20 pb-1">
                <Server className="w-3.5 h-3.5" /> Exposed Surface
              </div>
              <div className="text-[11px] space-y-1">
                <div className="text-on-surface/70">
                  Open Ports: <span className="text-primary-container">{data.infrastructure?.ports?.join(', ') || 'None'}</span>
                </div>
                <div className="text-on-surface/70">
                  CVEs: <span className="text-error">{data.infrastructure?.vulns?.length || 0} Detected</span>
                </div>
                {data.address_lookup?.cdn_detected && (
                  <div className="text-yellow-400 text-[10px]">
                    CDN: {data.address_lookup.cdn_detected}
                  </div>
                )}
              </div>
            </div>

            {/* Threat & Subdomains */}
            <div className="border border-outline-variant p-4 bg-surface-container space-y-2">
              <div className="text-primary-container font-bold text-[11px] flex items-center gap-1.5 border-b border-outline/20 pb-1">
                <ShieldAlert className="w-3.5 h-3.5" /> Threat & Subdomains
              </div>
              <div className="text-[11px] space-y-1">
                <div>Verdict: <span className="font-bold text-primary-container">{data.threat_intel?.verdict || 'CLEAN'}</span></div>
                <div>Subdomains: <span className="text-on-surface">{data.subdomains?.total || 0} Total</span></div>
                <div>Active Probed: <span className="text-primary-container">{data.subdomains?.active_probed || 0}</span></div>
                <div>High-Risk Endpoints: <span className="text-error">{data.subdomains?.notable?.length || 0}</span></div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

// ---------- Raw JSON Modal ----------
const RawJsonModal = ({ data, onClose }: { data: AnalyzeResponse; onClose: () => void }) => {
  const jsonString = JSON.stringify(data, null, 2);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/85 backdrop-blur-md p-4" onClick={onClose}>
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-surface-container-lowest border border-primary-container/40 p-6 max-w-4xl w-full max-h-[90vh] flex flex-col relative shadow-[0_0_50px_rgba(0,0,0,0.8)] font-mono"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center border-b border-primary-container/20 pb-3 mb-4 shrink-0">
          <div className="flex items-center gap-2 text-primary-container font-label text-sm uppercase tracking-widest font-bold">
            <FileCode className="w-5 h-5" /> Raw Telemetry Ledger: {data.domain}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-xs border border-primary-container/40 text-primary-container px-3 py-1 hover:bg-primary-container/10 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'COPIED' : 'COPY JSON'}
            </button>
            <button onClick={onClose} className="text-on-surface/60 hover:text-primary-container cursor-pointer">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>
        <pre className="flex-1 overflow-auto bg-black p-4 text-[11px] text-primary-container/90 border border-outline-variant/30 selection:bg-primary-container selection:text-black">
          {jsonString}
        </pre>
      </motion.div>
    </div>
  );
};

// ---------- Animation Variants ----------
const staggerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } }
};

const fadeUpBlock = {
  hidden: { opacity: 0, y: 15 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.35, ease: "easeOut" } }
};

// ---------- Main App Component ----------
export default function App() {
  const [targetUrl, setTargetUrl] = useState("google.com");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [legalModal, setLegalModal] = useState<'privacy' | 'terms' | null>(null);
  const [showTopology, setShowTopology] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);
  const [subdomainSearch, setSubdomainSearch] = useState("");
  const [subdomainFilter, setSubdomainFilter] = useState<'all' | 'notable'>('all');
  const [scanHistory, setScanHistory] = useState<string[]>([]);
  const [scanDiffAlert, setScanDiffAlert] = useState<string[]>([]);

  // System Status State
  const [serverStatus, setServerStatus] = useState<'checking' | 'waking' | 'awake' | 'offline'>('checking');

  // Load scan history from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('webtrace_history');
      if (saved) setScanHistory(JSON.parse(saved));
    } catch {}
  }, []);

  const saveHistoryAndComputeDiff = (current: AnalyzeResponse) => {
    try {
      const domainKey = current.domain.toLowerCase();
      const prevDataStr = localStorage.getItem(`webtrace_scan_${domainKey}`);
      const diffs: string[] = [];

      if (prevDataStr) {
        const prev: AnalyzeResponse = JSON.parse(prevDataStr);
        // Compare IP
        const prevIp = prev.address_lookup?.ipv4?.[0];
        const currIp = current.address_lookup?.ipv4?.[0];
        if (prevIp && currIp && prevIp !== currIp) {
          diffs.push(`IP address changed from ${prevIp} ➔ ${currIp}`);
        }

        // Compare Subdomains
        const prevTotal = prev.subdomains?.total || 0;
        const currTotal = current.subdomains?.total || 0;
        if (currTotal > prevTotal) {
          diffs.push(`+ ${currTotal - prevTotal} new subdomain(s) discovered since previous scan`);
        }

        // Compare SSL
        const prevDays = prev.ssl?.days_remaining;
        const currDays = current.ssl?.days_remaining;
        if (prevDays != null && currDays != null && prevDays !== currDays) {
          diffs.push(`SSL lifespan changed: ${currDays} days remaining (was ${prevDays}d)`);
        }
      }

      setScanDiffAlert(diffs);

      // Save current snapshot
      localStorage.setItem(`webtrace_scan_${domainKey}`, JSON.stringify(current));

      const updatedHistory = [current.domain, ...scanHistory.filter(d => d.toLowerCase() !== domainKey)].slice(0, 6);
      setScanHistory(updatedHistory);
      localStorage.setItem('webtrace_history', JSON.stringify(updatedHistory));
    } catch {}
  };

  // Backend Health Ping
  useEffect(() => {
    const apiUrl = import.meta.env.VITE_API_URL || 'https://webtrace.phish-x.workers.dev';
    fetch(`${apiUrl}/api/ping`)
      .then(res => {
        if (res.ok) setServerStatus('awake');
        else setServerStatus('offline');
      })
      .catch(() => setServerStatus('offline'));
  }, []);

  const handleRunAnalysis = (overrideTarget?: string) => {
    const domainToScan = (overrideTarget || targetUrl).trim();
    if (!domainToScan) return;

    if (overrideTarget) setTargetUrl(overrideTarget);

    setStatus("loading");
    setErrorMsg("");
    setData(null);
    setScanDiffAlert([]);

    const apiUrl = import.meta.env.VITE_API_URL || 'https://webtrace.phish-x.workers.dev';

    fetch(`${apiUrl}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: domainToScan }),
    })
      .then(async (res) => {
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.error || `HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((json: AnalyzeResponse) => {
        setData(json);
        setStatus("success");
        saveHistoryAndComputeDiff(json);
      })
      .catch((err) => {
        setStatus("error");
        setErrorMsg(err.message || "Failed to execute scan. Check network connectivity.");
      });
  };

  // Download Markdown Report
  const handleExportMarkdown = () => {
    if (!data) return;
    const risk = computeRiskScore(data);
    const mdContent = `# ⚡ WEBTRACE SECURITY ASSESSMENT & PENTEST AUDIT: ${data.domain}
Generated: ${new Date().toUTCString()}
Attack Surface Security Score: ${risk.score}/100 [${risk.label}]

================================================================================
1. 🧠 EXECUTIVE AI ASSESSMENT
================================================================================
${data.ai_explanation?.summary || 'N/A'}

================================================================================
2. 🌐 NETWORK & INFRASTRUCTURE TOPOLOGY
================================================================================
- Target Domain: ${data.domain}
- Canonical CNAME: ${data.address_lookup?.canonical || data.domain}
- Resolved IPv4 Nodes: ${data.address_lookup?.ipv4?.join(', ') || 'None'}
- Network Owner / ISP: ${data.whois_network?.org || 'N/A'} (${data.whois_network?.country || 'N/A'})
- ASN Block: ${data.whois_network?.asn || 'N/A'}
- CIDR Routing: ${data.whois_network?.network || 'N/A'}
- CDN / Edge Shielding: ${data.address_lookup?.cdn_detected || 'None (Direct Origin Exposed)'}

================================================================================
3. 💻 TECHNOLOGY STACK & DEFENSE HEADERS
================================================================================
- Server Signature: ${data.tech_stack?.server || 'Hidden / None'}
- Technologies Identified: ${data.tech_stack?.tech_stack?.join(', ') || 'None identified'}
- HSTS (Strict-Transport-Security): ${data.tech_stack?.security_headers?.hsts?.present ? 'ENFORCED' : 'MISSING'}
- CSP (Content-Security-Policy): ${data.tech_stack?.security_headers?.csp?.present ? 'CONFIGURED' : 'MISSING'}
- X-Frame-Options: ${data.tech_stack?.security_headers?.x_frame_options?.present ? 'CONFIGURED' : 'MISSING'}

================================================================================
4. 📜 REGISTRY (WHOIS) & HYGIENE
================================================================================
- Registrar: ${data.whois_domain?.registrar || 'Unknown'}
- Domain Age: ${data.whois_domain?.age_days || 'Unknown'} days
- Registration Date: ${data.whois_domain?.created || 'N/A'}
- Expiration Date: ${data.whois_domain?.expires || 'N/A'}
- DNSSEC Status: ${data.whois_domain?.dnssec || 'UNSIGNED'}
- SPF Record: ${data.dns_records?.has_spf ? 'CONFIGURED' : 'MISSING'}
- DMARC Policy: ${data.dns_records?.has_dmarc ? 'CONFIGURED' : 'MISSING'}
- DKIM Found: ${data.dns_records?.dkim_found ? 'CONFIGURED' : 'MISSING'}

================================================================================
5. 🎯 ATTACK SURFACE EXPOSURE & CVES
================================================================================
- Open Ports Detected: ${data.infrastructure?.ports?.join(', ') || 'None detected'}
- Exposed CVEs: ${data.infrastructure?.vulns?.join(', ') || 'None detected'}
- Total Subdomains Tracked: ${data.subdomains?.total || 0} (Active DoH Probed: ${data.subdomains?.active_probed || 0})
- Sensitive Endpoints: ${data.subdomains?.notable?.join(', ') || 'None'}

================================================================================
6. 🚨 MULTI-ENGINE THREAT INTEL VERDICT
================================================================================
- Aggregate Threat Verdict: ${data.threat_intel?.verdict || 'CLEAN'}
- Engines Flagged: ${data.threat_intel?.flagged_by || 0}
`;

    const blob = new Blob([mdContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webtrace_pentest_report_${data.domain.replace(/[^a-zA-Z0-9]/g, '_')}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const riskAssessment = useMemo(() => {
    return data ? computeRiskScore(data) : null;
  }, [data]);

  const filteredSubdomains = useMemo(() => {
    if (!data?.subdomains?.subdomains) return [];
    let list = data.subdomains.subdomains;
    if (subdomainFilter === 'notable' && data.subdomains.notable) {
      list = list.filter(s => data.subdomains.notable?.includes(s.subdomain));
    }
    if (subdomainSearch.trim()) {
      const q = subdomainSearch.toLowerCase().trim();
      list = list.filter(s => s.subdomain.toLowerCase().includes(q) || s.issuer.toLowerCase().includes(q));
    }
    return list;
  }, [data, subdomainSearch, subdomainFilter]);

  const PRESET_TARGETS = ['google.com', 'github.com', 'cloudflare.com', 'ktiwari.in', 'wikipedia.org'];

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-background text-inverse-surface relative selection:bg-primary-container selection:text-background font-body cyber-grid">
      <TopNav onOpenTopology={() => setShowTopology(true)} hasData={!!data} />

      <div className="flex flex-1 overflow-hidden relative z-10 w-full max-w-7xl mx-auto">
        <motion.main
          className="flex-1 overflow-y-auto p-4 md:p-8 relative z-10"
          variants={staggerVariants}
          initial="hidden"
          animate="visible"
        >

          {/* Header & Search Bar */}
          <motion.div variants={fadeUpBlock} className="mb-6">
            <div className="flex items-end justify-between mb-4">
              <pre className="hidden md:block ascii-art text-primary-container opacity-80 text-[clamp(6px,0.8vw,10px)] select-none pointer-events-none font-bold leading-none">
                {String.raw`__/\\\______________/\\\__/\\\\\\\\\\\\\\\__/\\\\\\\\\\\\\____/\\\\\\\\\\\\\\\____/\\\\\\\\\_________/\\\\\\\\\___________/\\\\\\\\\__/\\\\\\\\\\\\\\\_        
 _\/\\\_____________\/\\\_\/\\\///////////__\/\\\/////////\\\_\///////\\\/////___/\\\///////\\\_____/\\\\\\\\\\\\\______/\\\////////__\/\\\///////////__       
  _\/\\\_____________\/\\\_\/\\\_____________\/\\\_______\/\\\_______\/\\\_______\/\\\_____\/\\\____/\\\/////////\\\___/\\\/___________\/\\\_____________      
   _\//\\\____/\\\____/\\\__\/\\\\\\\\\\\_____\/\\\\\\\\\\\\\\________\/\\\_______\/\\\\\\\\\\\/____\/\\\_______\/\\\__/\\\_____________\/\\\\\\\\\\\_____     
    __\//\\\__/\\\\\__/\\\___\/\\\///////______\/\\\/////////\\\_______\/\\\_______\/\\\//////\\\____\/\\\\\\\\\\\\\\\_\/\\\_____________\/\\\///////______    
     ___\//\\\/\\\/\\\/\\\____\/\\\_____________\/\\\_______\/\\\_______\/\\\_______\/\\\____\//\\\___\/\\\/////////\\\_\//\\\____________\/\\\_____________   
      ____\//\\\\\\//\\\\\_____\/\\\_____________\/\\\_______\/\\\_______\/\\\_______\/\\\_____\//\\\__\/\\\_______\/\\\__\///\\\__________\/\\\_____________  
       _____\//\\\__\//\\\______\/\\\\\\\\\\\\\\\_\/\\\\\\\\\\\\\/________\/\\\_______\/\\\______\//\\\_\/\\\_______\/\\\____\////\\\\\\\\\_\/\\\\\\\\\\\\\\\_ 
        ______\///____\///_______\///////////////__\/////////////__________\///________\///________\///__\///________\///________\/////////__\///////////////__`}
              </pre>
              <div className="text-right font-label text-[10px] uppercase tracking-[0.2em] text-on-surface/50 border-r-2 border-primary-container/40 pr-4">
                <div><span className="text-primary-container">op_mode:</span> PENTEST_RECON</div>
                <div><span className="text-primary-container">recon_engine:</span> ACTIVE_DOH_10</div>
                <div><span className="text-primary-container">defense:</span> SSRF_FIREWALL</div>
              </div>
            </div>

            {/* Input Form */}
            <div className="bg-surface-container flex flex-col md:flex-row items-center overflow-hidden border border-outline/50 shadow-[0_0_30px_rgba(0,0,0,0.7)] focus-within:border-primary-container focus-within:shadow-[0_0_25px_rgba(0,255,156,0.2)] transition-all">
              <div className="flex-1 flex items-center px-6 py-4 font-label text-primary-container text-lg w-full bg-surface-container-lowest">
                <span className="opacity-50 mr-3 animate-pulse">&gt;</span>
                <span className="text-primary-container/70 mr-3 uppercase font-bold text-sm">analyze_domain</span>
                <input
                  className="bg-transparent border-none focus:ring-0 text-on-surface w-full placeholder:text-on-surface/20 uppercase tracking-wider outline-none font-medium text-sm md:text-base"
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleRunAnalysis()}
                  placeholder="ENTER DOMAIN OR IP (E.G. KTIWARI.IN)"
                  spellCheck="false"
                />
              </div>
              <button
                onClick={() => handleRunAnalysis()}
                disabled={status === "loading"}
                className="bg-primary-container text-on-primary-fixed font-label font-black tracking-widest text-xs px-10 h-full py-4 md:py-0 hover:bg-primary-fixed active:translate-y-0 transition-transform w-full md:w-auto overflow-hidden relative group cursor-pointer"
              >
                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out"></div>
                <span className="relative z-10 flex items-center gap-2 justify-center">
                  {status === "loading" ? <><Loader2 className="w-4 h-4 animate-spin" /> RUNNING...</> : "EXECUTE"}
                </span>
              </button>
            </div>

            {/* Target Presets & Quick Chips */}
            <div className="flex items-center gap-2 mt-3 flex-wrap text-[10px] font-mono">
              <span className="text-on-surface/40 uppercase tracking-wider">PRESETS:</span>
              {PRESET_TARGETS.map(t => (
                <button
                  key={t}
                  onClick={() => handleRunAnalysis(t)}
                  className="px-2 py-0.5 bg-surface-container hover:bg-primary-container/10 border border-outline-variant/30 text-on-surface/70 hover:text-primary-container transition-colors cursor-pointer"
                >
                  {t}
                </button>
              ))}
              {scanHistory.length > 0 && (
                <>
                  <span className="text-on-surface/30 ml-2">| RECENT:</span>
                  {scanHistory.slice(0, 3).map(h => (
                    <button
                      key={h}
                      onClick={() => handleRunAnalysis(h)}
                      className="px-2 py-0.5 bg-surface-container-high hover:border-primary-container/40 border border-transparent text-primary-container/80 transition-colors cursor-pointer"
                    >
                      {h}
                    </button>
                  ))}
                </>
              )}
            </div>

            <AnimatePresence>
              {status === 'error' && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="mt-4 font-label text-xs text-error tracking-widest bg-error/10 border border-error/20 px-4 py-3 flex items-center gap-3">
                  <AlertTriangle className="w-4 h-4 shrink-0" /> {errorMsg}
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          {/* Loading Animation HUD */}
          <AnimatePresence>
            {status === 'loading' && (
              <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="flex flex-col items-center justify-center py-24 text-primary-container">
                <div className="relative w-28 h-28">
                  <div className="w-28 h-28 border-2 border-primary-container/20 rounded-full animate-spin absolute inset-0"></div>
                  <div className="w-28 h-28 border-t-2 border-l-2 border-primary-container rounded-full absolute inset-0" style={{ animation: 'spin 0.9s linear infinite reverse' }}></div>
                  <div className="w-16 h-16 border border-primary-container/40 rounded-full absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-ping opacity-25"></div>
                  <Activity className="w-8 h-8 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-90" />
                </div>
                <div className="mt-8 font-label text-sm uppercase tracking-[0.3em] animate-pulse">Running Active DoH Probing & OSINT Feeds...</div>
                <div className="mt-2 font-mono text-[10px] text-on-surface/40">Querying DNS, RDAP, Tech Stack, Shodan, crt.sh, OTX & Gemini Edge</div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Results Display */}
          {status === 'success' && data && (
            <motion.div variants={staggerVariants} initial="hidden" animate="visible" className="flex flex-col gap-6">

              {/* Scan Delta / Historical Comparison Banner */}
              {scanDiffAlert.length > 0 && (
                <motion.div variants={fadeUpBlock} className="bg-primary-container/10 border border-primary-container/40 p-3.5 font-label text-xs">
                  <div className="flex items-center gap-2 text-primary-container font-bold uppercase tracking-wider mb-1">
                    <GitCompare className="w-4 h-4" /> Historical Delta Alert (Changes Since Previous Scan)
                  </div>
                  <div className="space-y-1 text-on-surface/90 font-mono text-[11px] pl-6">
                    {scanDiffAlert.map((diff, i) => (
                      <div key={i}>• {diff}</div>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* Action Bar & Quick Tools */}
              <motion.div variants={fadeUpBlock} className="flex flex-wrap items-center justify-between gap-3 bg-surface-container border border-outline-variant/30 px-4 py-2.5 font-label text-xs">
                <div className="flex items-center gap-2 text-primary-container">
                  <Terminal className="w-4 h-4" />
                  <span className="font-bold uppercase tracking-wider">{data.domain}</span>
                  <span className="text-[10px] text-on-surface/50">• PENTEST RECON COMPLETE</span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    onClick={() => setShowTopology(true)}
                    className="flex items-center gap-1.5 px-3 py-1 bg-surface-container-high hover:bg-primary-container/10 border border-primary-container/30 text-primary-container text-[11px] transition-colors cursor-pointer"
                  >
                    <Layers className="w-3.5 h-3.5" /> Topology Map
                  </button>
                  <button
                    onClick={handleExportMarkdown}
                    className="flex items-center gap-1.5 px-3 py-1 bg-surface-container-high hover:bg-primary-container/10 border border-outline-variant/40 text-on-surface hover:text-primary-container text-[11px] transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" /> Export Pentest Report (.md)
                  </button>
                  <button
                    onClick={() => setShowRawJson(true)}
                    className="flex items-center gap-1.5 px-3 py-1 bg-surface-container-high hover:bg-primary-container/10 border border-outline-variant/40 text-on-surface hover:text-primary-container text-[11px] transition-colors cursor-pointer"
                  >
                    <FileCode className="w-3.5 h-3.5" /> Raw JSON
                  </button>
                </div>
              </motion.div>

              {/* Risk Assessment Score Card */}
              {riskAssessment && (
                <motion.div variants={fadeUpBlock} className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-surface-container-low border border-outline-variant/40 p-5">
                  <div className="flex items-center gap-4 md:border-r md:border-outline/20 pr-4">
                    <div className="relative w-16 h-16 shrink-0 flex items-center justify-center">
                      <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
                        <path
                          className="text-white/10"
                          strokeWidth="3.5"
                          stroke="currentColor"
                          fill="none"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                        <path
                          className={riskAssessment.color}
                          strokeDasharray={`${riskAssessment.score}, 100`}
                          strokeWidth="3.5"
                          strokeLinecap="round"
                          stroke="currentColor"
                          fill="none"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                      </svg>
                      <span className={`absolute font-label font-bold text-lg ${riskAssessment.color}`}>
                        {riskAssessment.score}
                      </span>
                    </div>
                    <div>
                      <div className="text-[9px] font-label uppercase text-on-surface/50 tracking-widest">Health Index</div>
                      <div className={`font-label font-bold text-xs ${riskAssessment.color} tracking-wider`}>
                        {riskAssessment.label}
                      </div>
                    </div>
                  </div>

                  <div className="col-span-3 flex flex-col justify-center">
                    <div className="text-[10px] font-label uppercase text-primary-container mb-1 tracking-wider">
                      Key Risk & Exposure Factors:
                    </div>
                    <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                      {riskAssessment.penalties.length === 0 ? (
                        <span className="text-primary-container bg-primary-container/10 px-2 py-0.5 border border-primary-container/20">
                          ✓ No severe exposure factors identified
                        </span>
                      ) : (
                        riskAssessment.penalties.map((p, i) => (
                          <span key={i} className="text-error bg-error/10 border border-error/20 px-2 py-0.5">
                            ⚠ {p.reason} (-{p.deduction} pts)
                          </span>
                        ))
                      )}
                    </div>
                  </div>
                </motion.div>
              )}

              {/* Structured AI Pentest Briefing */}
              {data.ai_explanation && (
                <motion.div variants={fadeUpBlock} className="bg-surface-container-low border border-primary-container/40 p-6 terminal-glow relative overflow-hidden group hover:border-primary-container transition-colors">
                  <div className="absolute -top-10 -right-10 opacity-[0.04] group-hover:opacity-10 transition-opacity duration-700 pointer-events-none">
                    <Brain className="w-64 h-64 text-primary-container" />
                  </div>
                  <SectionHeader title="Structured AI Pentest Briefing" icon={Brain} badge={data.ai_explanation.engine || 'AI Engine'} />
                  <div className="font-body text-xs md:text-sm text-on-surface leading-relaxed relative z-10 space-y-3 whitespace-pre-line border-l-2 border-primary-container/50 pl-4 py-1">
                    {data.ai_explanation.available
                      ? data.ai_explanation.summary
                      : <span className="text-error">{data.ai_explanation.error || "AI Intel Unavailable"}</span>}
                  </div>
                </motion.div>
              )}

              {/* Tech Stack & Security Headers */}
              {data.tech_stack?.available && (
                <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6">
                  <SectionHeader title="Tech Stack & Security Headers Audit" icon={Cpu} />
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
                    {/* Technologies Detected */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">
                        Identified Technologies & Servers
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {data.tech_stack.tech_stack && data.tech_stack.tech_stack.length > 0 ? (
                          data.tech_stack.tech_stack.map((t, i) => (
                            <span key={i} className="px-2 py-0.5 bg-primary-container/10 border border-primary-container/30 text-primary-container text-[11px]">
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-on-surface/40">No specific framework signatures matched</span>
                        )}
                      </div>
                    </div>

                    {/* Security Headers */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">
                        Security Headers Compliance
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px]">
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-on-surface/60">HSTS (HTTPS):</span>
                          <span className={data.tech_stack.security_headers?.hsts?.present ? "text-primary-container font-bold" : "text-error"}>
                            {data.tech_stack.security_headers?.hsts?.present ? "✓ ENFORCED" : "✗ MISSING"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-on-surface/60">CSP (XSS Def):</span>
                          <span className={data.tech_stack.security_headers?.csp?.present ? "text-primary-container font-bold" : "text-error"}>
                            {data.tech_stack.security_headers?.csp?.present ? "✓ CONFIGURED" : "✗ MISSING"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-on-surface/60">X-Frame-Options:</span>
                          <span className={data.tech_stack.security_headers?.x_frame_options?.present ? "text-primary-container font-bold" : "text-error"}>
                            {data.tech_stack.security_headers?.x_frame_options?.present ? "✓ CONFIGURED" : "✗ MISSING"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-on-surface/60">X-Content-Type:</span>
                          <span className={data.tech_stack.security_headers?.x_content_type_options?.present ? "text-primary-container font-bold" : "text-error"}>
                            {data.tech_stack.security_headers?.x_content_type_options?.present ? "✓ CONFIGURED" : "✗ MISSING"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

                {/* ── Column 1 ── */}
                <div className="flex flex-col gap-6">

                  {/* Network Identity */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6 flex flex-col gap-6">
                    <SectionHeader title="Network Identity & Routing" icon={Globe} />

                    {/* Address Lookup */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3 flex justify-between">
                        <span>Address Lookup</span>
                        <span className="text-on-surface/40">Cloudflare DoH</span>
                      </div>
                      {data.address_lookup?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">Canonical:</span>
                          <span className="text-right truncate flex items-center justify-end gap-1">
                            {data.address_lookup.canonical || 'N/A'}
                            <CopyBtn text={data.address_lookup.canonical} />
                          </span>
                          <span className="text-on-surface/50">IPv4 Nodes:</span>
                          <span className="text-right text-primary-container truncate flex items-center justify-end gap-1">
                            {data.address_lookup.ipv4?.join(', ') || 'N/A'}
                            <CopyBtn text={data.address_lookup.ipv4?.[0]} />
                          </span>
                          <span className="text-on-surface/50">IPv6 Nodes:</span>
                          <span className="text-right truncate opacity-70">{data.address_lookup.ipv6?.length ? data.address_lookup.ipv6[0] : 'N/A'}</span>
                          {data.address_lookup.cdn_detected && (
                            <>
                              <span className="text-on-surface/50">CDN Detected:</span>
                              <span className="text-right text-yellow-400 uppercase">{data.address_lookup.cdn_detected} (Proxied)</span>
                            </>
                          )}
                        </div>
                      ) : (
                        <div className="text-xs text-error font-mono">{data.address_lookup?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* Domain WHOIS */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3 flex justify-between">
                        <span>Domain Registry (WHOIS)</span>
                        <span className="text-on-surface/40">{data.whois_domain?.source || 'RDAP'}</span>
                      </div>
                      {data.whois_domain?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">Registrar:</span>
                          <span className="text-right text-primary-container/90 truncate">{data.whois_domain.registrar || 'UNKNOWN'}</span>
                          <span className="text-on-surface/50">Age:</span>
                          <span className="text-right">{data.whois_domain.age_days != null ? `${data.whois_domain.age_days} Days` : 'UNKNOWN'}</span>
                          <span className="text-on-surface/50">Created:</span>
                          <span className="text-right truncate opacity-80">{data.whois_domain.created ? data.whois_domain.created.split('T')[0] : 'N/A'}</span>
                          <span className="text-on-surface/50">Expires:</span>
                          <span className="text-right truncate opacity-80">{data.whois_domain.expires ? data.whois_domain.expires.split('T')[0] : 'N/A'}</span>
                          <span className="text-on-surface/50">DNSSEC:</span>
                          <span className={`text-right font-bold ${data.whois_domain.dnssec === 'SIGNED' ? 'text-primary-container' : 'text-yellow-400'}`}>
                            {data.whois_domain.dnssec || 'UNSIGNED'}
                          </span>
                        </div>
                      ) : (
                        <div className="text-xs text-error font-mono">{data.whois_domain?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* Network WHOIS */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3 flex justify-between">
                        <span>IP Block Authority & ASN</span>
                        <span className="text-on-surface/40">Universal RDAP</span>
                      </div>
                      {data.whois_network?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">ISP / Org:</span>
                          <span className="text-right text-primary-container truncate">{data.whois_network.org || data.whois_network.net_name || 'UNKNOWN'}</span>
                          <span className="text-on-surface/50">ASN:</span>
                          <span className="text-right">{data.whois_network.asn || 'N/A'}</span>
                          <span className="text-on-surface/50">CIDR:</span>
                          <span className="text-right truncate">{data.whois_network.network || 'N/A'}</span>
                          <span className="text-on-surface/50">Country:</span>
                          <span className="text-right">{data.whois_network.country || 'N/A'}</span>
                        </div>
                      ) : (
                        <div className="text-xs text-on-surface/40 font-mono italic">No network routing intel fetched.</div>
                      )}
                    </div>
                  </motion.div>

                  {/* Cryptographic Ledger (SSL & DNS) */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6 flex flex-col gap-6">
                    <SectionHeader title="Cryptographic & DNS Ledger" icon={Database} />

                    {/* SSL */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">X.509 Certificate Profile</div>
                      {data.ssl?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">Verdict:</span>
                          <span className={`text-right font-bold ${data.ssl.valid ? 'text-primary-container' : 'text-error'}`}>
                            {data.ssl.valid ? 'VALID CERTIFICATE' : 'INVALID / UNTRUSTED'}
                          </span>
                          <span className="text-on-surface/50">Issuer CA:</span>
                          <span className="text-right truncate flex items-center justify-end gap-1">
                            {data.ssl.is_free_ca && <span className="bg-surface-container-highest text-[8px] px-1 text-yellow-400">FREE CA</span>}
                            {data.ssl.issuer_org || 'UNKNOWN'}
                          </span>
                          <span className="text-on-surface/50">Lifespan:</span>
                          <span className={`text-right ${data.ssl.days_remaining && data.ssl.days_remaining < 30 ? 'text-error' : 'opacity-80'}`}>
                            {data.ssl.days_remaining != null ? `${data.ssl.days_remaining} Days Left` : 'N/A'}
                          </span>
                          <span className="text-on-surface/50">Cert Age:</span>
                          <span className="text-right opacity-80">{data.ssl.cert_age_days != null ? `${data.ssl.cert_age_days} Days Old` : 'N/A'}</span>
                          <span className="text-on-surface/50">SAN Count:</span>
                          <span className="text-right opacity-80">{data.ssl.san_count ?? data.ssl.sans?.length ?? 0} Domains</span>
                        </div>
                      ) : (
                        <div className="text-xs text-error font-mono">{data.ssl?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* DNS Records */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">Authoritative DNS</div>
                      {data.dns_records?.available ? (
                        <div className="space-y-2 text-xs font-mono uppercase">
                          <div className="grid grid-cols-3 gap-2 mb-3 bg-surface-container p-2 text-center text-[10px] border border-outline/20">
                            <div className={data.dns_records.has_spf ? "text-primary-container font-bold" : "text-error"}>
                              SPF {data.dns_records.has_spf ? '✓ OK' : '✗ MISSING'}
                            </div>
                            <div className={data.dns_records.has_dmarc ? "text-primary-container font-bold" : "text-error"}>
                              DMARC {data.dns_records.has_dmarc ? '✓ OK' : '✗ MISSING'}
                            </div>
                            <div className={data.dns_records.dkim_found ? "text-primary-container font-bold" : "text-error"}>
                              DKIM {data.dns_records.dkim_found ? '✓ OK' : '✗ MISSING'}
                            </div>
                          </div>
                          <div className="max-h-36 overflow-y-auto pr-1 space-y-1">
                            {Object.entries(data.dns_records.records || {}).map(([type, records]) => {
                              if (!records || (records as string[]).length === 0) return null;
                              return (records as string[]).map((r, i) => (
                                <div key={`${type}-${i}`} className="flex justify-between border-b border-white/5 py-1">
                                  <span className="text-primary-container/80 w-12 shrink-0 font-bold">{type}</span>
                                  <span className="text-right truncate text-on-surface/80 pl-2 text-[10px]">{r}</span>
                                </div>
                              ));
                            })}
                          </div>
                        </div>
                      ) : (
                        <div className="text-xs text-error font-mono">{data.dns_records?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>
                  </motion.div>
                </div>

                {/* ── Column 2 ── */}
                <div className="flex flex-col gap-6">

                  {/* Threat Intel */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6">
                    <SectionHeader
                      title="Global Threat Radar"
                      icon={ShieldAlert}
                      error={data.threat_intel?.verdict === 'MALICIOUS'}
                    />

                    {data.threat_intel?.available ? (
                      <div className="space-y-4">
                        {/* Aggregate verdict banner */}
                        <div className={`flex items-center justify-between p-3.5 border font-label tracking-widest uppercase text-sm
                          ${data.threat_intel.verdict === 'CLEAN'
                            ? 'bg-primary-container/10 border-primary-container/30 text-primary-container'
                            : data.threat_intel.verdict === 'MALICIOUS'
                              ? 'bg-error/10 border-error/50 text-error'
                              : 'bg-surface-container border-outline/30 text-on-surface'}`}>
                          <span>Aggregate Verdict</span>
                          <span className="font-bold">{data.threat_intel.verdict || 'UNKNOWN'}</span>
                        </div>

                        {/* Stats */}
                        <div className="grid grid-cols-2 gap-4 text-xs font-mono uppercase text-center">
                          <div className="bg-surface-container py-3 border border-outline/10">
                            <div className="text-[10px] text-on-surface/50 mb-1">Vendors Polled</div>
                            <div className="text-lg font-bold">{Object.keys(data.threat_intel.engines || {}).length}</div>
                          </div>
                          <div className="bg-surface-container py-3 border border-outline/10">
                            <div className="text-[10px] text-on-surface/50 mb-1">Engines Flagged</div>
                            <div className={`text-lg font-bold ${(data.threat_intel.flagged_by ?? 0) > 0 ? 'text-error' : 'text-primary-container'}`}>
                              {data.threat_intel.flagged_by ?? 0}
                            </div>
                          </div>
                        </div>

                        {/* Per-engine breakdown */}
                        {data.threat_intel.engines && (
                          <div className="space-y-1 mt-2">
                            {Object.entries(data.threat_intel.engines).map(([name, engine]: [string, any]) => (
                              <div key={name} className="flex items-center justify-between text-[10px] font-mono uppercase py-1 border-b border-outline/10">
                                <span className="text-on-surface/60">{name}</span>
                                <span className={`px-2 py-0.5 font-bold ${engine?.flagged ? 'bg-error/20 text-error' : 'bg-primary-container/10 text-primary-container'}`}>
                                  {engine?.flagged ? 'FLAGGED' : engine?.available === false ? 'UNAVAILABLE' : 'CLEAN'}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-xs text-error font-mono">{data.threat_intel?.error || "UNAVAILABLE"}</div>
                    )}
                  </motion.div>

                  {/* Infrastructure Surface */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6">
                    <SectionHeader title="Infrastructure Surface (Shodan DB)" icon={Server} />
                    {data.infrastructure?.available ? (
                      <div className="space-y-4 text-xs font-mono uppercase">
                        <div>
                          <span className="text-[10px] text-on-surface/50 block mb-2 font-bold">Open Ports ({data.infrastructure.ports?.length || 0})</span>
                          <div className="flex flex-wrap gap-1.5 text-primary-container">
                            {data.infrastructure.ports && data.infrastructure.ports.length > 0
                              ? data.infrastructure.ports.map(p => {
                                const isDanger = [21, 23, 25, 110, 143, 3306, 5432, 27017].includes(p);
                                return (
                                  <span
                                    key={p}
                                    className={`px-2 py-0.5 border text-[11px] ${isDanger ? 'bg-error/10 border-error/40 text-error' : 'bg-primary-container/10 border-primary-container/20 text-primary-container'}`}
                                  >
                                    {p}
                                  </span>
                                );
                              })
                              : <span className="text-on-surface/40">NO OPEN PORTS DETECTED</span>}
                          </div>
                        </div>

                        {data.infrastructure.vulns && data.infrastructure.vulns.length > 0 && (
                          <div>
                            <span className="text-[10px] text-error block mb-2 font-bold">
                              Exposed CVE Vulnerabilities ({data.infrastructure.vulns.length})
                            </span>
                            <div className="flex flex-wrap gap-1.5 text-error">
                              {data.infrastructure.vulns.slice(0, 10).map((cve: string) => (
                                <span key={cve} className="bg-error/10 border border-error/30 px-1.5 py-0.5 text-[10px] font-mono">
                                  {cve}
                                </span>
                              ))}
                              {data.infrastructure.vulns.length > 10 && (
                                <span className="text-error/70 pt-1 text-[10px]">+{data.infrastructure.vulns.length - 10} MORE</span>
                              )}
                            </div>
                          </div>
                        )}

                        <div className="grid grid-cols-2 gap-4 border-t border-outline/10 pt-4 text-[10px]">
                          <div>
                            <span className="text-on-surface/50 block mb-1">Tags</span>
                            <span className="text-on-surface/80">{data.infrastructure.tags?.length ? data.infrastructure.tags.join(', ') : 'NONE'}</span>
                          </div>
                          <div>
                            <span className="text-on-surface/50 block mb-1">CPE Fingerprints</span>
                            <span className="text-on-surface/80 opacity-60">
                              {data.infrastructure.cpes?.length ? `${data.infrastructure.cpes.length} Software Matches` : 'NONE'}
                            </span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs text-on-surface/40 font-mono italic">{data.infrastructure?.error || "No infrastructure profile found."}</div>
                    )}
                  </motion.div>

                  {/* Subdomains & Historical Footprint */}
                  <motion.div variants={fadeUpBlock} className="grid grid-cols-1 md:grid-cols-2 gap-6">

                    {/* Subdomain CT Logs with Search & Active Probing */}
                    <div className="bg-surface-container-lowest border border-outline-variant p-4 flex flex-col">
                      <SectionHeader
                        title="Subdomains (Active + CT)"
                        icon={Network}
                        badge={`${data.subdomains?.total ?? 0}`}
                      />
                      {data.subdomains?.available ? (
                        <div className="text-xs font-mono uppercase space-y-2.5">
                          {/* Search bar inside subdomains */}
                          <div className="flex items-center gap-1 bg-surface-container px-2 py-1 border border-outline/20">
                            <Search className="w-3 h-3 text-on-surface/40" />
                            <input
                              type="text"
                              value={subdomainSearch}
                              onChange={(e) => setSubdomainSearch(e.target.value)}
                              placeholder="FILTER..."
                              className="bg-transparent border-none outline-none text-[10px] w-full text-on-surface"
                            />
                            {subdomainSearch && (
                              <button onClick={() => setSubdomainSearch("")} className="text-on-surface/40 hover:text-primary-container">
                                <X className="w-2.5 h-2.5" />
                              </button>
                            )}
                          </div>

                          {/* Subdomains scroll view */}
                          <div className="max-h-36 overflow-y-auto space-y-1 pr-1">
                            {filteredSubdomains.length > 0 ? (
                              filteredSubdomains.slice(0, 35).map((sub, i) => (
                                <div key={i} className="flex justify-between items-center text-[10px] py-0.5 border-b border-white/5">
                                  <div className="truncate max-w-[75%] flex items-center gap-1">
                                    {sub.source === 'ACTIVE_DOH' && (
                                      <span className="text-[8px] bg-primary-container/20 text-primary-container px-1 py-0.2">ACTIVE</span>
                                    )}
                                    <span className="text-on-surface/80">{sub.subdomain}</span>
                                  </div>
                                  <CopyBtn text={sub.subdomain} />
                                </div>
                              ))
                            ) : (
                              <div className="text-[10px] text-on-surface/40 py-2">No matches found</div>
                            )}
                          </div>
                        </div>
                      ) : (
                        <div className="text-[10px] text-error font-mono">{data.subdomains?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* Historical & Passive DNS */}
                    <div className="bg-surface-container-lowest border border-outline-variant p-4 flex flex-col">
                      <SectionHeader title="Passive DNS & Archives" icon={History} />
                      {data.historical?.available ? (
                        <div className="text-[10px] font-mono uppercase space-y-2">
                          <div className="flex justify-between border-b border-outline/10 py-1">
                            <span className="text-on-surface/50">Wayback Captures:</span>
                            <span className="text-primary-container font-bold">{data.historical.wayback?.snapshot_count ?? 0}</span>
                          </div>
                          <div className="flex justify-between border-b border-outline/10 py-1">
                            <span className="text-on-surface/50">First Archive:</span>
                            <span className="truncate max-w-[50%]">
                              {data.historical.wayback?.first_snapshot
                                ? data.historical.wayback.first_snapshot.slice(0, 8)
                                : 'N/A'}
                            </span>
                          </div>
                          {data.historical.passive_dns && data.historical.passive_dns.length > 0 && (
                            <div>
                              <span className="text-primary-container block mb-1">Passive DNS (OTX):</span>
                              <div className="max-h-20 overflow-y-auto space-y-1">
                                {data.historical.passive_dns.slice(0, 4).map((pdns, i) => (
                                  <div key={i} className="flex justify-between text-[9px] text-on-surface/70">
                                    <span>{pdns.ip}</span>
                                    <span className="text-on-surface/40">{pdns.last_seen ? pdns.last_seen.split('T')[0] : 'N/A'}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="text-[10px] text-on-surface/40 font-mono italic">No historical footprint identified.</div>
                      )}
                    </div>

                  </motion.div>
                </div>
              </div>
            </motion.div>
          )}
        </motion.main>
      </div>

      <Footer
        serverStatus={serverStatus}
        onPrivacyClick={() => setLegalModal('privacy')}
        onTermsClick={() => setLegalModal('terms')}
      />

      {/* Modals */}
      {showTopology && data && <TopologyModal data={data} onClose={() => setShowTopology(false)} />}
      {showRawJson && data && <RawJsonModal data={data} onClose={() => setShowRawJson(false)} />}
      {legalModal && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4" onClick={() => setLegalModal(null)}>
          <div className="bg-surface-container border border-outline-variant p-6 max-w-md w-full relative" onClick={e => e.stopPropagation()}>
            <button onClick={() => setLegalModal(null)} className="absolute top-4 right-4 text-on-surface/50 hover:text-primary-container">
              <X className="w-5 h-5" />
            </button>
            <h2 className="text-lg font-headline font-bold text-primary-container mb-3 uppercase tracking-widest border-b border-primary-container/20 pb-2">
              {legalModal === 'privacy' ? 'Privacy Policy' : 'Terms of Service'}
            </h2>
            <div className="font-body text-xs leading-relaxed space-y-3 text-on-surface/80">
              <p><strong className="text-primary-container font-mono">WEBTRACE</strong> is an educational OSINT domain intelligence project by athx1337.</p>
              <p>URLs and domains submitted are processed in real-time across public threat feeds and DNS servers to compile risk telemetry.</p>
              <p>No user accounts or personal tracking data are stored.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
