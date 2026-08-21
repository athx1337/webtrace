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
  LockKeyhole,
  Clock3,
  Wifi,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Cpu,
  Mail,
  GitCompare,
  Clock,
  RefreshCw
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
      otx?: { available: boolean; pulse_count: number; malware_families: string[]; tags: string[]; flagged: boolean; error?: string };
      abuseipdb?: { available: boolean; abuse_score: number; total_reports: number; last_reported: string; is_tor: boolean; usage_type: string; isp: string; flagged: boolean; error?: string };
      threatfox?: { available: boolean; flagged: boolean; ioc_count?: number; threat_types?: string[]; malware?: string[]; error?: string };
      greynoise?: { available: boolean; noise: boolean; riot: boolean; classification: string; name: string; flagged: boolean; error?: string };
      urlhaus?: { available: boolean; flagged: boolean; url_count: number; tags: string[]; error?: string };
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
      error?: string;
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
    penalties.push({ reason: `Exposed legacy/database ports (${openSensitive.join(', ')})`, deduction });
  }

  // SSL Issues
  if (data.ssl?.available && !data.ssl.valid) {
    score -= 20;
    penalties.push({ reason: 'Invalid or untrusted SSL certificate', deduction: 20 });
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

  let label = 'LOW EXPOSURE';
  let color = 'text-[#c8ff3d]';
  let bg = 'bg-[#c8ff3d]';

  if (score < 50) {
    label = 'CRITICAL RISK';
    color = 'text-[#ff4d4d]';
    bg = 'bg-[#ff4d4d]';
  } else if (score < 80) {
    label = 'MODERATE EXPOSURE';
    color = 'text-[#ffaa00]';
    bg = 'bg-[#ffaa00]';
  }

  return { score, label, color, bg, penalties };
}

// ---------- Tile Components from New Redesign ----------
function Tile({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <section className={`border border-white/20 bg-[#080b09] ${className}`}>{children}</section>;
}

function TileLabel({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[#88908a]">
      {icon}
      {children}
    </div>
  );
}

// ---------- Unified Status Badge Component ----------
const StatusBadge = ({ status, label }: { status: 'pass' | 'fail' | 'warn' | 'unavailable'; label: string }) => {
  if (status === 'pass') {
    return <span className="px-2 py-0.5 bg-[#c8ff3d]/10 border border-[#c8ff3d]/30 text-[#c8ff3d] text-[10px] font-mono font-bold tracking-wider">✓ {label}</span>;
  }
  if (status === 'warn') {
    return <span className="px-2 py-0.5 bg-[#ffaa00]/10 border border-[#ffaa00]/30 text-[#ffaa00] text-[10px] font-mono font-bold tracking-wider">⚠ {label}</span>;
  }
  if (status === 'fail') {
    return <span className="px-2 py-0.5 bg-[#ff4d4d]/10 border border-[#ff4d4d]/30 text-[#ff4d4d] text-[10px] font-mono font-bold tracking-wider">✗ {label}</span>;
  }
  return <span className="px-2 py-0.5 bg-white/5 border border-white/10 text-white/40 text-[10px] font-mono tracking-wider">⚪ {label}</span>;
};

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
      className="p-1 hover:text-[#c8ff3d] text-white/40 transition-colors inline-flex items-center cursor-pointer"
    >
      {copied ? <Check className="w-3 h-3 text-[#c8ff3d]" /> : <Copy className="w-3 h-3" />}
    </button>
  );
};

// ---------- Static Navigation ----------
const TopNav = ({ onOpenTopology, hasData }: { onOpenTopology?: () => void; hasData?: boolean }) => (
  <nav className="flex justify-between items-center w-full px-6 py-3 bg-[#040605] border-b border-white/20 shadow-[0_4px_16px_rgba(200,255,61,0.04)] z-50 shrink-0 relative">
    <div className="flex items-center gap-3">
      <img
        src="/navbar-logo.png"
        alt="WEBTRACE"
        className="h-8 md:h-9 w-auto object-contain"
        style={{ filter: 'drop-shadow(0 0 10px rgba(200, 255, 61, 0.45))' }}
      />
    </div>
    <div className="flex items-center gap-4">
      {hasData && onOpenTopology && (
        <button
          onClick={onOpenTopology}
          className="flex items-center gap-2 font-label text-[10px] uppercase tracking-widest text-[#c8ff3d] border border-[#c8ff3d]/30 px-3 py-1.5 hover:bg-[#c8ff3d]/10 transition-all cursor-pointer"
        >
          <Network className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Attack Surface Map</span>
        </button>
      )}
      <div className="font-label text-[9px] uppercase tracking-widest text-[#c8ff3d]/90 flex items-center gap-2 border border-[#c8ff3d]/20 px-2.5 py-1 bg-[#0c100d]">
        <span className="w-1.5 h-1.5 bg-[#c8ff3d] animate-pulse"></span>
        v2.8.4 OPERATIONAL_ENGINE
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
    awake: { text: 'EDGE: ONLINE', dotColor: 'bg-[#c8ff3d]', textColor: 'text-[#c8ff3d]', pulse: true },
    waking: { text: 'EDGE: INITIALIZING', dotColor: 'bg-[#ffaa00]', textColor: 'text-[#ffaa00]', pulse: true },
    checking: { text: 'EDGE: CONNECTING...', dotColor: 'bg-white/50', textColor: 'text-white/50', pulse: true },
    offline: { text: 'EDGE: OFFLINE', dotColor: 'bg-[#ff4d4d]', textColor: 'text-[#ff4d4d]', pulse: false }
  };
  const config = statusConfig[serverStatus] || statusConfig.checking;

  return (
    <footer className="bg-[#040605] border-t border-white/15 px-6 py-3 flex flex-col sm:flex-row justify-between items-center font-label text-[10px] uppercase tracking-[0.14em] text-[#5f6961] shrink-0 z-50 relative gap-2">
      <div className="flex gap-4 items-center">
        <span className={`${config.textColor} flex items-center gap-1.5 font-bold tracking-widest transition-colors duration-500`}>
          <span className={`w-1.5 h-1.5 ${config.dotColor} ${config.pulse ? 'animate-pulse' : ''}`}></span>
          {config.text}
        </span>
        <span className="hidden sm:inline">defense: SSRF_FIREWALL_ACTIVE</span>
        <span className={serverStatus === 'awake' ? 'text-[#c8ff3d]/80' : 'text-white/30'}>
          latency: {serverStatus === 'awake' ? '11ms' : '--- '}
        </span>
      </div>
      <div className="flex gap-3 items-center">
        <button onClick={onPrivacyClick} className="hover:text-[#c8ff3d] transition-colors cursor-pointer">
          PRIVACY
        </button>
        <button onClick={onTermsClick} className="hover:text-[#c8ff3d] transition-colors cursor-pointer">
          TERMS
        </button>
        <span className="hidden sm:inline ml-2">© 2026 WEBTRACE // RECONSOLE</span>
      </div>
    </footer>
  );
};

const SectionHeader = ({ title, icon: Icon, badge }: { title: string; icon: any; badge?: string }) => (
  <div className="flex items-center justify-between mb-4 font-label text-[#c8ff3d]">
    <div className="flex items-center gap-2">
      <Icon className="w-4 h-4" />
      <h3 className="text-xs md:text-sm font-bold tracking-widest uppercase">{title}</h3>
    </div>
    {badge && (
      <span className="text-[9px] px-2 py-0.5 border border-[#c8ff3d]/30 bg-[#c8ff3d]/10 font-mono tracking-wider">
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
        className="bg-[#080b09] border border-[#c8ff3d]/40 p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto relative shadow-[0_0_50px_rgba(200,255,61,0.15)] font-mono"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center border-b border-white/20 pb-3 mb-6">
          <div className="flex items-center gap-2 text-[#c8ff3d] font-label text-sm uppercase tracking-widest font-bold">
            <Network className="w-5 h-5" /> Attack Surface Topology Map: {data.domain}
          </div>
          <button onClick={onClose} className="text-white/60 hover:text-[#c8ff3d] cursor-pointer">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-6 text-xs uppercase">
          <div className="border border-[#c8ff3d] bg-[#c8ff3d]/10 p-4 flex items-center justify-between">
            <div>
              <span className="text-[#c8ff3d] font-bold text-base tracking-wider">{data.domain}</span>
              <div className="text-[10px] text-white/60 mt-1">Registrar: {data.whois_domain?.registrar || 'UNKNOWN'} • Age: {data.whois_domain?.age_days || 0}d</div>
            </div>
            <div className="text-right">
              <span className="px-2 py-1 bg-black border border-[#c8ff3d]/30 text-[#c8ff3d] text-[10px]">ROOT TARGET</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="border border-white/20 p-4 bg-[#0c100d] space-y-2">
              <div className="text-[#c8ff3d] font-bold text-[11px] flex items-center gap-1.5 border-b border-white/10 pb-1">
                <Globe className="w-3.5 h-3.5" /> IP & Network Nodes
              </div>
              <div className="space-y-1 text-[11px]">
                {data.address_lookup?.ipv4?.map((ip, i) => (
                  <div key={i} className="text-[#c8ff3d] flex justify-between">
                    <span>{ip}</span>
                    <CopyBtn text={ip} />
                  </div>
                )) || <div className="text-white/40">No IP</div>}
                {data.whois_network?.network && (
                  <div className="text-[10px] text-white/60 pt-2 border-t border-white/10">
                    CIDR: {data.whois_network.network} ({data.whois_network.org})
                  </div>
                )}
              </div>
            </div>

            <div className="border border-white/20 p-4 bg-[#0c100d] space-y-2">
              <div className="text-[#c8ff3d] font-bold text-[11px] flex items-center gap-1.5 border-b border-white/10 pb-1">
                <Server className="w-3.5 h-3.5" /> Exposed Surface
              </div>
              <div className="text-[11px] space-y-1">
                <div className="text-white/70">
                  Open Ports: <span className="text-[#c8ff3d]">{data.infrastructure?.ports?.join(', ') || 'None'}</span>
                </div>
                <div className="text-white/70">
                  CVEs: <span className="text-[#ff4d4d] font-bold">{data.infrastructure?.vulns?.length || 0} Detected</span>
                </div>
                {data.address_lookup?.cdn_detected && (
                  <div className="text-[#ffaa00] text-[10px]">
                    CDN: {data.address_lookup.cdn_detected}
                  </div>
                )}
              </div>
            </div>

            <div className="border border-white/20 p-4 bg-[#0c100d] space-y-2">
              <div className="text-[#c8ff3d] font-bold text-[11px] flex items-center gap-1.5 border-b border-white/10 pb-1">
                <ShieldAlert className="w-3.5 h-3.5" /> Threat & Subdomains
              </div>
              <div className="text-[11px] space-y-1">
                <div>Verdict: <span className="font-bold text-[#c8ff3d]">{data.threat_intel?.verdict || 'CLEAN'}</span></div>
                <div>Subdomains: <span className="text-white">{data.subdomains?.total || 0} Total</span></div>
                <div>Active Probed: <span className="text-[#c8ff3d]">{data.subdomains?.active_probed || 0}</span></div>
                <div>High-Risk Endpoints: <span className="text-[#ff4d4d] font-bold">{data.subdomains?.notable?.length || 0}</span></div>
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
        className="bg-[#080b09] border border-[#c8ff3d]/40 p-6 max-w-4xl w-full max-h-[90vh] flex flex-col relative shadow-[0_0_50px_rgba(0,0,0,0.8)] font-mono"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center border-b border-white/20 pb-3 mb-4 shrink-0">
          <div className="flex items-center gap-2 text-[#c8ff3d] font-label text-sm uppercase tracking-widest font-bold">
            <FileCode className="w-5 h-5" /> Raw Telemetry Ledger: {data.domain}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-xs border border-[#c8ff3d]/40 text-[#c8ff3d] px-3 py-1 hover:bg-[#c8ff3d]/10 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'COPIED' : 'COPY JSON'}
            </button>
            <button onClick={onClose} className="text-white/60 hover:text-[#c8ff3d] cursor-pointer">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>
        <pre className="flex-1 overflow-auto bg-black p-4 text-[11px] text-[#c8ff3d]/90 border border-white/10 selection:bg-[#c8ff3d] selection:text-black">
          {jsonString}
        </pre>
      </motion.div>
    </div>
  );
};

// ---------- Main App Component ----------
export default function App() {
  const [targetUrl, setTargetUrl] = useState("google.com");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [activeTab, setActiveTab] = useState<'Overview' | 'Network & DNS' | 'Threat Radar' | 'Tech Stack' | 'Subdomains & History'>('Overview');
  const [legalModal, setLegalModal] = useState<'privacy' | 'terms' | null>(null);
  const [showTopology, setShowTopology] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);
  const [expandAllCves, setExpandAllCves] = useState(false);
  const [subdomainSearch, setSubdomainSearch] = useState("");
  const [scanHistory, setScanHistory] = useState<string[]>([]);
  const [scanDiffAlert, setScanDiffAlert] = useState<string[]>([]);
  const [retryingBrief, setRetryingBrief] = useState(false);

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
        const prevIp = prev.address_lookup?.ipv4?.[0];
        const currIp = current.address_lookup?.ipv4?.[0];
        if (prevIp && currIp && prevIp !== currIp) {
          diffs.push(`IP address changed from ${prevIp} ➔ ${currIp}`);
        }

        const prevTotal = prev.subdomains?.total || 0;
        const currTotal = current.subdomains?.total || 0;
        if (currTotal > prevTotal) {
          diffs.push(`+ ${currTotal - prevTotal} new subdomain(s) discovered since previous scan`);
        }

        const prevDays = prev.ssl?.days_remaining;
        const currDays = current.ssl?.days_remaining;
        if (prevDays != null && currDays != null && prevDays !== currDays) {
          diffs.push(`SSL lifespan changed: ${currDays} days remaining (was ${prevDays}d)`);
        }
      }

      setScanDiffAlert(diffs);
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
    setExpandAllCves(false);
    setActiveTab('Overview');

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

  const handleRetryBriefing = () => {
    if (!data) return;
    setRetryingBrief(true);
    setTimeout(() => {
      setRetryingBrief(false);
    }, 1000);
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
4. 📧 EMAIL SECURITY & AUTHENTICATION
================================================================================
- SPF Policy: ${data.dns_records?.has_spf ? 'CONFIGURED' : 'MISSING'}
- DMARC Policy: ${data.dns_records?.has_dmarc ? 'CONFIGURED' : 'MISSING'}
- DKIM Selectors: ${data.dns_records?.dkim_found ? 'CONFIGURED' : 'MISSING'}

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
    if (subdomainSearch.trim()) {
      const q = subdomainSearch.toLowerCase().trim();
      list = list.filter(s => s.subdomain.toLowerCase().includes(q) || s.issuer.toLowerCase().includes(q));
    }
    return list;
  }, [data, subdomainSearch]);

  const PRESET_TARGETS = ['google.com', 'github.com', 'cloudflare.com', 'ktiwari.in', 'wikipedia.org'];
  const TABS: Array<'Overview' | 'Network & DNS' | 'Threat Radar' | 'Tech Stack' | 'Subdomains & History'> = [
    'Overview',
    'Network & DNS',
    'Threat Radar',
    'Tech Stack',
    'Subdomains & History'
  ];

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#050706] text-[#e7ebe6] relative selection:bg-[#c8ff3d] selection:text-[#050706] font-body cyber-grid">
      <TopNav onOpenTopology={() => setShowTopology(true)} hasData={!!data} />

      <div className="flex flex-1 overflow-hidden relative z-10 w-full max-w-[1440px] mx-auto">
        <main className="flex-1 overflow-y-auto p-4 md:p-8 relative z-10">

          {/* Header Title & ASCII Art preserved */}
          <div className="mb-6">
            <div className="flex items-end justify-between mb-4">
              <pre className="hidden md:block ascii-art text-[#c8ff3d] opacity-90 text-[clamp(6px,0.8vw,10px)] select-none pointer-events-none font-bold leading-none">
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
              <div className="text-right font-label text-[10px] uppercase tracking-[0.2em] text-[#88908a] border-r-2 border-[#c8ff3d]/50 pr-4">
                <div><span className="text-[#c8ff3d]">op_mode:</span> OSINT_RECONSOLE</div>
                <div><span className="text-[#c8ff3d]">recon_engine:</span> ACTIVE_DOH_15</div>
                <div><span className="text-[#c8ff3d]">defense:</span> SSRF_FIREWALL</div>
              </div>
            </div>

            {/* Input Bar */}
            <div className="bg-[#080b09] flex flex-col md:flex-row items-center overflow-hidden border border-white/25 shadow-[0_0_30px_rgba(0,0,0,0.8)] focus-within:border-[#c8ff3d] focus-within:shadow-[0_0_25px_rgba(200,255,61,0.15)] transition-all">
              <div className="flex-1 flex items-center px-6 py-4 font-label text-[#c8ff3d] text-lg w-full bg-[#040605]">
                <span className="opacity-60 mr-3 animate-pulse">&gt;</span>
                <span className="text-[#c8ff3d]/80 mr-3 uppercase font-bold text-sm">analyze_domain</span>
                <input
                  className="bg-transparent border-none focus:ring-0 text-[#e7ebe6] w-full placeholder:text-white/20 uppercase tracking-wider outline-none font-medium text-sm md:text-base font-mono"
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
                className="bg-[#c8ff3d] text-[#050706] font-label font-black tracking-widest text-xs px-10 h-full py-4 md:py-0 hover:bg-[#d8ff6b] active:translate-y-0 transition-transform w-full md:w-auto overflow-hidden relative group cursor-pointer"
              >
                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out"></div>
                <span className="relative z-10 flex items-center gap-2 justify-center font-bold">
                  {status === "loading" ? <><Loader2 className="w-4 h-4 animate-spin" /> RUNNING...</> : "EXECUTE"}
                </span>
              </button>
            </div>

            {/* Target Presets & Quick Chips */}
            <div className="flex items-center gap-2 mt-3 flex-wrap text-[10px] font-mono">
              <span className="text-[#88908a] uppercase tracking-wider">PRESETS:</span>
              {PRESET_TARGETS.map(t => (
                <button
                  key={t}
                  onClick={() => handleRunAnalysis(t)}
                  className="px-2.5 py-0.5 bg-[#080b09] hover:bg-[#c8ff3d]/10 border border-white/20 text-[#a5ada6] hover:text-[#c8ff3d] hover:border-[#c8ff3d]/40 transition-colors cursor-pointer"
                >
                  {t}
                </button>
              ))}
              {scanHistory.length > 0 && (
                <>
                  <span className="text-white/25 ml-2">| RECENT:</span>
                  {scanHistory.slice(0, 3).map(h => (
                    <button
                      key={h}
                      onClick={() => handleRunAnalysis(h)}
                      className="px-2 py-0.5 bg-[#0c100d] hover:border-[#c8ff3d]/40 border border-transparent text-[#c8ff3d]/80 transition-colors cursor-pointer"
                    >
                      {h}
                    </button>
                  ))}
                </>
              )}
            </div>

            {status === 'error' && (
              <div className="mt-4 font-label text-xs text-[#ff4d4d] tracking-widest bg-[#ff4d4d]/10 border border-[#ff4d4d]/25 px-4 py-3 flex items-center gap-3">
                <AlertTriangle className="w-4 h-4 shrink-0" /> {errorMsg}
              </div>
            )}
          </div>

          {/* Loading Animation HUD */}
          {status === 'loading' && (
            <div className="flex flex-col items-center justify-center py-24 text-[#c8ff3d]">
              <div className="relative w-28 h-28">
                <div className="w-28 h-28 border-2 border-[#c8ff3d]/20 rounded-full animate-spin absolute inset-0"></div>
                <div className="w-28 h-28 border-t-2 border-l-2 border-[#c8ff3d] rounded-full absolute inset-0" style={{ animation: 'spin 0.9s linear infinite reverse' }}></div>
                <div className="w-16 h-16 border border-[#c8ff3d]/40 rounded-full absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-ping opacity-25"></div>
                <Activity className="w-8 h-8 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-90" />
              </div>
              <div className="mt-8 font-label text-sm uppercase tracking-[0.3em] animate-pulse">Running Deep Reconnaissance & Active Probing...</div>
              <div className="mt-2 font-mono text-[10px] text-[#7d877f]">Querying DNS, RDAP, Shodan, Threat Feeds, Tech Stack & AI Briefing</div>
            </div>
          )}

          {/* Results Display */}
          {status === 'success' && data && (
            <div className="flex flex-col gap-6">

              {/* Scan Delta / Historical Comparison Banner */}
              {scanDiffAlert.length > 0 && (
                <div className="bg-[#c8ff3d]/10 border border-[#c8ff3d]/30 p-3.5 font-label text-xs">
                  <div className="flex items-center gap-2 text-[#c8ff3d] font-bold uppercase tracking-wider mb-1">
                    <GitCompare className="w-4 h-4" /> Historical Delta Alert (Changes Since Previous Scan)
                  </div>
                  <div className="space-y-1 text-[#e7ebe6]/90 font-mono text-[11px] pl-6">
                    {scanDiffAlert.map((diff, i) => (
                      <div key={i}>• {diff}</div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action Bar & Quick Tools */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/20 pb-4 font-label text-xs">
                <div>
                  <div className="flex items-baseline gap-3">
                    <h1 className="text-2xl sm:text-3xl font-bold tracking-[-0.05em] text-[#e7ebe6]">{data.domain}</h1>
                    <span className="text-xs text-[#707871]">/ recon results</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-[#a5ada6]">
                    <span>Canonical: {data.address_lookup?.canonical || data.domain}</span>
                    <span className="text-white/30">·</span>
                    <span className="flex items-center gap-1.5 text-[#c8ff3d]"><span className="h-1.5 w-1.5 bg-[#c8ff3d]" />PENTEST_GRADE</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    onClick={() => setShowTopology(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#080b09] hover:bg-[#c8ff3d]/10 border border-white/25 text-[#c8ff3d] text-[11px] uppercase tracking-wider transition-colors cursor-pointer"
                  >
                    <Layers className="w-3.5 h-3.5" /> Topology Map
                  </button>
                  <button
                    onClick={handleExportMarkdown}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#080b09] hover:bg-[#c8ff3d]/10 border border-white/25 text-[#d4dad4] hover:text-[#c8ff3d] text-[11px] uppercase tracking-wider transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" /> Export Report (.md)
                  </button>
                  <button
                    onClick={() => setShowRawJson(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#080b09] hover:bg-[#c8ff3d]/10 border border-white/25 text-[#d4dad4] hover:text-[#c8ff3d] text-[11px] uppercase tracking-wider transition-colors cursor-pointer"
                  >
                    <FileCode className="w-3.5 h-3.5" /> Raw JSON
                  </button>
                </div>
              </div>

              {/* Navigation Tabs from New Redesign */}
              <nav className="flex overflow-x-auto border-y border-white/25" aria-label="Dashboard sections">
                {TABS.map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`whitespace-nowrap border-r border-white/25 px-4 py-3 text-[11px] uppercase tracking-[0.12em] transition-colors first:border-l sm:px-6 cursor-pointer ${
                      activeTab === tab
                        ? 'bg-[#c8ff3d] font-bold text-[#050706]'
                        : 'text-[#8c958e] hover:bg-white/5 hover:text-[#e7ebe6]'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
                <div className="ml-auto hidden items-center gap-2 px-4 text-[10px] uppercase tracking-[0.16em] text-[#667069] lg:flex">
                  <Wifi size={13} /> stream active
                </div>
              </nav>

              {/* ── TAB 1: OVERVIEW ── */}
              {activeTab === 'Overview' && (
                <div className="space-y-6">
                  {/* Hero Bento Grid */}
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-4 lg:grid-cols-12">
                    {/* Big Exposure Risk Tile */}
                    {riskAssessment && (
                      <Tile className="min-h-[300px] p-6 md:col-span-2 lg:col-span-5 lg:row-span-2 lg:p-8">
                        <div className="flex h-full flex-col justify-between">
                          <div className="flex items-start justify-between">
                            <TileLabel icon={<Activity size={13} />}>Exposure Health Index</TileLabel>
                            <span className="text-[10px] uppercase tracking-[0.12em] text-[#657068]">XR / 01</span>
                          </div>
                          <div>
                            <div className={`font-mono text-8xl sm:text-9xl font-bold leading-[0.8] tracking-[-0.1em] ${riskAssessment.color}`}>
                              {String(riskAssessment.score).padStart(2, '0')}
                            </div>
                            <div className="mt-6 flex items-center gap-3">
                              <span className={`${riskAssessment.bg} px-2 py-1 text-[11px] font-bold uppercase tracking-[0.15em] text-[#050706]`}>
                                {riskAssessment.label}
                              </span>
                              <span className="text-xs text-[#8c958e]">
                                {riskAssessment.penalties.length === 0 ? 'within safe threshold' : `${riskAssessment.penalties.length} penalty factors`}
                              </span>
                            </div>
                          </div>
                        </div>
                      </Tile>
                    )}

                    {/* Metric 1: Threat Feed Verdict */}
                    <Tile className="min-h-[150px] p-5 md:col-span-2 lg:col-span-4">
                      <div className="flex h-full flex-col justify-between">
                        <div className="flex justify-between">
                          <TileLabel icon={<ShieldCheck size={13} />}>Threat Feed Verdict</TileLabel>
                          <span className="text-[10px] text-[#657068]">TF / 05</span>
                        </div>
                        <div>
                          <div className="flex items-center gap-3">
                            <span className={`text-4xl sm:text-5xl font-bold tracking-[-0.08em] ${data.threat_intel?.verdict === 'CLEAN' ? 'text-[#c8ff3d]' : 'text-[#ff4d4d]'}`}>
                              {data.threat_intel?.verdict || 'CLEAN'}
                            </span>
                            {data.threat_intel?.verdict === 'CLEAN' && <Check size={24} className="text-[#c8ff3d]" />}
                          </div>
                          <p className="mt-2 text-xs leading-5 text-[#7d877f]">
                            {data.threat_intel?.flagged_by === 0 ? 'No confirmed malicious indicators across feeds.' : `Flagged by ${data.threat_intel?.flagged_by} security vendor(s).`}
                          </p>
                        </div>
                      </div>
                    </Tile>

                    {/* Metric 2: Subdomains */}
                    <Tile className="min-h-[150px] p-5 md:col-span-2 lg:col-span-3">
                      <div className="flex h-full flex-col justify-between">
                        <TileLabel icon={<Server size={13} />}>Subdomains</TileLabel>
                        <div>
                          <div className="flex items-end gap-3">
                            <span className="text-5xl font-bold leading-none tracking-[-0.1em]">{data.subdomains?.total ?? 0}</span>
                            <span className="mb-1 text-xs text-[#7d877f]">discovered</span>
                          </div>
                          <div className="mt-3 flex items-center gap-2 border-t border-white/15 pt-2 text-[10px] uppercase tracking-[0.1em] text-[#aab2ab]">
                            <span className={`h-1.5 w-1.5 ${(data.subdomains?.notable?.length ?? 0) > 0 ? 'bg-[#ff4d4d]' : 'bg-[#c8ff3d]'}`} />
                            {String(data.subdomains?.notable?.length ?? 0).padStart(2, '0')} high-value targets
                          </div>
                        </div>
                      </div>
                    </Tile>

                    {/* Metric 3: SSL Certificate */}
                    <Tile className="min-h-[150px] p-5 md:col-span-2 lg:col-span-4">
                      <div className="flex h-full flex-col justify-between">
                        <TileLabel icon={<LockKeyhole size={13} />}>SSL Certificate</TileLabel>
                        <div>
                          <div className="flex items-center gap-3">
                            <span className={`text-3xl font-bold tracking-[-0.08em] ${data.ssl?.valid ? 'text-[#c8ff3d]' : 'text-[#ff4d4d]'}`}>
                              {data.ssl?.valid ? 'VALID' : 'UNTRUSTED'}
                            </span>
                            <span className={`h-2 w-2 ${data.ssl?.valid ? 'bg-[#c8ff3d]' : 'bg-[#ff4d4d]'}`} />
                          </div>
                          <p className="mt-2 text-xs text-[#7d877f]">
                            {data.ssl?.issuer_org || 'Unknown CA'} · {data.ssl?.days_remaining != null ? `expires in ${data.ssl.days_remaining}d` : 'no expiry'}
                          </p>
                        </div>
                      </div>
                    </Tile>

                    {/* Metric 4: Domain Age */}
                    <Tile className="min-h-[150px] p-5 md:col-span-2 lg:col-span-3">
                      <div className="flex h-full flex-col justify-between">
                        <TileLabel icon={<Clock3 size={13} />}>Domain Age</TileLabel>
                        <div>
                          <div className="flex items-baseline gap-2">
                            <span className="text-5xl font-bold leading-none tracking-[-0.1em]">
                              {data.whois_domain?.age_days != null ? (data.whois_domain.age_days / 365.25).toFixed(1) : '---'}
                            </span>
                            <span className="text-sm text-[#8c958e]">years</span>
                          </div>
                          <p className="mt-3 text-[10px] uppercase tracking-[0.1em] text-[#7d877f]">
                            registered {data.whois_domain?.created ? data.whois_domain.created.split('T')[0] : 'UNKNOWN'}
                          </p>
                        </div>
                      </div>
                    </Tile>
                  </div>

                  {/* Structured AI Pentest Briefing Tile */}
                  {data.ai_explanation && (
                    <section className="border border-white/20 bg-[#080b09] p-6 terminal-glow relative" aria-labelledby="briefing-title">
                      <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 mb-4 pb-3 border-b border-white/15">
                        <div className="flex items-center gap-3">
                          <Brain className="w-5 h-5 text-[#c8ff3d]" />
                          <h2 id="briefing-title" className="text-xs font-bold uppercase tracking-[0.18em] text-[#c8ff3d]">
                            Structured AI Pentest Briefing
                          </h2>
                          <span className="border border-white/20 px-2 py-0.5 text-[9px] uppercase tracking-[0.14em] text-[#747e76]">
                            {data.ai_explanation.engine || 'AI Engine'}
                          </span>
                        </div>
                        <button
                          onClick={handleRetryBriefing}
                          disabled={retryingBrief}
                          className="flex items-center gap-2 border border-white/25 px-3 py-1.5 text-[10px] uppercase tracking-[0.14em] text-[#a9b1aa] hover:border-[#c8ff3d] hover:text-[#c8ff3d] transition-colors cursor-pointer"
                        >
                          <RefreshCw size={12} className={retryingBrief ? 'animate-spin' : ''} />
                          {retryingBrief ? 'Refreshed' : 'Re-analyze'}
                        </button>
                      </div>

                      <div className="font-body text-xs md:text-sm text-[#e7ebe6] leading-relaxed whitespace-pre-line border-l-2 border-[#c8ff3d]/60 pl-4 py-1 space-y-3">
                        {data.ai_explanation.available ? (
                          data.ai_explanation.summary
                        ) : (
                          <StatusBadge status="unavailable" label="AI BRIEFING UNAVAILABLE" />
                        )}
                      </div>
                    </section>
                  )}
                </div>
              )}

              {/* ── TAB 2: NETWORK & DNS ── */}
              {activeTab === 'Network & DNS' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Network Routing & Identity */}
                  <Tile className="p-6 flex flex-col gap-6">
                    <SectionHeader title="Network Identity & Routing" icon={Globe} />

                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3 flex justify-between">
                        <span>Address Lookup</span>
                        <span className="text-[#88908a]">Cloudflare DoH</span>
                      </div>
                      {data.address_lookup?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-[#88908a]">Canonical:</span>
                          <span className="text-right truncate flex items-center justify-end gap-1">
                            {data.address_lookup.canonical || 'N/A'}
                            <CopyBtn text={data.address_lookup.canonical} />
                          </span>
                          <span className="text-[#88908a]">IPv4 Nodes:</span>
                          <span className="text-right text-[#c8ff3d] truncate flex items-center justify-end gap-1">
                            {data.address_lookup.ipv4?.join(', ') || 'N/A'}
                            <CopyBtn text={data.address_lookup.ipv4?.[0]} />
                          </span>
                          <span className="text-[#88908a]">IPv6 Nodes:</span>
                          <span className="text-right truncate opacity-70">{data.address_lookup.ipv6?.length ? data.address_lookup.ipv6[0] : 'N/A'}</span>
                          {data.address_lookup.cdn_detected && (
                            <>
                              <span className="text-[#88908a]">CDN Detected:</span>
                              <span className="text-right text-[#ffaa00] uppercase">{data.address_lookup.cdn_detected} (Proxied)</span>
                            </>
                          )}
                        </div>
                      ) : (
                        <StatusBadge status="unavailable" label="ADDRESS LOOKUP UNAVAILABLE" />
                      )}
                    </div>

                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3 flex justify-between">
                        <span>Domain Registry (WHOIS)</span>
                        <span className="text-[#88908a]">{data.whois_domain?.source || 'RDAP'}</span>
                      </div>
                      {data.whois_domain?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-[#88908a]">Registrar:</span>
                          <span className="text-right text-[#c8ff3d]/90 truncate">{data.whois_domain.registrar || 'UNKNOWN'}</span>
                          <span className="text-[#88908a]">Age:</span>
                          <span className="text-right">{data.whois_domain.age_days != null ? `${data.whois_domain.age_days} Days` : 'UNKNOWN'}</span>
                          <span className="text-[#88908a]">Created:</span>
                          <span className="text-right truncate opacity-80">{data.whois_domain.created ? data.whois_domain.created.split('T')[0] : 'N/A'}</span>
                          <span className="text-[#88908a]">Expires:</span>
                          <span className="text-right truncate opacity-80">{data.whois_domain.expires ? data.whois_domain.expires.split('T')[0] : 'N/A'}</span>
                          <span className="text-[#88908a]">DNSSEC:</span>
                          <span className={`text-right font-bold ${data.whois_domain.dnssec === 'SIGNED' ? 'text-[#c8ff3d]' : 'text-[#ffaa00]'}`}>
                            {data.whois_domain.dnssec || 'UNSIGNED'}
                          </span>
                        </div>
                      ) : (
                        <StatusBadge status="unavailable" label="WHOIS REGISTRY UNAVAILABLE" />
                      )}
                    </div>

                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3 flex justify-between">
                        <span>IP Block Authority & ASN</span>
                        <span className="text-[#88908a]">Universal RDAP</span>
                      </div>
                      {data.whois_network?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-[#88908a]">ISP / Org:</span>
                          <span className="text-right text-[#c8ff3d] truncate">{data.whois_network.org || data.whois_network.net_name || 'UNKNOWN'}</span>
                          <span className="text-[#88908a]">ASN:</span>
                          <span className="text-right">{data.whois_network.asn || 'N/A'}</span>
                          <span className="text-[#88908a]">CIDR:</span>
                          <span className="text-right truncate">{data.whois_network.network || 'N/A'}</span>
                          <span className="text-[#88908a]">Country:</span>
                          <span className="text-right">{data.whois_network.country || 'N/A'}</span>
                        </div>
                      ) : (
                        <StatusBadge status="unavailable" label="NETWORK WHOIS UNAVAILABLE" />
                      )}
                    </div>
                  </Tile>

                  {/* Cryptographic & Email Posture */}
                  <Tile className="p-6 flex flex-col gap-6">
                    <SectionHeader title="Cryptographic & Email Posture" icon={Database} />

                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3">X.509 Certificate Profile</div>
                      {data.ssl?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-[#88908a]">Verdict:</span>
                          <span className={`text-right font-bold ${data.ssl.valid ? 'text-[#c8ff3d]' : 'text-[#ff4d4d]'}`}>
                            {data.ssl.valid ? 'VALID CERTIFICATE' : 'INVALID / UNTRUSTED'}
                          </span>
                          <span className="text-[#88908a]">Issuer CA:</span>
                          <span className="text-right truncate flex items-center justify-end gap-1">
                            {data.ssl.is_free_ca && <span className="bg-white/10 text-[8px] px-1 text-[#ffaa00]">FREE CA</span>}
                            {data.ssl.issuer_org || 'UNKNOWN'}
                          </span>
                          <span className="text-[#88908a]">Lifespan:</span>
                          <span className={`text-right ${data.ssl.days_remaining && data.ssl.days_remaining < 30 ? 'text-[#ff4d4d]' : 'opacity-80'}`}>
                            {data.ssl.days_remaining != null ? `${data.ssl.days_remaining} Days Left` : 'N/A'}
                          </span>
                          <span className="text-[#88908a]">SAN Count:</span>
                          <span className="text-right opacity-80">{data.ssl.san_count ?? data.ssl.sans?.length ?? 0} Domains</span>
                        </div>
                      ) : (
                        <StatusBadge status="unavailable" label="CERTIFICATE PROFILE UNAVAILABLE" />
                      )}
                    </div>

                    {/* Dedicated Email Security Table */}
                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3 flex items-center gap-1.5">
                        <Mail className="w-3.5 h-3.5" /> Email Security & Spoofing Defense
                      </div>
                      {data.dns_records?.available ? (
                        <div className="space-y-2 text-xs font-mono uppercase">
                          <div className="flex items-center justify-between p-2 bg-[#0c100d] border border-white/10">
                            <div>
                              <span className="text-white/80 font-bold block text-[11px]">SPF Policy</span>
                              <span className="text-[9px] text-[#88908a]">Sender Policy Framework validation</span>
                            </div>
                            <StatusBadge status={data.dns_records.has_spf ? 'pass' : 'fail'} label={data.dns_records.has_spf ? 'CONFIGURED' : 'MISSING'} />
                          </div>

                          <div className="flex items-center justify-between p-2 bg-[#0c100d] border border-white/10">
                            <div>
                              <span className="text-white/80 font-bold block text-[11px]">DMARC Policy</span>
                              <span className="text-[9px] text-[#88908a]">Domain-based Message Authentication</span>
                            </div>
                            <StatusBadge status={data.dns_records.has_dmarc ? 'pass' : 'fail'} label={data.dns_records.has_dmarc ? 'CONFIGURED' : 'MISSING'} />
                          </div>

                          <div className="flex items-center justify-between p-2 bg-[#0c100d] border border-white/10">
                            <div>
                              <span className="text-white/80 font-bold block text-[11px]">DKIM Selector</span>
                              <span className="text-[9px] text-[#88908a]">DomainKeys Identified Mail</span>
                            </div>
                            <StatusBadge status={data.dns_records.dkim_found ? 'pass' : 'fail'} label={data.dns_records.dkim_found ? 'FOUND' : 'MISSING'} />
                          </div>
                        </div>
                      ) : (
                        <StatusBadge status="unavailable" label="EMAIL POSTURE UNAVAILABLE" />
                      )}
                    </div>

                    {/* Authoritative DNS Record Ledger */}
                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3">
                        Authoritative DNS Record Ledger
                      </div>
                      {data.dns_records?.available ? (
                        <div className="max-h-36 overflow-y-auto pr-1 space-y-1 font-mono text-xs">
                          {Object.entries(data.dns_records.records || {}).map(([type, records]) => {
                            if (!records || (records as string[]).length === 0) return null;
                            return (records as string[]).map((r, i) => (
                              <div key={`${type}-${i}`} className="flex justify-between border-b border-white/5 py-1">
                                <span className="text-[#c8ff3d]/80 w-12 shrink-0 font-bold">{type}</span>
                                <span className="text-right truncate text-white/80 pl-2 text-[10px]">{r}</span>
                              </div>
                            ));
                          })}
                        </div>
                      ) : (
                        <StatusBadge status="unavailable" label="DNS RECORDS UNAVAILABLE" />
                      )}
                    </div>
                  </Tile>
                </div>
              )}

              {/* ── TAB 3: THREAT RADAR ── */}
              {activeTab === 'Threat Radar' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Global Threat Radar */}
                  <Tile className="p-6 flex flex-col gap-4">
                    <SectionHeader title="Global Threat Radar" icon={ShieldAlert} />

                    {data.threat_intel?.available ? (
                      <div className="space-y-4">
                        <div className={`flex items-center justify-between p-3.5 border font-label tracking-widest uppercase text-sm ${
                          data.threat_intel.verdict === 'CLEAN'
                            ? 'bg-[#c8ff3d]/10 border-[#c8ff3d]/30 text-[#c8ff3d]'
                            : data.threat_intel.verdict === 'MALICIOUS'
                              ? 'bg-[#ff4d4d]/10 border-[#ff4d4d]/50 text-[#ff4d4d]'
                              : 'bg-[#ffaa00]/10 border-[#ffaa00]/30 text-[#ffaa00]'
                        }`}>
                          <span>Aggregate Verdict</span>
                          <span className="font-bold">{data.threat_intel.verdict || 'UNKNOWN'}</span>
                        </div>

                        <div className="grid grid-cols-2 gap-4 text-xs font-mono uppercase text-center">
                          <div className="bg-[#0c100d] py-3 border border-white/10">
                            <div className="text-[10px] text-[#88908a] mb-1">Vendors Polled</div>
                            <div className="text-lg font-bold">{Object.keys(data.threat_intel.engines || {}).length}</div>
                          </div>
                          <div className="bg-[#0c100d] py-3 border border-white/10">
                            <div className="text-[10px] text-[#88908a] mb-1">Engines Flagged</div>
                            <div className={`text-lg font-bold ${(data.threat_intel.flagged_by ?? 0) > 0 ? 'text-[#ff4d4d]' : 'text-[#c8ff3d]'}`}>
                              {data.threat_intel.flagged_by ?? 0}
                            </div>
                          </div>
                        </div>

                        {data.threat_intel.engines && (
                          <div className="space-y-1.5 mt-2">
                            {Object.entries(data.threat_intel.engines).map(([name, engine]: [string, any]) => (
                              <div key={name} className="flex items-center justify-between text-[11px] font-mono uppercase py-1 border-b border-white/10">
                                <span className="text-white/70">{name}</span>
                                {engine?.flagged ? (
                                  <StatusBadge status="fail" label="FLAGGED" />
                                ) : engine?.available === false ? (
                                  <StatusBadge status="unavailable" label="UNAVAILABLE" />
                                ) : (
                                  <StatusBadge status="pass" label="CLEAN" />
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <StatusBadge status="unavailable" label="THREAT RADAR UNAVAILABLE" />
                    )}
                  </Tile>

                  {/* Infrastructure Surface & CVEs */}
                  <Tile className="p-6 flex flex-col gap-4">
                    <SectionHeader title="Infrastructure Surface (Shodan DB)" icon={Server} />

                    {data.infrastructure?.available ? (
                      <div className="space-y-4 text-xs font-mono uppercase">
                        <div>
                          <span className="text-[10px] text-white/70 font-bold block mb-2">Open Ports ({data.infrastructure.ports?.length || 0})</span>
                          <div className="flex flex-wrap gap-1.5">
                            {data.infrastructure.ports && data.infrastructure.ports.length > 0 ? (
                              data.infrastructure.ports.map(p => {
                                const isDanger = [21, 23, 25, 110, 143, 3306, 5432, 27017].includes(p);
                                return (
                                  <span
                                    key={p}
                                    className={`px-2 py-0.5 border text-[11px] ${isDanger ? 'bg-[#ff4d4d]/10 border-[#ff4d4d]/40 text-[#ff4d4d] font-bold' : 'bg-[#c8ff3d]/10 border-[#c8ff3d]/20 text-[#c8ff3d]'}`}
                                  >
                                    {p}
                                  </span>
                                );
                              })
                            ) : (
                              <span className="text-white/40">NO OPEN PORTS DETECTED</span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 mt-2 text-[9px] text-white/40 font-mono">
                            <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[#c8ff3d]"></span> 🟢 Standard / Encrypted</span>
                            <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[#ff4d4d]"></span> 🔴 Legacy / Database</span>
                          </div>
                        </div>

                        {data.infrastructure.vulns && data.infrastructure.vulns.length > 0 && (
                          <div className="border-t border-white/10 pt-3">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-[10px] text-[#ff4d4d] font-bold">
                                Exposed CVE Vulnerabilities ({data.infrastructure.vulns.length})
                              </span>
                              {data.infrastructure.vulns.length > 6 && (
                                <button
                                  onClick={() => setExpandAllCves(!expandAllCves)}
                                  className="text-[10px] text-[#c8ff3d] flex items-center gap-1 hover:underline cursor-pointer"
                                >
                                  {expandAllCves ? <>COLLAPSE <ChevronUp className="w-3 h-3" /></> : <>SHOW ALL ({data.infrastructure.vulns.length}) <ChevronDown className="w-3 h-3" /></>}
                                </button>
                              )}
                            </div>
                            <div className={`flex flex-wrap gap-1.5 ${expandAllCves ? 'max-h-48 overflow-y-auto' : ''}`}>
                              {(expandAllCves ? data.infrastructure.vulns : data.infrastructure.vulns.slice(0, 6)).map((cve: string) => (
                                <span key={cve} className="bg-[#ff4d4d]/10 border border-[#ff4d4d]/30 px-1.5 py-0.5 text-[10px] text-[#ff4d4d] font-mono">
                                  {cve}
                                </span>
                              ))}
                              {!expandAllCves && data.infrastructure.vulns.length > 6 && (
                                <button
                                  onClick={() => setExpandAllCves(true)}
                                  className="text-[#ff4d4d]/80 px-2 py-0.5 border border-[#ff4d4d]/20 bg-[#ff4d4d]/5 text-[10px] hover:bg-[#ff4d4d]/20 cursor-pointer"
                                >
                                  +{data.infrastructure.vulns.length - 6} MORE...
                                </button>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <StatusBadge status="unavailable" label="INFRASTRUCTURE PROFILE UNAVAILABLE" />
                    )}
                  </Tile>
                </div>
              )}

              {/* ── TAB 4: TECH STACK ── */}
              {activeTab === 'Tech Stack' && (
                <Tile className="p-6">
                  <SectionHeader title="Technology Stack & Security Headers Audit" icon={Cpu} />
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3">
                        Identified Technologies & Server Header
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {data.tech_stack?.tech_stack && data.tech_stack.tech_stack.length > 0 ? (
                          data.tech_stack.tech_stack.map((t, i) => (
                            <span key={i} className="px-2.5 py-1 bg-[#c8ff3d]/10 border border-[#c8ff3d]/30 text-[#c8ff3d] text-[11px]">
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-white/40">No specific framework signatures matched</span>
                        )}
                      </div>
                    </div>

                    <div>
                      <div className="text-[10px] font-label text-[#c8ff3d] uppercase border-b border-white/10 pb-1 mb-3">
                        Security Headers Compliance
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px]">
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-white/60">HSTS (HTTPS):</span>
                          <span className={data.tech_stack?.security_headers?.hsts?.present ? "text-[#c8ff3d] font-bold" : "text-[#ff4d4d]"}>
                            {data.tech_stack?.security_headers?.hsts?.present ? "✓ ENFORCED" : "✗ MISSING"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-white/60">CSP (XSS Def):</span>
                          <span className={data.tech_stack?.security_headers?.csp?.present ? "text-[#c8ff3d] font-bold" : "text-[#ff4d4d]"}>
                            {data.tech_stack?.security_headers?.csp?.present ? "✓ CONFIGURED" : "✗ MISSING"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-white/60">X-Frame-Options:</span>
                          <span className={data.tech_stack?.security_headers?.x_frame_options?.present ? "text-[#c8ff3d] font-bold" : "text-[#ff4d4d]"}>
                            {data.tech_stack?.security_headers?.x_frame_options?.present ? "✓ CONFIGURED" : "✗ MISSING"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between border-b border-white/5 pb-1">
                          <span className="text-white/60">X-Content-Type:</span>
                          <span className={data.tech_stack?.security_headers?.x_content_type_options?.present ? "text-[#c8ff3d] font-bold" : "text-[#ff4d4d]"}>
                            {data.tech_stack?.security_headers?.x_content_type_options?.present ? "✓ CONFIGURED" : "✗ MISSING"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </Tile>
              )}

              {/* ── TAB 5: SUBDOMAINS & HISTORY ── */}
              {activeTab === 'Subdomains & History' && (
                <div className="space-y-6">
                  {/* Subdomain Reconnaissance Panel */}
                  <Tile className="p-6">
                    <SectionHeader
                      title="Subdomain Reconnaissance (Active DoH Probe + CT Logs)"
                      icon={Network}
                      badge={`${data.subdomains?.total ?? 0} Subdomains Tracked`}
                    />

                    {data.subdomains?.available ? (
                      <div className="space-y-4">
                        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
                          <div className="flex items-center gap-4 text-xs font-mono">
                            <div className="flex items-center gap-1.5">
                              <span className="text-white/50">Active Probed:</span>
                              <span className="text-[#c8ff3d] font-bold">{data.subdomains.active_probed ?? 0}</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                              <span className="text-white/50">High-Value Endpoints:</span>
                              <span className="text-[#ff4d4d] font-bold">{data.subdomains.notable?.length ?? 0}</span>
                            </div>
                          </div>

                          <div className="flex items-center gap-1.5 bg-[#0c100d] px-3 py-1 border border-white/20 w-full sm:w-64">
                            <Search className="w-3.5 h-3.5 text-white/40" />
                            <input
                              type="text"
                              value={subdomainSearch}
                              onChange={(e) => setSubdomainSearch(e.target.value)}
                              placeholder="SEARCH SUBDOMAINS..."
                              className="bg-transparent border-none outline-none text-[11px] w-full text-white font-mono uppercase"
                            />
                            {subdomainSearch && (
                              <button onClick={() => setSubdomainSearch("")} className="text-white/40 hover:text-[#c8ff3d]">
                                <X className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-64 overflow-y-auto pr-1 font-mono text-xs">
                          {filteredSubdomains.length > 0 ? (
                            filteredSubdomains.map((sub, i) => {
                              const isHighValue = data.subdomains?.notable?.includes(sub.subdomain);
                              const isActive = sub.source === 'ACTIVE_DOH';

                              return (
                                <div
                                  key={i}
                                  className={`p-2.5 border flex items-center justify-between transition-colors ${
                                    isHighValue ? 'bg-[#ff4d4d]/5 border-[#ff4d4d]/30' : 'bg-[#0c100d] border-white/10 hover:border-[#c8ff3d]/30'
                                  }`}
                                >
                                  <div className="truncate max-w-[80%]">
                                    <div className="flex items-center gap-1.5 mb-1">
                                      {isActive ? (
                                        <span className="text-[8px] bg-[#c8ff3d]/20 text-[#c8ff3d] px-1 py-0.2 border border-[#c8ff3d]/40">ACTIVE_DOH</span>
                                      ) : (
                                        <span className="text-[8px] bg-white/10 text-white/50 px-1 py-0.2">CT_LOG</span>
                                      )}
                                      {isHighValue && (
                                        <span className="text-[8px] bg-[#ff4d4d]/20 text-[#ff4d4d] px-1 py-0.2 border border-[#ff4d4d]/40">HIGH_VALUE</span>
                                      )}
                                    </div>
                                    <div className="text-white font-medium truncate text-[11px]">{sub.subdomain}</div>
                                  </div>
                                  <CopyBtn text={sub.subdomain} />
                                </div>
                              );
                            })
                          ) : (
                            <div className="col-span-full py-4 text-center text-white/40 font-mono text-xs">
                              No subdomains matched filter
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <StatusBadge status="unavailable" label="SUBDOMAIN SERVICE UNAVAILABLE" />
                    )}
                  </Tile>

                  {/* Historical Footprint & Resolution Timeline */}
                  <Tile className="p-6">
                    <SectionHeader title="Historical Footprint & Resolution Timeline" icon={History} />

                    <div className="space-y-4 font-mono text-xs">
                      <div className="grid grid-cols-2 gap-3 border-b border-white/10 pb-3 text-[11px]">
                        <div>
                          <span className="text-white/50 block">Wayback Captures:</span>
                          <span className="text-[#c8ff3d] font-bold">{data.historical?.wayback?.snapshot_count ?? 0}</span>
                        </div>
                        <div>
                          <span className="text-white/50 block">First Archive:</span>
                          <span>{data.historical?.wayback?.first_snapshot ? data.historical.wayback.first_snapshot.slice(0, 8) : 'N/A'}</span>
                        </div>
                      </div>

                      <div>
                        <div className="text-[10px] text-[#c8ff3d] uppercase font-bold mb-2 flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5" /> Resolution Timeline (Passive DNS)
                        </div>

                        {data.historical?.ip_history?.history && data.historical.ip_history.history.length > 0 ? (
                          <div className="space-y-2 border-l border-[#c8ff3d]/30 pl-3 ml-1.5 my-2">
                            {data.historical.ip_history.history.map((rec, i) => (
                              <div key={i} className="relative text-[11px]">
                                <div className="absolute -left-[17px] top-1.5 w-2 h-2 bg-[#c8ff3d]"></div>
                                <div className="flex items-center justify-between text-white">
                                  <span className="font-bold text-[#c8ff3d]">{rec.ip}</span>
                                  <span className="text-[10px] text-white/50">{rec.last_seen}</span>
                                </div>
                                <div className="text-[10px] text-white/60 truncate">{rec.owner} ({rec.location})</div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-white/40 text-[11px] py-1">No historical IP changes recorded</div>
                        )}
                      </div>
                    </div>
                  </Tile>
                </div>
              )}

            </div>
          )}
        </main>
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
          <div className="bg-[#080b09] border border-white/20 p-6 max-w-md w-full relative" onClick={e => e.stopPropagation()}>
            <button onClick={() => setLegalModal(null)} className="absolute top-4 right-4 text-white/50 hover:text-[#c8ff3d] cursor-pointer">
              <X className="w-5 h-5" />
            </button>
            <h2 className="text-lg font-headline font-bold text-[#c8ff3d] mb-3 uppercase tracking-widest border-b border-white/20 pb-2">
              {legalModal === 'privacy' ? 'Privacy Policy' : 'Terms of Service'}
            </h2>
            <div className="font-body text-xs leading-relaxed space-y-3 text-white/80">
              <p><strong className="text-[#c8ff3d] font-mono">WEBTRACE</strong> is an educational OSINT domain intelligence project by athx1337.</p>
              <p>URLs and domains submitted are processed in real-time across public threat feeds and DNS servers to compile risk telemetry.</p>
              <p>No user accounts or personal tracking data are stored.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
