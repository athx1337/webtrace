/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
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
  Server
} from 'lucide-react';

// ---------- Interfaces (matched exactly to backend response shapes) ----------
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
    network?: string;      // CIDR string e.g. "172.64.0.0/13"
    range?: string;
    net_name?: string;
    net_type?: string;
    org?: string;
    country?: string;
    asn?: string;
    abuse_email?: string;
    error?: string;
  };

  dns_records: {
    available: boolean;
    records?: Record<string, string[]>;
    spf?: string | null;
    dmarc?: string | null;
    has_spf?: boolean;
    has_dmarc?: boolean;
    dkim_found?: boolean;
    flags?: string[];
    error?: string;
  };

  ssl: {
    available: boolean;
    valid?: boolean;
    common_name?: string;
    issuer_org?: string;    // NOTE: backend sends issuer_org not issuer
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
    subdomains?: { subdomain: string; issuer: string; not_before: string; not_after: string }[];
    notable?: string[];
    flags?: string[];
    error?: string;
  };

  threat_intel: {
    available: boolean;
    verdict?: string;          // backend sends "verdict" not "aggregate_verdict"
    flagged_by?: number;
    engines?: {                // backend sends "engines" not "results"
      otx?: { available: boolean; pulse_count?: number; malware_families?: string[]; flagged?: boolean };
      abuseipdb?: { available: boolean; abuse_score?: number; total_reports?: number; is_tor?: boolean; flagged?: boolean };
      threatfox?: { available: boolean; ioc_count?: number; threat_types?: string[]; flagged?: boolean };
      greynoise?: { available: boolean; noise?: boolean; riot?: boolean; classification?: string; flagged?: boolean };
      urlhaus?: { available: boolean; url_count?: number; flagged?: boolean };
    };
    error?: string;
  };

  historical: {
    available: boolean;
    wayback?: {               // backend nests this — not flat fields
      available: boolean;
      first_snapshot?: string;
      snapshot_count?: number | null;
      closest_url?: string;
      flag?: string | null;
    };
    ip_history?: {
      available: boolean;
      history?: { ip: string; location: string; owner: string; last_seen: string }[];
      reason?: string;
    };
    error?: string;
  };

  ai_explanation?: {
    available: boolean;
    summary?: string;
    engine?: string;
    error?: string;
  };
}

// ---------- Static Components ----------
const TopNav = () => (
  <nav className="flex justify-between items-center w-full px-6 py-3 bg-surface-container-lowest font-label uppercase tracking-tighter border-b border-primary-container/20 shadow-[0_4px_10px_rgba(0,255,156,0.05)] z-50 shrink-0 relative">
    <div className="flex items-center gap-4">
      <pre className="text-primary-container font-mono font-bold leading-[1.1] text-[8px] md:text-[10px] hidden sm:block pointer-events-none select-none">
{`  ▄▄▄                                              
 █▀██  ██  ██▀▀     █▄    █▄                       
   ██  ██  ██       ██   ▄██▄▄                     
   ██  ██  ██ ▄█▀█▄ ████▄ ██ ████▄▄▀▀█▄ ▄███▀ ▄█▀█▄
   ██▄ ██▄ ██ ██▄█▀ ██ ██ ██ ██   ▄█▀██ ██    ██▄█▀
   ▀████▀███▀▄▀█▄▄▄▄████▀▄██▄█▀  ▄▀█▄██▄▀███▄▄▀█▄▄▄`}
      </pre>
    </div>
  </nav>
);

const Footer = ({ serverStatus }: { serverStatus: 'checking' | 'waking' | 'awake' | 'offline' }) => {
  const statusConfig = {
    awake: { text: 'BACKEND: ONLINE', dotColor: 'bg-primary-container', textColor: 'text-primary-container', pulse: true },
    waking: { text: 'BACKEND: BOOTING', dotColor: 'bg-yellow-400', textColor: 'text-yellow-400', pulse: true },
    checking: { text: 'BACKEND: CONNECTING...', dotColor: 'bg-on-surface/50', textColor: 'text-on-surface/50', pulse: true },
    offline: { text: 'BACKEND: OFFLINE', dotColor: 'bg-error', textColor: 'text-error', pulse: false }
  };
  const config = statusConfig[serverStatus] || statusConfig.checking;

  return (
    <footer className="bg-surface-container-lowest border-t border-outline-variant/10 px-6 py-2 flex justify-between items-center font-label text-[9px] uppercase tracking-widest text-on-surface/40 shrink-0 z-50 relative transition-colors duration-500">
      <div className="flex gap-4 items-center">
        <span className={`${config.textColor} flex items-center gap-1 font-bold tracking-widest transition-colors duration-500`}>
          <span className={`w-1.5 h-1.5 rounded-full ${config.dotColor} ${config.pulse ? 'animate-pulse' : ''} transition-colors duration-500`}></span>
          {config.text}
        </span>
        <span className="hidden sm:inline">node: hk-09.relay.net</span>
        <span className={serverStatus === 'awake' ? 'text-primary-container/70' : 'text-on-surface/30'}>
          ping: {serverStatus === 'awake' ? '18ms' : '--- '}
        </span>
      </div>
      <div>© 2026 WEBTRACE // CLASSIFIED_ACCESS_ONLY</div>
    </footer>
  );
};

// ---------- Animation Variants ----------
const staggerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
};

const fadeUpBlock = {
  hidden: { opacity: 0, y: 15 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.4, ease: "easeOut" } }
};

const SectionHeader = ({ title, icon: Icon, error = false }: { title: string; icon: any; error?: boolean }) => (
  <div className={`flex items-center gap-2 mb-4 font-label ${error ? 'text-error/80' : 'text-primary-container opacity-80'}`}>
    <Icon className="w-4 h-4" />
    <h3 className="text-sm font-bold tracking-widest uppercase">{title}</h3>
  </div>
);

// ---------- Main App ----------
export default function App() {
  const [targetUrl, setTargetUrl] = useState("google.com");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  // System Status State ('checking', 'waking', 'awake', 'offline')
  const [serverStatus, setServerStatus] = useState<'checking' | 'waking' | 'awake' | 'offline'>('checking');
  const [isWaitingForWake, setIsWaitingForWake] = useState(false);

  // Global effect to wake up Render backend on page load and keep it alive
  React.useEffect(() => {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

    const pingServer = () => {
      // If it takes longer than 2 seconds, assume it's doing a cold boot
      const timeout = setTimeout(() => {
        setServerStatus(prev => prev === 'checking' ? 'waking' : prev);
      }, 2000);

      fetch(`${apiUrl}/api/ping`)
        .then(res => {
          if (res.ok) setServerStatus('awake');
          else setServerStatus('offline');
        })
        .catch(() => {
          setServerStatus('waking'); // Usually CORS fails before boot finishes
        })
        .finally(() => {
          clearTimeout(timeout);
        });
    };

    pingServer();

    // Set up a structured heartbeat interval every 10 minutes (600,000 ms).
    // Render's Free Tier hypervisor sleeps web services after 15 minutes of zero inbound HTTP traffic.
    const heartbeatTimer = setInterval(pingServer, 10 * 60 * 1000);

    return () => clearInterval(heartbeatTimer);
  }, []);

  // Rapid polling effect when waiting for wake
  React.useEffect(() => {
    let pollInterval: NodeJS.Timeout;
    if (isWaitingForWake) {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

      const poll = () => {
        fetch(`${apiUrl}/api/ping`)
          .then(res => {
            if (res.ok) setServerStatus('awake');
          })
          .catch(() => {
            setServerStatus('waking');
          });
      };

      pollInterval = setInterval(poll, 3000);
      poll(); // Ping immediately on queue enter
    }
    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [isWaitingForWake]);

  const handleRunAnalysis = async () => {
    if (!targetUrl.trim()) return;

    // Prevent scan execution if server is asleep, enter the pre-queue instead
    if (serverStatus !== 'awake') {
      setIsWaitingForWake(true);
      return;
    }

    setStatus("loading");
    setErrorMsg("");
    setData(null);

    try {
      const apiUrl = import.meta.env.VITE_API_URL || "http://localhost:8000";
      const response = await fetch(`${apiUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
      });

      if (!response.ok) throw new Error(`API returned status ${response.status}`);

      const result = await response.json();
      setData(result);
      setStatus("success");
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to reach the TRACE backend. Ensure it is running on port 8000.");
      setStatus("error");
    }
  };

  // Effect to auto-start the scan once the server announces it is awake
  React.useEffect(() => {
    if (isWaitingForWake && serverStatus === 'awake' && targetUrl) {
      setIsWaitingForWake(false);
      handleRunAnalysis();
    }
  }, [serverStatus, isWaitingForWake]); 



  return (
    <div className="flex flex-col h-screen overflow-hidden bg-background text-inverse-surface relative selection:bg-primary-container selection:text-background font-body">
      <TopNav />
      <div className="flex flex-1 overflow-hidden relative z-10 w-full max-w-7xl mx-auto">
        <motion.main
          className="flex-1 overflow-y-auto p-4 md:p-8 relative z-10"
          variants={staggerVariants}
          initial="hidden"
          animate="visible"
        >

          {/* Header & Input */}
          <motion.div variants={fadeUpBlock} className="mb-8">
            <div className="flex items-end justify-between mb-6">
              <img 
                src="/logo.png" 
                alt="WEBTRACE Logo" 
                className="hidden md:block w-28 md:w-36 object-contain select-none pointer-events-none mb-2" 
                style={{ imageRendering: 'pixelated', filter: 'drop-shadow(0 0 16px rgba(0, 255, 156, 0.4))' }} 
              />
              <div className="text-right font-label text-[10px] uppercase tracking-[0.2em] text-on-surface/50 border-r-2 border-primary-container/40 pr-4">
                <div><span className="text-primary-container">op_mode:</span> OSINT_DEEP_DIVE</div>
                <div><span className="text-primary-container">modules:</span> LOADED_10</div>
                <div><span className="text-primary-container">encryption:</span> AES-256-GCM</div>
              </div>
            </div>

            <div className="bg-surface-container flex flex-col md:flex-row items-center overflow-hidden border border-outline/50 shadow-[0_0_20px_rgba(0,0,0,0.5)] focus-within:border-primary-container focus-within:shadow-[0_0_20px_rgba(0,255,156,0.15)] transition-all">
              <div className="flex-1 flex items-center px-6 py-4 font-label text-primary-container text-lg w-full bg-surface-container-lowest">
                <span className="opacity-50 mr-3 animate-pulse">&gt;</span>
                <span className="text-primary-container/70 mr-3 uppercase font-bold text-sm">analyze_domain</span>
                <input
                  className="bg-transparent border-none focus:ring-0 text-on-surface w-full placeholder:text-on-surface/20 uppercase tracking-wider outline-none font-medium"
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleRunAnalysis()}
                  placeholder="INPUT TARGET (E.G. GOOGLE.COM)"
                  spellCheck="false"
                />
              </div>
              <button
                onClick={handleRunAnalysis}
                disabled={status === "loading"}
                className="bg-primary-container text-on-primary-fixed font-label font-black tracking-widest text-xs px-10 h-full py-5 md:py-0 hover:bg-primary-fixed hover:-translate-y-0.5 active:translate-y-0 transition-transform w-full md:w-auto overflow-hidden relative group"
              >
                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out"></div>
                <span className="relative z-10 flex items-center gap-2 justify-center">
                  {status === "loading" ? <><Loader2 className="w-4 h-4 animate-spin" /> RUNNING...</> : isWaitingForWake ? <><Loader2 className="w-4 h-4 animate-spin" /> WAKING BACKEND...</> : "EXECUTE"}
                </span>
              </button>
            </div>

            <AnimatePresence>
              {status === 'error' && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="mt-4 font-label text-xs text-error tracking-widest bg-error/10 border border-error/20 px-4 py-3 flex items-center gap-3">
                  <AlertTriangle className="w-4 h-4" /> {errorMsg}
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          {/* Loading */}
          <AnimatePresence>
            {status === 'loading' && (
              <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="flex flex-col items-center justify-center py-24 text-primary-container">
                <div className="relative w-24 h-24">
                  <div className="w-24 h-24 border-2 border-primary-container/20 rounded-full animate-spin absolute inset-0"></div>
                  <div className="w-24 h-24 border-t-2 border-l-2 border-primary-container rounded-full absolute inset-0" style={{ animation: 'spin 0.8s linear infinite reverse' }}></div>
                  <Activity className="w-8 h-8 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-80" />
                </div>
                <div className="mt-8 font-label text-sm uppercase tracking-[0.3em] animate-pulse">Engaging Intelligence Modules...</div>
                <div className="mt-2 font-mono text-[10px] text-on-surface/40">Gathering telemetry from 10 distinct nodes</div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Results */}
          {status === 'success' && data && (
            <motion.div variants={staggerVariants} initial="hidden" animate="visible" className="flex flex-col gap-6">

              {/* AI Briefing */}
              {data.ai_explanation && (
                <motion.div variants={fadeUpBlock} className="bg-surface-container-low border border-primary-container/40 p-6 terminal-glow relative overflow-hidden group hover:border-primary-container transition-colors">
                  <div className="absolute -top-10 -right-10 opacity-[0.03] group-hover:opacity-10 transition-opacity duration-700 pointer-events-none">
                    <Brain className="w-64 h-64 text-primary-container" />
                  </div>
                  <SectionHeader title="AI Executive Briefing" icon={Brain} />
                  <p className="font-body text-sm md:text-base text-on-surface leading-relaxed relative z-10 border-l-2 border-primary-container/50 pl-4 py-1">
                    {data.ai_explanation.available
                      ? data.ai_explanation.summary
                      : <span className="text-error">{data.ai_explanation.error || "AI Intel Unavailable"}</span>}
                  </p>
                  {data.ai_explanation.engine && (
                    <div className="mt-3 text-[8px] font-label tracking-widest text-primary-container/50 uppercase">
                      engine: {data.ai_explanation.engine}
                    </div>
                  )}
                </motion.div>
              )}

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

                {/* ── Column 1 ── */}
                <div className="flex flex-col gap-6">

                  {/* Network Identity */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6 flex flex-col gap-6">
                    <SectionHeader title="Network Identity & Resolve" icon={Globe} />

                    {/* Address Lookup */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">Address Lookup</div>
                      {data.address_lookup?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">Canonical:</span>
                          <span className="text-right truncate">{data.address_lookup.canonical || 'N/A'}</span>
                          <span className="text-on-surface/50">IPv4 Nodes:</span>
                          <span className="text-right text-primary-container truncate">{data.address_lookup.ipv4?.join(', ') || 'N/A'}</span>
                          <span className="text-on-surface/50">IPv6 Nodes:</span>
                          <span className="text-right truncate opacity-70">{data.address_lookup.ipv6?.length ? data.address_lookup.ipv6[0] : 'N/A'}</span>
                          {data.address_lookup.cdn_detected && (
                            <>
                              <span className="text-on-surface/50">CDN:</span>
                              <span className="text-right text-yellow-400 uppercase">{data.address_lookup.cdn_detected} ⚠ Real IP Hidden</span>
                            </>
                          )}
                        </div>
                      ) : (
                        <div className="text-xs text-error font-mono">{data.address_lookup?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* Domain WHOIS */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">
                        Domain Registry (WHOIS) {data.whois_domain?.source && <span className="opacity-40 ml-2">via {data.whois_domain.source}</span>}
                      </div>
                      {data.whois_domain?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">Registrar:</span>
                          <span className="text-right text-primary-container/90 truncate">{data.whois_domain.registrar || 'UNKNOWN'}</span>
                          <span className="text-on-surface/50">Age (Days):</span>
                          <span className="text-right">{data.whois_domain.age_days ?? 'UNKNOWN'}</span>
                          <span className="text-on-surface/50">Created:</span>
                          <span className="text-right truncate opacity-80">{data.whois_domain.created ? data.whois_domain.created.split('T')[0] : 'N/A'}</span>
                          <span className="text-on-surface/50">Expires:</span>
                          <span className="text-right truncate opacity-80">{data.whois_domain.expires ? data.whois_domain.expires.split('T')[0] : 'N/A'}</span>
                          <span className="text-on-surface/50">Reg Org:</span>
                          <span className="text-right truncate">{data.whois_domain.registrant_org || 'N/A'}</span>
                          <span className="text-on-surface/50">DNSSEC:</span>
                          <span className={`text-right ${data.whois_domain.dnssec === 'SIGNED' ? 'text-primary-container' : 'text-yellow-400'}`}>
                            {data.whois_domain.dnssec || 'N/A'}
                          </span>
                        </div>
                      ) : (
                        <div className="text-xs text-error font-mono">{data.whois_domain?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* Network WHOIS */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">IP Block Authority (ARIN)</div>
                      {data.whois_network?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">ISP / Org:</span>
                          <span className="text-right text-primary-container truncate">{data.whois_network.org || data.whois_network.net_name || 'UNKNOWN'}</span>
                          <span className="text-on-surface/50">ASN:</span>
                          <span className="text-right">{data.whois_network.asn || 'N/A'}</span>
                          <span className="text-on-surface/50">CIDR:</span>
                          <span className="text-right">{data.whois_network.network || 'N/A'}</span>
                          <span className="text-on-surface/50">Country:</span>
                          <span className="text-right">{data.whois_network.country || 'N/A'}</span>
                        </div>
                      ) : (
                        <div className="text-xs text-on-surface/40 font-mono italic">No network routing intel fetched.</div>
                      )}
                    </div>
                  </motion.div>

                  {/* DNS & SSL */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6 flex flex-col gap-6">
                    <SectionHeader title="Cryptographic & DNS Ledger" icon={Database} />

                    {/* SSL */}
                    <div>
                      <div className="text-[10px] font-label text-primary-container uppercase border-b border-primary-container/20 pb-1 mb-3">X.509 Certificate Profile</div>
                      {data.ssl?.available ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono uppercase">
                          <span className="text-on-surface/50">Verdict:</span>
                          <span className={`text-right font-bold ${data.ssl.valid ? 'text-primary-container' : 'text-error'}`}>
                            {data.ssl.valid ? 'VALID' : 'INVALID'}
                          </span>
                          <span className="text-on-surface/50">Issuer CA:</span>
                          <span className="text-right truncate flex items-center justify-end gap-1">
                            {data.ssl.is_free_ca && <span className="bg-surface-container-highest text-[8px] px-1">FREE CA</span>}
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
                          {data.ssl.is_new_cert && (
                            <span className="col-span-2 text-error text-[10px]">⚠ Certificate issued less than 7 days ago</span>
                          )}
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
                          <div className="grid grid-cols-3 gap-2 mb-3 bg-surface-container p-2 text-center text-[10px]">
                            <div className={data.dns_records.has_spf ? "text-primary-container" : "text-error"}>
                              SPF {data.dns_records.has_spf ? 'OK' : 'MISSING'}
                            </div>
                            <div className={data.dns_records.has_dmarc ? "text-primary-container" : "text-error"}>
                              DMARC {data.dns_records.has_dmarc ? 'OK' : 'MISSING'}
                            </div>
                            <div className={data.dns_records.dkim_found ? "text-primary-container" : "text-error"}>
                              DKIM {data.dns_records.dkim_found ? 'OK' : 'MISSING'}
                            </div>
                          </div>
                          <div className="max-h-36 overflow-y-auto pr-1 space-y-1">
                            {Object.entries(data.dns_records.records || {}).map(([type, records]) => {
                              if (!records || (records as string[]).length === 0) return null;
                              return (records as string[]).map((r, i) => (
                                <div key={`${type}-${i}`} className="flex justify-between border-b border-white/5 py-1">
                                  <span className="text-primary-container/80 w-12 shrink-0">{type}</span>
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
                        <div className={`flex items-center justify-between p-3 border font-label tracking-widest uppercase text-sm
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
                            <div className="text-lg">{Object.keys(data.threat_intel.engines || {}).length}</div>
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
                                <span className={`px-2 py-0.5 ${engine?.flagged ? 'bg-error/20 text-error' : 'bg-primary-container/10 text-primary-container'}`}>
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

                  {/* Infrastructure */}
                  <motion.div variants={fadeUpBlock} className="bg-surface-container-lowest border border-outline-variant p-6">
                    <SectionHeader title="Infrastructure Surface (Shodan DB)" icon={Server} />
                    {data.infrastructure?.available ? (
                      <div className="space-y-4 text-xs font-mono uppercase">
                        <div>
                          <span className="text-[10px] text-on-surface/50 block mb-2">Open Ports</span>
                          <div className="flex flex-wrap gap-2 text-primary-container">
                            {data.infrastructure.ports && data.infrastructure.ports.length > 0
                              ? data.infrastructure.ports.map(p => (
                                <span key={p} className="bg-primary-container/10 px-2 py-0.5">{p}</span>
                              ))
                              : <span className="text-on-surface/40">NO OPEN PORTS DETECTED</span>}
                          </div>
                        </div>

                        {data.infrastructure.vulns && data.infrastructure.vulns.length > 0 && (
                          <div>
                            <span className="text-[10px] text-error/80 block mb-2">Known CVEs</span>
                            <div className="flex flex-wrap gap-2 text-error">
                              {data.infrastructure.vulns.slice(0, 8).map((cve: string) => (
                                <span key={cve} className="bg-error/10 border border-error/20 px-1 py-0.5 text-[10px]">{cve}</span>
                              ))}
                              {data.infrastructure.vulns.length > 8 && (
                                <span className="opacity-60 pt-1">+{data.infrastructure.vulns.length - 8} MORE</span>
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
                            <span className="text-on-surface/50 block mb-1">CPEs</span>
                            <span className="text-on-surface/80 opacity-60">
                              {data.infrastructure.cpes?.length ? `${data.infrastructure.cpes.length} Software Fingerprints` : 'NONE'}
                            </span>
                          </div>
                        </div>

                        {data.infrastructure.flags && data.infrastructure.flags.length > 0 && (
                          <div className="space-y-1 mt-2">
                            {data.infrastructure.flags.map((flag, i) => (
                              <div key={i} className="text-[10px] text-error/80 bg-error/5 border-l-2 border-error px-2 py-1">{flag}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-xs text-on-surface/40 font-mono italic">{data.infrastructure?.error || "No infrastructure profile found."}</div>
                    )}
                  </motion.div>

                  {/* Subdomains + Historical */}
                  <motion.div variants={fadeUpBlock} className="grid grid-cols-2 gap-6">

                    {/* Subdomains */}
                    <div className="bg-surface-container-lowest border border-outline-variant p-4 flex flex-col">
                      <SectionHeader title="Subdomain CT Logs" icon={Network} />
                      {data.subdomains?.available ? (
                        <div className="text-xs font-mono uppercase space-y-3">
                          <div className="flex justify-between items-center text-primary-container border-b border-primary-container/20 pb-1">
                            <span>crt.sh returned</span>
                            <span className="font-bold">{data.subdomains.total ?? 0}</span>
                          </div>
                          {data.subdomains.notable && data.subdomains.notable.length > 0 && (
                            <div>
                              <span className="text-[8px] text-error mb-1 block">SENSITIVE FOUND:</span>
                              <div className="max-h-24 overflow-y-auto space-y-1">
                                {data.subdomains.notable.map((sub: string, i: number) => (
                                  <div key={i} className="truncate text-[10px] pl-1 border-l border-error text-error opacity-80">{sub}</div>
                                ))}
                              </div>
                            </div>
                          )}
                          {(!data.subdomains.notable || data.subdomains.notable.length === 0) && (
                            <div className="text-[10px] text-on-surface/40">No sensitive subdomains flagged</div>
                          )}
                        </div>
                      ) : (
                        <div className="text-[10px] text-error font-mono">{data.subdomains?.error || "UNAVAILABLE"}</div>
                      )}
                    </div>

                    {/* Historical */}
                    <div className="bg-surface-container-lowest border border-outline-variant p-4 flex flex-col">
                      <SectionHeader title="Historical Footprint" icon={History} />
                      {data.historical?.available ? (
                        <div className="text-[10px] font-mono uppercase space-y-2">
                          <div className="flex justify-between border-b border-outline/10 py-1">
                            <span className="text-on-surface/50">Wayback Captures:</span>
                            <span className="text-primary-container">{data.historical.wayback?.snapshot_count ?? 0}</span>
                          </div>
                          <div className="flex justify-between border-b border-outline/10 py-1">
                            <span className="text-on-surface/50">First Seen (WB):</span>
                            <span className="truncate max-w-[50%]">
                              {data.historical.wayback?.first_snapshot
                                ? data.historical.wayback.first_snapshot.slice(0, 8)
                                : 'N/A'}
                            </span>
                          </div>
                          <div className="flex justify-between border-b border-outline/10 py-1">
                            <span className="text-on-surface/50">IP History:</span>
                            <span>{data.historical.ip_history?.history?.length ?? 0} IPs</span>
                          </div>
                          {data.historical.wayback?.flag && (
                            <div className="text-error text-[9px] mt-1">{data.historical.wayback.flag}</div>
                          )}
                        </div>
                      ) : (
                        <div className="text-[10px] text-on-surface/40 font-mono italic">{data.historical?.error || "No historical footprint identified."}</div>
                      )}
                    </div>

                  </motion.div>
                </div>
              </div>
            </motion.div>
          )}
        </motion.main>
      </div>
      <Footer serverStatus={serverStatus} />
    </div>
  );
}
