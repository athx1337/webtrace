'use client'

import { useState } from 'react'
import { Activity, AlertTriangle, Check, ChevronRight, Clock3, Database, LockKeyhole, RefreshCw, Search, Server, ShieldCheck, Terminal, Wifi } from 'lucide-react'

const tabs = ['Overview', 'Network', 'Threat Intel', 'Tech Stack', 'History']

function Tile({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <section className={`border border-white/25 bg-[#080b09] ${className}`}>{children}</section>
}

function TileLabel({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[#88908a]">{icon}{children}</div>
}

export function WebtraceDashboard() {
  const [activeTab, setActiveTab] = useState('Overview')
  const [retrying, setRetrying] = useState(false)

  function retryBriefing() {
    setRetrying(true)
    window.setTimeout(() => setRetrying(false), 900)
  }

  return (
    <main className="min-h-screen bg-[#050706] text-[#e7ebe6] selection:bg-[#c8ff3d] selection:text-[#050706]">
      <div className="mx-auto w-full max-w-[1440px] px-5 py-5 sm:px-8 lg:px-12 lg:py-8">
        <header className="flex flex-col gap-6 border-b border-white/25 pb-6 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="mb-5 flex items-center gap-3 text-[#c8ff3d]"><Terminal size={17} strokeWidth={1.5} /><span className="text-xs font-bold tracking-[0.25em]">WEBTRACE // RECONSOLE</span></div>
            <div className="flex items-baseline gap-4"><h1 className="text-3xl font-bold tracking-[-0.07em] sm:text-4xl">Domain reconnaissance</h1><span className="hidden text-xs text-[#707871] sm:inline">/ results</span></div>
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-[#a5ada6]"><span className="text-[#e7ebe6]">northstar-labs.com</span><span className="text-white/30">·</span><span>scan completed 14:32:08 UTC</span><span className="flex items-center gap-1.5 text-[#c8ff3d]"><span className="h-1.5 w-1.5 bg-[#c8ff3d]" />LIVE</span></div>
          </div>
          <button className="flex w-fit items-center gap-2 border border-white/30 px-4 py-2.5 text-xs uppercase tracking-[0.15em] text-[#d4dad4] transition-colors hover:border-[#c8ff3d] hover:text-[#c8ff3d]" aria-label="Start a new scan"><Search size={14} /> New scan</button>
        </header>

        <nav className="mt-6 flex overflow-x-auto border-y border-white/25" aria-label="Dashboard sections">
          {tabs.map((tab) => <button key={tab} onClick={() => setActiveTab(tab)} className={`whitespace-nowrap border-r border-white/25 px-4 py-3 text-[11px] uppercase tracking-[0.12em] transition-colors first:border-l sm:px-6 ${activeTab === tab ? 'bg-[#c8ff3d] font-bold text-[#050706]' : 'text-[#8c958e] hover:bg-white/5 hover:text-[#e7ebe6]'}`} aria-current={activeTab === tab ? 'page' : undefined}>{tab}</button>)}
          <div className="ml-auto hidden items-center gap-2 px-4 text-[10px] uppercase tracking-[0.16em] text-[#667069] lg:flex"><Wifi size={13} /> stream active</div>
        </nav>

        <div className="mt-6 grid grid-cols-1 gap-3 md:grid-cols-4 lg:grid-cols-12">
          <Tile className="min-h-[330px] p-6 md:col-span-2 lg:col-span-5 lg:row-span-2 lg:p-8">
            <div className="flex h-full flex-col justify-between"><div className="flex items-start justify-between"><TileLabel icon={<Activity size={13} />}>Exposure risk</TileLabel><span className="text-[10px] uppercase tracking-[0.12em] text-[#657068]">XR / 01</span></div><div><div className="font-mono text-[10rem] font-bold leading-[0.8] tracking-[-0.12em] text-[#c8ff3d] sm:text-[12rem]">08</div><div className="mt-8 flex items-center gap-3"><span className="bg-[#c8ff3d] px-2 py-1 text-[11px] font-bold uppercase tracking-[0.15em] text-[#050706]">Low exposure</span><span className="text-xs text-[#8c958e]">within safe threshold</span></div></div></div>
          </Tile>

          <Tile className="min-h-[160px] p-5 md:col-span-2 lg:col-span-4"><div className="flex h-full flex-col justify-between"><div className="flex justify-between"><TileLabel icon={<ShieldCheck size={13} />}>Threat feed verdict</TileLabel><span className="text-[10px] text-[#657068]">TF / 06</span></div><div><div className="flex items-center gap-3"><span className="text-5xl font-bold tracking-[-0.08em] text-[#c8ff3d]">CLEAN</span><Check size={24} className="text-[#c8ff3d]" /></div><p className="mt-3 text-xs leading-5 text-[#7d877f]">No confirmed malicious indicators across 46 feeds.</p></div></div></Tile>

          <Tile className="min-h-[160px] p-5 md:col-span-2 lg:col-span-3"><div className="flex h-full flex-col justify-between"><TileLabel icon={<Server size={13} />}>Subdomains</TileLabel><div><div className="flex items-end gap-3"><span className="text-6xl font-bold leading-none tracking-[-0.1em]">27</span><span className="mb-1 text-xs text-[#7d877f]">discovered</span></div><div className="mt-4 flex items-center gap-2 border-t border-white/15 pt-3 text-[10px] uppercase tracking-[0.1em] text-[#aab2ab]"><span className="h-1.5 w-1.5 bg-[#ff4d4d]" /> 03 high-value targets</div></div></div></Tile>

          <Tile className="min-h-[160px] p-5 md:col-span-2 lg:col-span-4"><div className="flex h-full flex-col justify-between"><TileLabel icon={<LockKeyhole size={13} />}>SSL certificate</TileLabel><div><div className="flex items-center gap-3"><span className="text-4xl font-bold tracking-[-0.08em]">VALID</span><span className="h-2 w-2 bg-[#c8ff3d]" /></div><p className="mt-3 text-xs text-[#7d877f]">Let&apos;s Encrypt · expires in 64 days</p></div></div></Tile>

          <Tile className="min-h-[160px] p-5 md:col-span-2 lg:col-span-3"><div className="flex h-full flex-col justify-between"><TileLabel icon={<Clock3 size={13} />}>Domain age</TileLabel><div><div className="flex items-baseline gap-2"><span className="text-6xl font-bold leading-none tracking-[-0.1em]">6.4</span><span className="text-sm text-[#8c958e]">years</span></div><p className="mt-4 text-[10px] uppercase tracking-[0.1em] text-[#7d877f]">registered 12.04.2019</p></div></div></Tile>

          <Tile className="min-h-[160px] p-5 md:col-span-2 lg:col-span-4"><div className="flex h-full flex-col justify-between"><TileLabel icon={<Database size={13} />}>DNS records</TileLabel><div><div className="flex items-baseline gap-2"><span className="text-6xl font-bold leading-none tracking-[-0.1em]">19</span><span className="text-xs text-[#8c958e]">active records</span></div><p className="mt-4 text-[10px] uppercase tracking-[0.1em] text-[#ff4d4d]">2 exposed services detected</p></div></div></Tile>
        </div>

        <section className="mt-3 border border-white/25 bg-[#080b09] p-5 sm:p-6" aria-labelledby="briefing-title"><div className="flex flex-col gap-5 md:flex-row md:items-start md:justify-between"><div><div className="flex items-center gap-3"><h2 id="briefing-title" className="text-xs font-bold uppercase tracking-[0.18em]">AI briefing</h2><span className="border border-white/25 px-2 py-1 text-[9px] uppercase tracking-[0.14em] text-[#747e76]">automated analysis</span></div><div className="mt-6 flex items-start gap-3 text-[#89928a]"><AlertTriangle size={17} className="mt-0.5 shrink-0" /><div><p className="text-sm font-bold text-[#b9c0ba]">Briefing unavailable</p><p className="mt-1 text-xs leading-5">The analysis worker did not respond. Your scan data is intact. Retry to request a new briefing.</p></div></div></div><button onClick={retryBriefing} className="flex w-fit items-center gap-2 border border-white/25 px-4 py-2.5 text-[10px] uppercase tracking-[0.14em] text-[#a9b1aa] transition-colors hover:border-[#e7ebe6] hover:text-[#e7ebe6]" disabled={retrying}><RefreshCw size={13} className={retrying ? 'animate-spin' : ''} /> {retrying ? 'Retrying' : 'Retry briefing'}</button></div><div className="mt-6 border-t border-white/15 pt-4 text-[10px] uppercase tracking-[0.12em] text-[#5f6961]">status: degraded · last attempt 14:32:12 UTC <span className="float-right">request id: wt-8f21c</span></div></section>

        <footer className="flex flex-col gap-3 py-6 text-[10px] uppercase tracking-[0.14em] text-[#5f6961] sm:flex-row sm:items-center sm:justify-between"><span>webtrace / operational intelligence</span><span>scan engine v2.8.4 <ChevronRight className="mx-2 inline" size={11} /> node eu-west-1</span></footer>
      </div>
    </main>
  )
}
