import React, { useState } from "react";
import { Link } from "wouter";
import { optionsSchema, type AnalysisOptions } from "@shared/netguard";
import { useAnalysis } from "../contexts/AnalysisContext";
import { startLogin } from "../const";
export default function LiveAnalysis() {
  const state=useAnalysis();const [file,setFile]=useState<File|null>(null);
  const [options,setOptions]=useState<AnalysisOptions>(()=>optionsSchema.parse({}));
  const [ips,setIps]=useState("");const [domains,setDomains]=useState("");
  const running=state.status==="running";
  const split=(s:string)=>s.split(/[\s,]+/).filter(Boolean);
  const fields: Array<[keyof Pick<AnalysisOptions,"workers"|"scan_ports"|"scan_hosts"|"dns_queries"|"window_seconds"|"dns_entropy"|"exfil_bytes">,string]>=[
    ["workers","Worker threads"],["scan_ports","Distinct port threshold"],["scan_hosts","Distinct host threshold"],["dns_queries","High-entropy query threshold"],["window_seconds","Window seconds"],["dns_entropy","DNS entropy threshold"],["exfil_bytes","First-direction byte threshold"]];
  return <section className="shell detail-block" id="live-analysis" aria-label="Live PCAP analysis">
    <div className="detail-block-head"><div><span className="eyebrow">LIVE ENGINE</span><h2>Analyze your packet capture.</h2></div></div>
    <p>Classic Ethernet PCAP, IPv4 TCP/UDP · 32 MiB / 100,000 packets maximum. Only upload captures you are authorized to inspect. Files are sent to the configured backend.</p>
    <form onSubmit={event=>{event.preventDefault();if(file)void state.analyze(file,{...options,deny_ips:split(ips),deny_domains:split(domains.toLowerCase())});}}>
      <div className="mini-stat-grid">
        <label className="mini-stat">PCAP file<input aria-label="PCAP file" type="file" accept=".pcap" disabled={running} onChange={event=>setFile(event.target.files?.[0]??null)} /></label>
        <label className="mini-stat">Backend access token (optional with existing login)<input aria-label="Backend access token" type="password" autoComplete="off" value={state.token} disabled={running} onChange={event=>state.setToken(event.target.value)} /><small>Kept in memory only. Never paste a GitHub token. Use the operator token configured on your own backend.</small></label>
      </div>
      <details><summary>Detection thresholds and blocking policies</summary><div className="mini-stat-grid">
        {fields.map(([key,label])=><label className="mini-stat" key={key}>{label}<input aria-label={label} type="number" step={key==="dns_entropy"?"0.1":"1"} value={options[key]} disabled={running} onChange={event=>setOptions({...options,[key]:Number(event.target.value)})} /></label>)}
        <label className="mini-stat">Deny IPv4 addresses<textarea aria-label="Deny IPv4 addresses" value={ips} disabled={running} onChange={event=>setIps(event.target.value)} placeholder="One IPv4 address per line" /></label>
        <label className="mini-stat">Deny DNS domains<textarea aria-label="Deny DNS domains" value={domains} disabled={running} onChange={event=>setDomains(event.target.value)} placeholder="example.com" /><small>Filters matching unencrypted UDP DNS queries only, not live firewall traffic or subsequent connections.</small></label>
      </div></details>
      <div className="project-actions"><button className="primary-button" type="submit" disabled={!file||running}>{running?"Analyzing capture…":"Analyze PCAP"}</button>
        {running&&<button type="button" className="copy-button" onClick={state.cancel}>Cancel analysis</button>}
        {import.meta.env.VITE_OAUTH_PORTAL_URL&&<button type="button" className="copy-button" onClick={()=>startLogin()}>Sign in</button>}
        <button className="copy-button" type="button" disabled={running} onClick={()=>state.setMode(state.mode==="live"?"demo":"live")}>{state.mode==="live"?"Show demo results":"Show live results"}</button>
      </div>
    </form>
    {running&&<p role="status">Uploading and running the C++ engine. Progress percentage is unavailable; no simulated progress is shown.</p>}
    {state.error&&<p role="alert">{state.error}</p>}
    {state.result&&state.mode==="live"&&<div role="status"><h3>Real analysis complete</h3><p>{state.filename} · {state.result.report.summary.input_packets} packets · {state.result.report.alerts.length} alerts</p><Link href="/analysis">View actual results</Link> · <Link href="/report">View JSON report</Link><p>Input is removed after processing. Downloadable artifacts expire after 10 minutes. Reloading clears local results and the token.</p></div>}
  </section>;
}
