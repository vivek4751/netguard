import React, { useMemo, useState } from "react";
import { Braces, Check, Copy, FileCheck2, ShieldAlert } from "lucide-react";
import { Link } from "wouter";
import SiteChrome from "@/components/SiteChrome";
import { demoSummary, reportJson as demoReportJson } from "@/data/netguardDemo";
import { useAnalysis } from "@/contexts/AnalysisContext";
function JsonView({ value }: { value: string }) {
  const tokenized = useMemo(() => {
    const tokenPattern = /("(?:\\.|[^"\\])*")(?=\s*:)|("(?:\\.|[^"\\])*")|(\btrue\b|\bfalse\b|\bnull\b)|(-?\d+(?:\.\d+)?)|([{}\[\],:])/g;
    return value.split("\n").map((line, lineIndex) => {
      const parts: React.ReactNode[] = []; let cursor = 0; let match: RegExpExecArray | null;
      while ((match = tokenPattern.exec(line)) !== null) {
        if (match.index > cursor) parts.push(line.slice(cursor, match.index));
        const className = match[1] ? "json-key" : match[2] ? "json-string" : match[3] ? "json-boolean" : match[4] ? "json-number" : "json-punctuation";
        parts.push(<span className={className} key={`${lineIndex}-${match.index}`}>{match[0]}</span>); cursor = match.index + match[0].length;
      }
      if (cursor < line.length) parts.push(line.slice(cursor));
      return <div className="json-line" key={lineIndex}>{parts.length ? parts : " "}</div>;
    });
  }, [value]);
  return <code className="json-code">{tokenized}</code>;
}
export default function Report() {
  const state=useAnalysis();const live=state.mode==="live";const report=live?state.result?.report:undefined;
  const [copied,setCopied]=useState(false);const [copyError,setCopyError]=useState("");
  const reportJson=useMemo(()=>report?JSON.stringify(report,null,2):demoReportJson,[report]);
  const copyReport=async()=>{try{if(!navigator.clipboard)throw Error("Clipboard unavailable; use the download instead.");await navigator.clipboard.writeText(reportJson);setCopied(true);setCopyError("");window.setTimeout(()=>setCopied(false),1700);}catch(error){setCopyError(error instanceof Error?error.message:"Copy failed.");}};
  if(live&&!report)return <SiteChrome><main className="shell detail-page"><h1>No live report yet</h1><p role="status">{state.status==="running"?"The engine is processing your capture.":"Upload a PCAP to generate an actual report."}</p>{state.error&&<p role="alert">{state.error}</p>}<Link href="/#live-analysis">Open upload</Link></main></SiteChrome>;
  const preview=reportJson.length>200000?reportJson.slice(0,200000):reportJson;
  return <SiteChrome><main className="shell detail-page report-page">
    <section className="page-intro"><span className="eyebrow">{live?"Live engine evidence":"Sample evidence — simulated"}</span><h1>One report for people<br/>and <em>automation.</em></h1><p>{live?"Validated JSON from the C++ engine. Summary, alerts, flows and policy results match the dashboard.":"This is the original illustrative demo report, not an uploaded capture."}</p></section>
    <section className="report-summary-strip"><span><FileCheck2 size={16}/>{report?.summary.parsed_packets??demoSummary.parsedPackets} packets parsed</span><span><ShieldAlert size={16}/>{report?.alerts.length??demoSummary.alerts} evidence-backed alerts</span><span><Braces size={16}/> application/json</span></section>
    <section className="detail-block report-detail"><div className="detail-block-head"><div><span className="eyebrow">Findings artifact</span><h2>findings.json</h2></div><button className="copy-button" onClick={()=>void copyReport()}>{copied?<Check size={15}/>:<Copy size={15}/>} {copied?"Copied":"Copy JSON"}</button></div>
      {live&&<div className="project-actions"><button className="primary-button" onClick={()=>void state.download("findings.json")}>Download JSON</button><button className="copy-button" onClick={()=>void state.download("filtered.pcap")}>Download filtered PCAP</button></div>}
      {(state.error||copyError)&&<p role="alert">{copyError||state.error}</p>}
      {preview.length!==reportJson.length&&<p>Preview truncated to 200,000 characters. Copy or download contains the complete report.</p>}
      <div className="report-card"><div className="report-topline"><span><Braces size={16}/> findings.json</span><span>application/json</span></div><pre><JsonView value={preview}/></pre></div>
    </section>
  </main></SiteChrome>;
}
