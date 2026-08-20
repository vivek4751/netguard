import React, { useMemo, useState } from "react";
import { Braces, Check, Copy, FileCheck2, ShieldAlert } from "lucide-react";
import SiteChrome from "@/components/SiteChrome";
import { demoSummary, reportJson } from "@/data/netguardDemo";

function JsonView({ value }: { value: string }) {
  const tokenized = useMemo(() => {
    const tokenPattern = /("(?:\\.|[^"\\])*")(?=\s*:)|("(?:\\.|[^"\\])*")|(\btrue\b|\bfalse\b|\bnull\b)|(-?\d+(?:\.\d+)?)|([{}\[\],:])/g;
    return value.split("\n").map((line, lineIndex) => {
      const parts: React.ReactNode[] = [];
      let cursor = 0;
      let match: RegExpExecArray | null;
      while ((match = tokenPattern.exec(line)) !== null) {
        if (match.index > cursor) parts.push(line.slice(cursor, match.index));
        const className = match[1] ? "json-key" : match[2] ? "json-string" : match[3] ? "json-boolean" : match[4] ? "json-number" : "json-punctuation";
        parts.push(<span className={className} key={`${lineIndex}-${match.index}`}>{match[0]}</span>);
        cursor = match.index + match[0].length;
      }
      if (cursor < line.length) parts.push(line.slice(cursor));
      return <div className="json-line" key={lineIndex}>{parts.length ? parts : " "}</div>;
    });
  }, [value]);
  return <code className="json-code">{tokenized}</code>;
}

export default function Report() {
  const [copied, setCopied] = useState(false);
  const copyReport = async () => {
    await navigator.clipboard?.writeText(reportJson);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1700);
  };
  return (
    <SiteChrome>
      <main className="shell detail-page report-page">
        <section className="page-intro">
          <span className="eyebrow">Evidence output</span>
          <h1>One report for people<br />and <em>automation.</em></h1>
          <p>The exact structured JSON that powers the visual dashboard can also flow into a ticket, SIEM pipeline, or an analyst’s evidence store.</p>
        </section>
        <section className="report-summary-strip"><span><FileCheck2 size={16} /> {demoSummary.parsedPackets} packets parsed</span><span><ShieldAlert size={16} /> {demoSummary.alerts} evidence-backed alerts</span><span><Braces size={16} /> application/json</span></section>
        <section className="detail-block report-detail">
          <div className="detail-block-head"><div><span className="eyebrow">Findings artifact</span><h2>findings.json</h2></div><button type="button" className="copy-button" onClick={copyReport}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? "Copied" : "Copy JSON"}</button></div>
          <div className="report-card"><div className="report-topline"><span><Braces size={16} /> findings.json</span><span>application/json</span></div><pre><JsonView value={reportJson} /></pre></div>
        </section>
      </main>
    </SiteChrome>
  );
}
