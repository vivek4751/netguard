import React, { useEffect, useReducer } from "react";
import { Activity, ArrowRight, Braces, Check, ChevronDown, Cpu, FileCode2, Play, Radar, ShieldAlert, ShieldCheck, TimerReset, Workflow, Zap } from "lucide-react";
import { Link } from "wouter";
import SiteChrome from "@/components/SiteChrome";
import { analysisPhases, demoRunReducer, demoSummary, getDemoRunState, initialDemoRun } from "@/data/netguardDemo";

const overviewItems = [
  { title: "Findings & flows", description: "Alert evidence, flow-level context, and policy decisions from the sample run.", icon: ShieldAlert, href: "/analysis", metrics: ["3 detector findings", "27 active flows", "7 policy drops"] },
  { title: "Engine architecture", description: "See how bounded queues and flow-affine workers preserve inspection context.", icon: Workflow, href: "/architecture", metrics: ["4 pipeline stages", "4 worker threads", "Ordered output"] },
  { title: "Evidence report", description: "Inspect or copy the JSON artifact that NetGuard emits for downstream automation.", icon: FileCode2, href: "/report", metrics: ["JSON schema", "3 alert records", "Replayable evidence"] },
];

export default function Home() {
  const [demoRun, dispatchDemoRun] = useReducer(demoRunReducer, initialDemoRun);
  const isRunning = demoRun.status === "running";
  const isComplete = demoRun.status === "complete";
  const runState = getDemoRunState(demoRun.progress);
  const phaseIndex = runState.phaseIndex;

  useEffect(() => {
    if (!isRunning) return;
    const timer = window.setTimeout(() => dispatchDemoRun({ type: "advance", amount: demoRun.progress < 70 ? 9 : 6 }), 280);
    return () => window.clearTimeout(timer);
  }, [demoRun, isRunning]);

  const startDemo = () => {
    dispatchDemoRun({ type: "start" });
    window.setTimeout(() => document.getElementById("demo")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  };

  return (
    <SiteChrome>
      <main id="top">
        <section className="hero shell compact-hero">
          <div className="hero-copy">
            <div className="signal-label"><span className="signal-line" /> EXPLAINABLE NETWORK INTELLIGENCE</div>
            <h1>See the <em>why</em><br />behind every packet.</h1>
            <p className="hero-description">NetGuard turns raw PCAP traffic into clear threat findings, policy decisions, and evidence an analyst can defend.</p>
            <div className="hero-actions"><button type="button" className="primary-button" onClick={startDemo}><Play size={17} fill="currentColor" />Run Demo Analysis</button><Link className="ghost-button" href="/analysis">Open the analysis workspace <ArrowRight size={16} /></Link></div>
            <div className="hero-proof"><div><strong>{demoSummary.inputPackets}</strong><span>packets analyzed</span></div><div><strong>4</strong><span>flow-affine workers</span></div><div><strong>{demoSummary.alerts}</strong><span>explainable alerts</span></div></div>
          </div>
          <div className="hero-console" aria-label="NetGuard analysis preview"><div className="console-topline"><span><span className="terminal-dot red" /><span className="terminal-dot yellow" /><span className="terminal-dot green" /></span><span>netguard / live-preview</span><span className="secure-label"><ShieldCheck size={12} /> sandbox</span></div><div className="console-body"><div className="console-command"><span className="terminal-prompt">›</span> netguard analyze <strong>campus_edge_sample.pcap</strong></div><div className="console-divider" /><div className="console-grid"><div className="console-flow"><span className="console-kicker">FLOW ANALYSIS</span><div className="flow-path"><i /><i /><i /><i /><i /><i /></div><span className="console-muted">5-tuple affinity preserved</span></div><div className="mini-alert"><span className="mini-alert-icon"><ShieldAlert size={15} /></span><div><b>High risk flow</b><span>10.0.0.10 → 10.0.0.30</span></div><strong>45</strong></div></div><div className="console-log"><span className="log-ok">✓</span> structured evidence ready <span className="cursor" /></div></div></div>
        </section>

        <section id="demo" className="shell quick-demo">
          <div className="quick-demo-copy"><span className="eyebrow">Interactive sample</span><h2>{isComplete ? "Evidence assembled." : isRunning ? analysisPhases[phaseIndex].label : "Run a compact investigation."}</h2><p>{isComplete ? "The report, flow context, and policy ledger are ready to explore on their own pages." : isRunning ? analysisPhases[phaseIndex].detail : "Use the bundled capture to show NetGuard’s ingestion-to-evidence path in under a minute."}</p><button type="button" className="primary-button compact" onClick={startDemo} disabled={isRunning}>{isRunning ? <><TimerReset size={16} /> Analyzing…</> : <><Play size={16} fill="currentColor" /> {isComplete ? "Run Again" : "Run Demo Analysis"}</>}</button></div>
          <div className="quick-demo-progress"><div className="analysis-eyebrow" role="status" aria-live="polite"><span className={isRunning ? "pulse-icon running" : "pulse-icon"}><Activity size={15} /></span>{isComplete ? "Analysis complete" : isRunning ? "Analysis in progress" : "Ready to analyze"}</div><div className="progress-caption"><span>Analysis lifecycle</span><strong>{isComplete ? "100" : demoRun.progress}%</strong></div><div className="progress-track" role="progressbar" aria-label="Demo analysis progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={isComplete ? 100 : demoRun.progress}><span style={{ width: `${isComplete ? 100 : demoRun.progress}%` }} /></div><div className="phase-list">{analysisPhases.map((phase, index) => { const complete = isComplete || demoRun.progress >= phase.checkpoint; const active = isRunning && index === phaseIndex; return <div className={`phase-row ${complete ? "complete" : ""} ${active ? "active" : ""}`} key={phase.label}><span className="phase-state">{complete ? <Check size={12} /> : index + 1}</span><div><b>{phase.label}</b><small>{phase.detail}</small></div>{active && <span className="phase-pulse" />}</div>; })}</div></div>
        </section>

        <section className="shell overview-section">
          <div className="section-heading"><div><span className="eyebrow">Explore NetGuard</span><h2>Open only the detail you need.</h2><p>The overview stays focused. Expand a summary or continue into a dedicated workspace.</p></div></div>
          <div className="overview-list">{overviewItems.map((item) => { const Icon = item.icon; return <details className="overview-item" key={item.title}><summary><span className="overview-icon"><Icon size={19} /></span><div><strong>{item.title}</strong><small>{item.description}</small></div><ChevronDown size={18} /></summary><div className="overview-expanded"><div>{item.metrics.map((metric) => <span key={metric}>{metric}</span>)}</div><Link href={item.href}>Open {item.title} <ArrowRight size={15} /></Link></div></details>; })}</div>
        </section>

        <section className="trust-strip shell" aria-label="NetGuard capabilities"><span><Radar size={16} /> Behavioral detection</span><span><Workflow size={16} /> Flow-aware concurrency</span><span><Braces size={16} /> Explainable JSON</span><span><Cpu size={16} /> Focused workspaces</span></section>
      </main>
    </SiteChrome>
  );
}
