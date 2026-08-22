import React, { useEffect, useReducer } from "react";
import { Activity, ArrowRight, Check, ChevronDown, Code2, FileCode2, GitBranch, Play, ShieldAlert, Terminal, TimerReset } from "lucide-react";
import { Link } from "wouter";
import SiteChrome from "@/components/SiteChrome";
import { analysisPhases, demoRunReducer, demoSummary, getDemoRunState, initialDemoRun } from "@/data/netguardDemo";

const overviewItems = [
  { title: "Detection results", description: "Review the sample run’s alerts, active flows, and policy decisions.", icon: ShieldAlert, href: "/analysis", metrics: ["3 findings", "27 flows", "7 dropped"] },
  { title: "System design", description: "Inspect the PCAP processing pipeline and flow-affine worker model.", icon: GitBranch, href: "/architecture", metrics: ["4 stages", "4 workers", "bounded queues"] },
  { title: "Output format", description: "View the JSON report produced for alerts and downstream tools.", icon: FileCode2, href: "/report", metrics: ["findings.json", "copyable output", "evidence fields"] },
];

export default function Home() {
  const [demoRun, dispatchDemoRun] = useReducer(demoRunReducer, initialDemoRun);
  const isRunning = demoRun.status === "running";
  const isComplete = demoRun.status === "complete";
  const runState = getDemoRunState(demoRun.progress);

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
      <main>
        <section className="project-header shell">
          <div className="project-copy">
            <span className="project-label">STUDENT PROJECT · NETWORK SECURITY · C++17</span>
            <h1>NetGuard: PCAP-based threat detection with explainable findings.</h1>
            <p>This project processes packet captures, groups traffic into flows, applies configurable security heuristics, and produces a readable JSON evidence report.</p>
            <div className="project-actions">
              <button type="button" className="primary-button" onClick={startDemo}><Play size={16} fill="currentColor" />Run Demo Analysis</button>
              <Link className="secondary-link" href="/analysis">View sample results <ArrowRight size={16} /></Link>
            </div>
            <div className="tech-list"><span><Code2 size={14} /> C++17 engine</span><span><Terminal size={14} /> CMake build</span><span><FileCode2 size={14} /> JSON output</span></div>
          </div>
          <aside className="project-run-card" aria-label="Project implementation summary">
            <div className="run-card-head"><span>DEMO INPUT</span><b>campus_edge_sample.pcap</b></div>
            <code>./netguard analyze campus_edge_sample.pcap</code>
            <div className="run-card-results"><div><strong>{demoSummary.inputPackets}</strong><span>packets</span></div><div><strong>{demoSummary.activeFlows}</strong><span>flows</span></div><div><strong>{demoSummary.alerts}</strong><span>alerts</span></div></div>
            <div className="validation-list" aria-label="Project validation results"><span><Check size={14} /> 7/7 tests passed</span><span><Check size={14} /> TypeScript check passed</span><span><Check size={14} /> Production build passed</span></div>
          </aside>
        </section>

        <section id="demo" className="demo-section shell">
          <div className="demo-heading"><div><span className="section-kicker">INTERACTIVE DEMO</span><h2>{isComplete ? "Analysis complete" : isRunning ? analysisPhases[runState.phaseIndex].label : "Run the included PCAP sample"}</h2><p>{isComplete ? "The sample output is ready. Use the pages below to inspect alerts, architecture, and JSON evidence." : isRunning ? analysisPhases[runState.phaseIndex].detail : "This simulates the project CLI processing a deterministic test capture."}</p></div><button type="button" className="primary-button compact" onClick={startDemo} disabled={isRunning}>{isRunning ? <><TimerReset size={16} /> Running…</> : <><Play size={16} fill="currentColor" />{isComplete ? "Run Again" : "Run Demo Analysis"}</>}</button></div>
          <div className="demo-panel">
            <div className="demo-progress"><div className="analysis-eyebrow" role="status" aria-live="polite"><Activity size={15} className={isRunning ? "active-icon" : ""} /> {isComplete ? "Completed" : isRunning ? "Processing capture" : "Ready"}</div><div className="progress-caption"><span>Progress</span><strong>{isComplete ? 100 : demoRun.progress}%</strong></div><div className="progress-track" role="progressbar" aria-label="Demo analysis progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={isComplete ? 100 : demoRun.progress}><span style={{ width: `${isComplete ? 100 : demoRun.progress}%` }} /></div></div>
            <div className="phase-list">{analysisPhases.map((phase, index) => { const done = isComplete || demoRun.progress >= phase.checkpoint; const active = isRunning && index === runState.phaseIndex; return <div className={`phase-row ${done ? "complete" : ""} ${active ? "active" : ""}`} key={phase.label}><span className="phase-state">{done ? <Check size={12} /> : index + 1}</span><div><b>{phase.label}</b><small>{phase.detail}</small></div></div>; })}</div>
          </div>
        </section>

        <section className="overview-section shell">
          <div className="section-title"><span className="section-kicker">PROJECT WORKSPACES</span><h2>Explore the implementation and output.</h2><p>Each section is kept separate so the project remains easy to present during a technical interview.</p></div>
          <div className="overview-list">{overviewItems.map((item) => { const Icon = item.icon; return <details className="overview-item" key={item.title}><summary><span className="overview-icon"><Icon size={18} /></span><div><strong>{item.title}</strong><small>{item.description}</small></div><ChevronDown size={18} /></summary><div className="overview-expanded"><div>{item.metrics.map((metric) => <span key={metric}>{metric}</span>)}</div><Link href={item.href}>Open section <ArrowRight size={15} /></Link></div></details>; })}</div>
        </section>
      </main>
    </SiteChrome>
  );
}
