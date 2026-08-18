import React, { useEffect, useMemo, useReducer, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  Braces,
  Check,
  ChevronRight,
  Clipboard,
  Copy,
  Cpu,
  Database,
  FileCode2,
  FileSearch,
  Gauge,
  GitBranch,
  LockKeyhole,
  Network,
  Play,
  Radar,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TimerReset,
  TriangleAlert,
  Upload,
  Workflow,
  Zap,
} from "lucide-react";
import {
  analysisPhases,
  demoAlerts,
  demoFlows,
  demoSummary,
  detectorExplainers,
  demoRunReducer,
  getDemoRunState,
  initialDemoRun,
  policies,
  reportJson,
} from "@/data/netguardDemo";

const stats = [
  { label: "Input packets", value: demoSummary.inputPackets.toString(), note: "campus_edge_sample.pcap", icon: Database, accent: "blue" },
  { label: "Parsed cleanly", value: demoSummary.parsedPackets.toString(), note: "100% IPv4 / TCP / UDP", icon: ScanSearch, accent: "mint" },
  { label: "Forwarded", value: demoSummary.forwardedPackets.toString(), note: `${demoSummary.droppedPackets} policy drops`, icon: ArrowDownRight, accent: "violet" },
  { label: "Active flows", value: demoSummary.activeFlows.toString(), note: "5-tuple flow affinity", icon: GitBranch, accent: "amber" },
  { label: "Throughput", value: `${demoSummary.throughput}`, suffix: "MB/s", note: "4 worker threads", icon: Gauge, accent: "blue" },
  { label: "Alerts", value: demoSummary.alerts.toString(), note: "3 high-priority findings", icon: ShieldAlert, accent: "coral" },
];

const pipeline = [
  { label: "Reader", description: "PCAP records", icon: FileSearch, tone: "blue" },
  { label: "Dispatcher", description: "5-tuple hash", icon: Workflow, tone: "violet" },
  { label: "Workers", description: "Flows & detectors", icon: Cpu, tone: "mint" },
  { label: "Output", description: "PCAP + JSON", icon: FileCode2, tone: "amber" },
];

function SectionHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return (
    <div className="section-heading">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}

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

export default function Home() {
  const [demoRun, dispatchDemoRun] = useReducer(demoRunReducer, initialDemoRun);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (demoRun.status !== "running") return;
    const timer = window.setTimeout(() => {
      dispatchDemoRun({ type: "advance", amount: demoRun.progress < 70 ? 9 : 6 });
    }, 280);
    return () => window.clearTimeout(timer);
  }, [demoRun]);

  const isRunning = demoRun.status === "running";
  const isComplete = demoRun.status === "complete";
  const progress = demoRun.progress;
  const runState = getDemoRunState(progress);
  const phaseIndex = runState.phaseIndex;

  const startDemo = () => {
    dispatchDemoRun({ type: "start" });
    window.setTimeout(() => document.getElementById("demo")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  };

  const copyReport = async () => {
    await navigator.clipboard?.writeText(reportJson);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1700);
  };

  return (
    <div className="netguard-app">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="topbar">
        <a className="brand" href="#top" aria-label="NetGuard home">
          <span className="brand-mark"><ShieldCheck size={18} strokeWidth={2.5} /></span>
          <span>NetGuard</span>
        </a>
        <nav className="desktop-nav" aria-label="Primary navigation">
          <a href="#demo">Demo</a>
          <a href="#findings">Findings</a>
          <a href="#architecture">Architecture</a>
          <a href="#report">Report</a>
        </nav>
        <span className="status-chip"><span className="live-dot" /> demo environment</span>
      </header>

      <main id="top">
        <section className="hero shell">
          <div className="hero-copy">
            <div className="signal-label"><span className="signal-line" /> EXPLAINABLE NETWORK INTELLIGENCE</div>
            <h1>See the <em>why</em><br />behind every packet.</h1>
            <p className="hero-description">NetGuard transforms raw PCAP traffic into explainable threat findings, policy decisions, and evidence an analyst can act on.</p>
            <div className="hero-actions">
              <button type="button" className="primary-button" onClick={startDemo}>
                <Play size={17} fill="currentColor" />
                Run Demo Analysis
              </button>
              <a className="ghost-button" href="#architecture">Explore the pipeline <ArrowRight size={16} /></a>
            </div>
            <div className="hero-proof">
              <div><strong>77</strong><span>packets analyzed</span></div>
              <div><strong>4</strong><span>flow-affine workers</span></div>
              <div><strong>3</strong><span>explainable alerts</span></div>
            </div>
          </div>

          <div className="hero-console" aria-label="NetGuard analysis preview">
            <div className="console-topline"><span><span className="terminal-dot red" /><span className="terminal-dot yellow" /><span className="terminal-dot green" /></span><span>netguard / live-preview</span><span className="secure-label"><LockKeyhole size={12} /> sandbox</span></div>
            <div className="console-body">
              <div className="console-command"><span className="terminal-prompt">›</span> netguard analyze <strong>campus_edge_sample.pcap</strong></div>
              <div className="console-divider" />
              <div className="console-grid">
                <div className="console-flow"><span className="console-kicker">FLOW ANALYSIS</span><div className="flow-path"><i /><i /><i /><i /><i /><i /></div><span className="console-muted">5-tuple affinity preserved</span></div>
                <div className="mini-alert"><span className="mini-alert-icon"><TriangleAlert size={15} /></span><div><b>High risk flow</b><span>10.0.0.10 → 10.0.0.30</span></div><strong>45</strong></div>
              </div>
              <div className="console-log"><span className="log-ok">✓</span> structured evidence ready <span className="cursor" /></div>
            </div>
          </div>
        </section>

        <section className="trust-strip shell" aria-label="NetGuard capabilities">
          <span><Radar size={16} /> Behavioral detection</span>
          <span><Workflow size={16} /> Flow-aware concurrency</span>
          <span><Braces size={16} /> Explainable JSON</span>
          <span><ShieldCheck size={16} /> Policy enforcement</span>
        </section>

        <section id="demo" className="shell section demo-section">
          <SectionHeading eyebrow="Interactive sample" title="Run the investigation, end to end." description="A consistent NetGuard sample PCAP analysis—from capture ingestion to filtered output and evidence." action={<span className="sample-chip"><Upload size={14} /> campus_edge_sample.pcap</span>} />
          <div className="analysis-stage">
            <div className="analysis-left">
              <div className="analysis-eyebrow" role="status" aria-live="polite"><span className={isRunning ? "pulse-icon running" : "pulse-icon"}><Activity size={15} /></span>{isComplete ? "Analysis complete" : isRunning ? "Analysis in progress" : "Ready to analyze"}</div>
              <h3>{isComplete ? "Evidence assembled. Decisions explained." : isRunning ? analysisPhases[phaseIndex].label : "Ready when you are."}</h3>
              <p>{isComplete ? "The sample run produced a filtered PCAP and a complete JSON investigation report." : isRunning ? analysisPhases[phaseIndex].detail : "Use the sample capture to walk a reviewer through the full NetGuard decision pipeline."}</p>
              <div className="analysis-actions">
                <button type="button" className="primary-button compact" onClick={startDemo} disabled={isRunning}>
                  {isRunning ? <><TimerReset size={16} /> Analyzing…</> : <><Play size={16} fill="currentColor" /> {isComplete ? "Run Again" : "Run Demo Analysis"}</>}
                </button>
                <span className="execution-note"><Zap size={14} /> {isComplete ? "1.0 ms sample run" : "Offline PCAP simulation"}</span>
              </div>
            </div>
            <div className="analysis-right">
              <div className="progress-caption"><span>Analysis lifecycle</span><strong>{isComplete ? "100" : progress}%</strong></div>
              <div className="progress-track" role="progressbar" aria-label="Demo analysis progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={isComplete ? 100 : progress}><span style={{ width: `${isComplete ? 100 : progress}%` }} /></div>
              <div className="phase-list">
                {analysisPhases.map((phase, index) => {
                  const complete = isComplete || progress >= phase.checkpoint;
                  const active = isRunning && index === phaseIndex;
                  return <div className={`phase-row ${complete ? "complete" : ""} ${active ? "active" : ""}`} key={phase.label}><span className="phase-state">{complete ? <Check size={12} /> : index + 1}</span><div><b>{phase.label}</b><small>{phase.detail}</small></div>{active && <span className="phase-pulse" />}</div>;
                })}
              </div>
            </div>
          </div>
        </section>

        <section id="findings" className="shell section">
          <SectionHeading eyebrow="Analysis summary" title="Clear operational signal, at a glance." description="The sample run reconciles every packet and surfaces the context that matters most." />
          <div className="stats-grid">
            {stats.map((stat) => {
              const Icon = stat.icon;
              return <article className={`stat-card ${stat.accent}`} key={stat.label}><div className="stat-icon"><Icon size={18} /></div><span>{stat.label}</span><strong>{stat.value}{stat.suffix && <small>{stat.suffix}</small>}</strong><p>{stat.note}</p></article>;
            })}
          </div>
        </section>

        <section className="shell section split-section">
          <div className="feed-panel">
            <SectionHeading eyebrow="Threat feed" title="Every alert comes with evidence." description="NetGuard presents a detector decision, risk signal, and supporting context—not just a label." action={<span className="count-badge">3 findings</span>} />
            <div className="alert-list">
              {demoAlerts.map((alert, index) => <article className="alert-card" key={alert.detector}>
                <div className="alert-index">0{index + 1}</div>
                <div className="alert-main">
                  <div className="alert-title-row"><span className={`severity-badge ${alert.severity}`}>{alert.severity}</span><code>{alert.detector}</code><span className="risk-score">risk {alert.score}</span></div>
                  <p>{alert.explanation}</p>
                  <div className="ip-route"><span>{alert.sourceIp}</span><ArrowRight size={14} /><span>{alert.destinationIp}{alert.destinationPort ? `:${alert.destinationPort}` : ""}</span></div>
                  {alert.domain && <div className="domain-line"><Network size={13} /> {alert.domain}</div>}
                  <div className="evidence-grid">{alert.evidence.map(([key, value]) => <div key={key}><small>{key.replaceAll("_", " ")}</small><b>{value}</b></div>)}</div>
                </div>
              </article>)}
            </div>
          </div>
          <aside className="policy-panel">
            <div className="policy-head"><span className="eyebrow">Policy enforcement</span><span className="shield-orb"><ShieldCheck size={18} /></span></div>
            <h3>7 packets stopped<br />by explicit policy.</h3>
            <p>Every dropped packet is attributed to a normalized rule, preserving a clear audit trail.</p>
            <div className="policy-rules">
              {policies.map((policy) => <div className="policy-rule" key={policy.rule}><div className="policy-rule-top"><span>{policy.type}</span><b>{policy.dropped} dropped</b></div><strong>{policy.rule}</strong><small>{policy.description}</small><div className="rule-meter"><span style={{ width: `${(policy.dropped / demoSummary.droppedPackets) * 100}%` }} /></div></div>)}
            </div>
            <div className="policy-footer"><LockKeyhole size={15} /><span>Filtered output preserves original packet ordering.</span></div>
          </aside>
        </section>

        <section className="shell section flow-section">
          <SectionHeading eyebrow="Flow analysis" title="State is kept where the work happens." description="A bidirectional 5-tuple stays on one worker, avoiding a global lock on each packet." action={<span className="table-caption">Showing 6 of 27 active flows</span>} />
          <div className="flow-table-wrap">
            <table className="flow-table">
              <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Domain</th><th>Application</th><th>State</th></tr></thead>
              <tbody>{demoFlows.map((flow) => <tr key={`${flow.source}-${flow.destination}`}><td>{flow.source}</td><td>{flow.destination}</td><td><span className={`protocol ${flow.protocol.toLowerCase()}`}>{flow.protocol}</span></td><td>{flow.packets}</td><td>{flow.bytes}</td><td className="domain-cell">{flow.domain}</td><td>{flow.app}</td><td><span className={`flow-state ${flow.state.toLowerCase()}`}>{flow.state}</span></td></tr>)}</tbody>
            </table>
          </div>
        </section>

        <section id="architecture" className="architecture-section">
          <div className="shell architecture-shell">
            <SectionHeading eyebrow="Concurrent architecture" title="Reader → Dispatcher → Workers → Output" description="The pipeline applies controlled backpressure, retains per-flow state, and restores the original packet order before writing results." />
            <div className="pipeline-card">
              <div className="pipeline-rail"><span className="moving-signal one" /><span className="moving-signal two" /><span className="moving-signal three" /></div>
              <div className="pipeline-nodes">{pipeline.map((stage, index) => { const Icon = stage.icon; return <div className="pipeline-node-wrap" key={stage.label}><article className={`pipeline-node ${stage.tone}`}><span className="pipeline-icon"><Icon size={20} /></span><b>{stage.label}</b><small>{stage.description}</small></article>{index < pipeline.length - 1 && <ChevronRight className="pipeline-chevron" size={20} />}</div>; })}</div>
              <div className="architecture-notes"><span><Check size={14} /> bounded queues</span><span><Check size={14} /> flow-affine workers</span><span><Check size={14} /> ordered output</span></div>
            </div>
          </div>
        </section>

        <section id="report" className="shell section report-section">
          <SectionHeading eyebrow="Evidence output" title="Human-readable in the UI. Machine-readable everywhere else." description="The same structured NetGuard report used for downstream automation is available for analyst review." action={<button type="button" className="copy-button" onClick={copyReport}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? "Copied" : "Copy JSON"}</button>} />
          <div className="report-card">
            <div className="report-topline"><span><Braces size={16} /> findings.json</span><span>application/json</span></div>
            <pre><JsonView value={reportJson} /></pre>
          </div>
        </section>

        <section className="shell section detector-section">
          <SectionHeading eyebrow="Detector playbook" title="Thresholds are explicit, configurable, and explainable." description="NetGuard uses behavioral signals that can be calibrated to an environment instead of hard-coded judgments." />
          <div className="detector-grid">{detectorExplainers.map((detector) => <article className="detector-card" key={detector.slug}><div className="detector-card-top"><span>{detector.key}</span><Radar size={17} /></div><h3>{detector.name}</h3><code>{detector.slug}</code><p>{detector.description}</p><div className="detector-metric"><span>{detector.metric}</span><ArrowRight size={14} /></div><pre>{detector.example}</pre></article>)}</div>
        </section>

        <section className="closing shell">
          <div><span className="eyebrow">Ready for the review room</span><h2>From packets to a decision<br />you can defend.</h2></div>
          <button type="button" className="primary-button" onClick={startDemo}><Play size={17} fill="currentColor" />Run Demo Analysis</button>
        </section>
      </main>
      <footer className="shell footer"><span className="brand"><span className="brand-mark"><ShieldCheck size={16} /></span>NetGuard</span><span>Explainable network threat detection engine</span><span>Demo data is deterministic and internally consistent.</span></footer>
    </div>
  );
}
