import React from "react";
import { Check, ChevronRight, Cpu, Database, FileCode2, FileSearch, Radar, Workflow } from "lucide-react";
import SiteChrome from "@/components/SiteChrome";
import { detectorExplainers } from "@/data/netguardDemo";

const pipeline = [
  { label: "Reader", description: "PCAP records", icon: FileSearch, tone: "blue" },
  { label: "Dispatcher", description: "5-tuple hash", icon: Workflow, tone: "violet" },
  { label: "Workers", description: "Flows & detectors", icon: Cpu, tone: "mint" },
  { label: "Output", description: "PCAP + JSON", icon: FileCode2, tone: "amber" },
];

export default function Architecture() {
  return (
    <SiteChrome>
      <main className="shell detail-page architecture-page">
        <section className="page-intro">
          <span className="eyebrow">System design</span>
          <h1>Concurrency that protects <em>flow context.</em></h1>
          <p>NetGuard keeps packets from the same bidirectional flow on the same worker, so behavioral detection stays consistent without a global lock for every update.</p>
        </section>
        <section className="detail-block architecture-detail">
          <div className="detail-block-head"><div><span className="eyebrow">Concurrent pipeline</span><h2>Reader → Dispatcher → Workers → Output</h2></div><span className="status-chip"><Database size={13} /> 77 ordered records</span></div>
          <div className="pipeline-card">
            <div className="pipeline-rail"><span className="moving-signal one" /><span className="moving-signal two" /><span className="moving-signal three" /></div>
            <div className="pipeline-nodes">{pipeline.map((stage, index) => { const Icon = stage.icon; return <div className="pipeline-node-wrap" key={stage.label}><article className={`pipeline-node ${stage.tone}`}><span className="pipeline-icon"><Icon size={20} /></span><b>{stage.label}</b><small>{stage.description}</small></article>{index < pipeline.length - 1 && <ChevronRight className="pipeline-chevron" size={20} />}</div>; })}</div>
            <div className="architecture-notes"><span><Check size={14} /> bounded queues</span><span><Check size={14} /> flow-affine workers</span><span><Check size={14} /> ordered output</span></div>
          </div>
        </section>
        <section className="detail-block">
          <div className="detail-block-head"><div><span className="eyebrow">Detector playbook</span><h2>Every threshold is explicit.</h2></div><span className="table-caption">Environment-calibrated heuristics</span></div>
          <div className="detector-grid">{detectorExplainers.map((detector) => <article className="detector-card" key={detector.slug}><div className="detector-card-top"><span>{detector.key}</span><Radar size={17} /></div><h3>{detector.name}</h3><code>{detector.slug}</code><p>{detector.description}</p><div className="detector-metric"><span>{detector.metric}</span><ChevronRight size={14} /></div><pre>{detector.example}</pre></article>)}</div>
        </section>
      </main>
    </SiteChrome>
  );
}
