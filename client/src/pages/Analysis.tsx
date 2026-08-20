import React from "react";
import { ArrowRight, LockKeyhole, Network, ShieldAlert, ShieldCheck } from "lucide-react";
import SiteChrome from "@/components/SiteChrome";
import { demoAlerts, demoFlows, demoSummary, policies } from "@/data/netguardDemo";

const stats = [
  ["Input packets", demoSummary.inputPackets, "Sample PCAP intake"],
  ["Forwarded", demoSummary.forwardedPackets, `${demoSummary.droppedPackets} policy drops`],
  ["Active flows", demoSummary.activeFlows, "5-tuple affinity"],
  ["Throughput", `${demoSummary.throughput} MB/s`, "4 worker threads"],
];

export default function Analysis() {
  return (
    <SiteChrome>
      <main className="shell detail-page">
        <section className="page-intro">
          <span className="eyebrow">Analysis workspace</span>
          <h1>From a packet capture to <em>defensible findings.</em></h1>
          <p>This dedicated view holds the NetGuard sample run: packet accounting, detector evidence, active flows, and the policy decision ledger.</p>
        </section>

        <section className="detail-block">
          <div className="detail-block-head"><div><span className="eyebrow">Run summary</span><h2>Operational context first.</h2></div><span className="status-chip"><ShieldCheck size={13} /> accounting reconciled</span></div>
          <div className="mini-stat-grid">{stats.map(([label, value, note]) => <article className="mini-stat" key={label as string}><span>{label}</span><strong>{value}</strong><small>{note}</small></article>)}</div>
        </section>

        <section className="detail-block">
          <div className="detail-block-head"><div><span className="eyebrow">Threat feed</span><h2>Three findings, each with evidence.</h2></div><span className="count-badge">3 high-priority alerts</span></div>
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
        </section>

        <section className="detail-block">
          <div className="detail-block-head"><div><span className="eyebrow">Flow analysis</span><h2>State remains with the worker that owns it.</h2></div><span className="table-caption">6 of {demoSummary.activeFlows} flows shown</span></div>
          <div className="flow-table-wrap"><table className="flow-table"><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Domain</th><th>Application</th><th>State</th></tr></thead><tbody>{demoFlows.map((flow) => <tr key={`${flow.source}-${flow.destination}`}><td>{flow.source}</td><td>{flow.destination}</td><td><span className={`protocol ${flow.protocol.toLowerCase()}`}>{flow.protocol}</span></td><td>{flow.packets}</td><td>{flow.bytes}</td><td className="domain-cell">{flow.domain}</td><td>{flow.app}</td><td><span className={`flow-state ${flow.state.toLowerCase()}`}>{flow.state}</span></td></tr>)}</tbody></table></div>
        </section>

        <section className="policy-ledger">
          <div><span className="eyebrow">Policy enforcement</span><h2>Seven packets stopped by explicit policy.</h2><p>Policy matches remain visible and reviewable, instead of becoming invisible drop events.</p></div>
          <div className="policy-rules">{policies.map((policy) => <article className="policy-rule" key={policy.rule}><div className="policy-rule-top"><span>{policy.type}</span><b>{policy.dropped} dropped</b></div><strong>{policy.rule}</strong><small>{policy.description}</small><div className="rule-meter"><span style={{ width: `${(policy.dropped / demoSummary.droppedPackets) * 100}%` }} /></div></article>)}</div>
          <div className="policy-footer"><LockKeyhole size={15} /><span>Filtered output preserves original packet ordering.</span></div>
        </section>
      </main>
    </SiteChrome>
  );
}
