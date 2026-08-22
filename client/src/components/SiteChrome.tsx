import React from "react";
import { ChevronDown, CircleDot, ShieldCheck } from "lucide-react";
import { Link } from "wouter";

export default function SiteChrome({ children }: { children: React.ReactNode }) {
  return (
    <div className="netguard-app">
      <header className="topbar">
        <div className="topbar-inner">
          <Link className="brand" href="/" aria-label="NetGuard home">
            <span className="brand-mark"><ShieldCheck size={19} strokeWidth={2.4} /></span>
            <span><strong>NetGuard</strong><small>Network analysis project</small></span>
          </Link>
          <nav className="desktop-nav" aria-label="Primary navigation">
            <Link href="/">Overview</Link>
            <Link href="/analysis">Analysis</Link>
            <Link href="/architecture">Architecture</Link>
            <Link href="/report">Report</Link>
          </nav>
          <details className="mobile-menu">
            <summary aria-label="Open navigation"><ChevronDown size={18} /></summary>
            <div>
              <Link href="/">Overview</Link>
              <Link href="/analysis">Analysis</Link>
              <Link href="/architecture">Architecture</Link>
              <Link href="/report">Report</Link>
            </div>
          </details>
          <span className="status-chip"><CircleDot size={14} /> Demo mode</span>
        </div>
      </header>
      {children}
      <footer className="footer"><div><strong>NetGuard</strong><span>Student systems project · C++17</span></div><span>PCAP analysis, flow tracking, threat heuristics, JSON reporting</span></footer>
    </div>
  );
}
