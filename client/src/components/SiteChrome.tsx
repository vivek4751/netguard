import React from "react";
import { ChevronDown, ShieldCheck } from "lucide-react";
import { Link } from "wouter";

type SiteChromeProps = {
  children: React.ReactNode;
};

export default function SiteChrome({ children }: SiteChromeProps) {
  return (
    <div className="netguard-app">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="topbar">
        <Link className="brand" href="/" aria-label="NetGuard home">
          <span className="brand-mark"><ShieldCheck size={18} strokeWidth={2.5} /></span>
          <span>NetGuard</span>
        </Link>
        <nav className="desktop-nav" aria-label="Primary navigation">
          <Link href="/">Overview</Link>
          <Link href="/analysis">Analysis</Link>
          <Link href="/architecture">Architecture</Link>
          <Link href="/report">Report</Link>
        </nav>
        <details className="mobile-menu">
          <summary aria-label="Open navigation"><ChevronDown size={17} /></summary>
          <div>
            <Link href="/">Overview</Link>
            <Link href="/analysis">Analysis</Link>
            <Link href="/architecture">Architecture</Link>
            <Link href="/report">Report</Link>
          </div>
        </details>
        <span className="status-chip"><span className="live-dot" /> demo environment</span>
      </header>
      {children}
      <footer className="shell footer"><span className="brand"><span className="brand-mark"><ShieldCheck size={16} /></span>NetGuard</span><span>Explainable network threat detection engine</span><span>Demo data is deterministic and internally consistent.</span></footer>
    </div>
  );
}
