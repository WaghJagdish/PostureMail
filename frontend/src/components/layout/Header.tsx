import React from "react";
import { Activity, HelpCircle, UploadCloud, Terminal, CheckCircle2 } from "lucide-react";

interface HeaderProps {
  currentAnalysisId: string;
  onNewUpload: () => void;
  onOpenShortcuts: () => void;
  isMockMode: boolean;
  onToggleMockMode: () => void;
  activeTab: string;
  triageTimerSeconds: number;
}

export const Header: React.FC<HeaderProps> = ({
  currentAnalysisId,
  onNewUpload,
  onOpenShortcuts,
  isMockMode,
  onToggleMockMode,
  triageTimerSeconds,
}) => {
  const formatTimer = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  };

  return (
    <header className="glass-panel" style={{ margin: "12px 16px 8px 16px", padding: "10px 18px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      {/* Brand */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <img src="/relic-logo.png" alt="Relic" style={{ width: 32, height: 32, objectFit: "contain" }} />
        <img src="/relic-wordmark.png" alt="RELIC" style={{ height: 22, width: "auto", objectFit: "contain" }} />
        <span style={{ fontSize: "11px", background: "rgba(30, 111, 200, 0.1)", color: "#1e6fc8", border: "1px solid rgba(30, 111, 200, 0.25)", padding: "1px 6px", borderRadius: 4, fontWeight: 700 }}>
          FORENSIC CONSOLE
        </span>
      </div>

      {/* Center Triage Timer & Target */}
      <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(0, 0, 0, 0.3)", padding: "4px 12px", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
          <Activity size={14} color="#38bdf8" />
          <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Active Capture:</span>
          <span className="font-mono" style={{ fontSize: "12px", fontWeight: 600, color: "#f8fafc" }}>
            {currentAnalysisId}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "6px", background: "rgba(16, 185, 129, 0.1)", padding: "4px 10px", borderRadius: 6, border: "1px solid rgba(16, 185, 129, 0.25)" }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981", display: "inline-block" }} className="pulse-active" />
          <span style={{ fontSize: "11px", color: "#10b981", fontWeight: 600 }}>Triage Timer:</span>
          <span className="font-mono" style={{ fontSize: "12px", fontWeight: 700, color: "#10b981" }}>
            {formatTimer(triageTimerSeconds)}
          </span>
        </div>
      </div>

      {/* Right Controls */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <button
          onClick={onToggleMockMode}
          className="btn btn-secondary btn-sm"
          title="Toggle between Live API and 1,000-session demo corpus"
          style={{ fontSize: "11.5px" }}
        >
          {isMockMode ? (
            <>
              <CheckCircle2 size={13} color="#38bdf8" />
              <span>1k Session Demo</span>
            </>
          ) : (
            <>
              <Terminal size={13} color="#10b981" />
              <span>Live Engine API</span>
            </>
          )}
        </button>

        <button onClick={onNewUpload} className="btn btn-primary btn-sm" style={{ gap: "5px" }}>
          <UploadCloud size={14} />
          <span>Ingest PCAP</span>
        </button>

        <button
          onClick={onOpenShortcuts}
          className="btn btn-secondary btn-sm"
          style={{ padding: "6px 8px" }}
          title="Keyboard Shortcuts (Press ?)"
          aria-label="Keyboard Shortcuts"
        >
          <HelpCircle size={15} />
        </button>
      </div>
    </header>
  );
};
