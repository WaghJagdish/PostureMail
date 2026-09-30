import React from "react";
import { UploadCloud, LayoutDashboard, GitBranch, Table2, FileSearch, HelpCircle, Activity } from "lucide-react";

export type AppPage = "landing" | "ingestion" | "overview" | "sessions" | "detail" | "correlations";

interface AppNavProps {
  currentPage: AppPage;
  onNavigate: (page: AppPage) => void;
  analysisFilename?: string;
  isMockMode: boolean;
  onOpenShortcuts?: () => void;
  triageTimerSeconds: number;
}

const formatTimer = (secs: number) => {
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
};

const NAV_ITEMS: { page: AppPage; label: string; icon: React.ReactNode; dashboardOnly?: boolean }[] = [
  { page: "ingestion",     label: "Ingest",        icon: <UploadCloud size={14} /> },
  { page: "overview",      label: "Dashboard",     icon: <LayoutDashboard size={14} />, dashboardOnly: true },
  { page: "sessions",      label: "Sessions",      icon: <Table2 size={14} />,          dashboardOnly: true },
  { page: "detail",        label: "Session Detail",icon: <FileSearch size={14} />,       dashboardOnly: true },
  { page: "correlations",  label: "Correlations",  icon: <GitBranch size={14} />,        dashboardOnly: true },
];

export const AppNav: React.FC<AppNavProps> = ({
  currentPage, onNavigate, analysisFilename, isMockMode, onOpenShortcuts, triageTimerSeconds,
}) => {
  const inDashboard = ["overview", "sessions", "detail", "correlations"].includes(currentPage);

  return (
    <nav style={{
      position: "sticky", top: 0, zIndex: 200,
      background: "rgba(255,255,255,0.96)", backdropFilter: "blur(16px)",
      borderBottom: "1px solid #dde2ee",
      padding: "0 24px",
      display: "flex", alignItems: "center", gap: 2,
      height: 54,
      boxShadow: "0 1px 6px rgba(13,27,46,0.07)",
    }}>
      {/* Brand */}
      <button onClick={() => onNavigate("landing")} style={{
        display: "flex", alignItems: "center", gap: 8,
        background: "none", border: "none", cursor: "pointer",
        padding: "5px 16px 5px 0",
        marginRight: 16,
        borderRight: "1px solid #dde2ee",
      }}>
        {/* R icon mark */}
        <img src="/relic-logo.png" alt="" style={{ width: 28, height: 28, objectFit: "contain", flexShrink: 0 }} />
        {/* Full wordmark */}
        <img src="/relic-wordmark.png" alt="Relic" style={{ height: 22, width: "auto", objectFit: "contain", display: "block" }} />
        {/* Subtitle */}
        <span style={{ fontSize: 9.5, fontWeight: 700, color: "#1e6fc8", letterSpacing: "0.1em", textTransform: "uppercase", borderLeft: "1px solid #dde2ee", paddingLeft: 10, whiteSpace: "nowrap" }}>
          Forensics
        </span>
      </button>

      {/* Nav links */}
      <div style={{ display: "flex", alignItems: "center", gap: 2, flex: 1 }}>
        {NAV_ITEMS.map((item) => {
          const active = currentPage === item.page;
          const disabled = item.dashboardOnly && !inDashboard && item.page !== currentPage;
          return (
            <button
              key={item.page}
              onClick={() => !disabled && onNavigate(item.page)}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "6px 13px", borderRadius: 7, border: "none",
                fontSize: 13, fontWeight: active ? 600 : 400,
                cursor: disabled ? "not-allowed" : "pointer",
                background: active ? "rgba(30,111,200,0.1)" : "transparent",
                color: active ? "#1e6fc8" : disabled ? "#c5cfe0" : "#3d566e",
                transition: "all 0.15s ease",
                opacity: disabled ? 0.5 : 1,
              }}
              onMouseEnter={e => { if (!active && !disabled) (e.currentTarget as HTMLElement).style.background = "#f4f6fb"; }}
              onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
            >
              {item.icon}
              {item.label}
            </button>
          );
        })}
      </div>

      {/* Right meta */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {inDashboard && analysisFilename && (
          <div style={{
            display: "flex", alignItems: "center", gap: 7,
            padding: "4px 12px", borderRadius: 7,
            background: "#f4f6fb", border: "1px solid #dde2ee",
            fontSize: 12, color: "#3d566e",
          }}>
            <Activity size={12} color="#1e6fc8" />
            <span className="font-mono" style={{
              fontWeight: 600, color: "#0d1b2e",
              maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {analysisFilename}
            </span>
            {isMockMode && (
              <span style={{
                fontSize: 10, background: "rgba(30,111,200,0.1)", color: "#1e6fc8",
                borderRadius: 4, padding: "1px 6px", fontWeight: 700, letterSpacing: "0.05em",
              }}>DEMO</span>
            )}
          </div>
        )}

        {inDashboard && (
          <div style={{
            display: "flex", alignItems: "center", gap: 6, padding: "4px 10px",
            borderRadius: 7, background: "#ecfdf5", border: "1px solid #a7f3d0",
            fontSize: 11.5, color: "#059669", fontWeight: 700, fontFamily: "JetBrains Mono, monospace",
          }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981", display: "inline-block" }} className="pulse-active" />
            {formatTimer(triageTimerSeconds)}
          </div>
        )}

        {onOpenShortcuts && (
          <button className="btn btn-ghost btn-sm" onClick={onOpenShortcuts} title="Keyboard Shortcuts (?)">
            <HelpCircle size={15} color="#7b93ab" />
          </button>
        )}
      </div>
    </nav>
  );
};
