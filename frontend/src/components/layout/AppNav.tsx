import React from "react";
import { UploadCloud, LayoutDashboard, GitBranch, Table2, FileSearch, HelpCircle, HardDrive, FileText } from "lucide-react";
import { LedIndicator } from "../common/LedIndicator";
import { TactileButton } from "../common/TactileButton";

export type AppPage = "landing" | "ingestion" | "overview" | "sessions" | "detail" | "correlations" | "report";

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
  { page: "ingestion",     label: "INGESTION BAY", icon: <UploadCloud size={13} /> },
  { page: "overview",      label: "TELEMETRY",     icon: <LayoutDashboard size={13} />, dashboardOnly: true },
  { page: "sessions",      label: "SWITCHBOARD",   icon: <Table2 size={13} />,          dashboardOnly: true },
  { page: "detail",        label: "DISSECTOR",     icon: <FileSearch size={13} />,       dashboardOnly: true },
  { page: "correlations",  label: "RADAR C2",      icon: <GitBranch size={13} />,        dashboardOnly: true },
  { page: "report",        label: "SUMMARY REPORT", icon: <FileText size={13} />,        dashboardOnly: true },
];

export const AppNav: React.FC<AppNavProps> = ({
  currentPage,
  onNavigate,
  analysisFilename,
  isMockMode,
  onOpenShortcuts,
  triageTimerSeconds,
}) => {
  const inDashboard = ["overview", "sessions", "detail", "correlations", "report"].includes(currentPage);

  return (
    <header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 200,
        background: "var(--chassis)",
        borderBottom: "1px solid #babecc",
        boxShadow: "0 6px 14px rgba(186,190,204,0.6), inset 0 1px 0 #ffffff",
        padding: "0 20px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        height: 60,
      }}
    >
      {/* Brand / Unit Identifier */}
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <button
          onClick={() => onNavigate("landing")}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            background: "var(--chassis)",
            border: "1px solid rgba(255,255,255,0.7)",
            boxShadow: "var(--shadow-card)",
            borderRadius: 10,
            padding: "6px 14px",
            cursor: "pointer",
            transition: "all 150ms var(--ease-spring)",
          }}
          className="tactile-btn"
          title="Return to System Root"
        >
          <img
            src="/relic-logo.png"
            alt=""
            style={{ width: 22, height: 22, objectFit: "contain", filter: "drop-shadow(0 1px 1px rgba(0,0,0,0.2))" }}
          />
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", lineHeight: 1.1 }}>
            <span
              style={{
                fontFamily: "var(--font-sans)",
                fontWeight: 800,
                fontSize: 13,
                letterSpacing: "0.08em",
                color: "var(--text-primary)",
                textTransform: "uppercase",
              }}
              className="text-embossed-light"
            >
              RELIC-01
            </span>
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 9,
                fontWeight: 600,
                color: "var(--accent)",
                letterSpacing: "0.12em",
                textTransform: "uppercase",
              }}
            >
              PECFF CONSOLE
            </span>
          </div>
        </button>

        {/* Ventilation slot detail */}
        <div className="vent-grille" style={{ display: "none" }}>
          <div className="vent-slot" />
          <div className="vent-slot" />
        </div>
      </div>

      {/* Rack Selector Push Keys */}
      <nav style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {NAV_ITEMS.map((item) => {
          const active = currentPage === item.page;
          const disabled = item.dashboardOnly && !inDashboard && item.page !== currentPage;

          return (
            <button
              key={item.page}
              onClick={() => !disabled && onNavigate(item.page)}
              disabled={disabled}
              className={`tactile-btn ${active ? "tactile-btn-pressed" : "tactile-btn-chassis"}`}
              style={{
                padding: "8px 14px",
                fontSize: 11,
                opacity: disabled ? 0.35 : 1,
                cursor: disabled ? "not-allowed" : "pointer",
                border: active ? "1px solid rgba(0,0,0,0.08)" : "1px solid rgba(255,255,255,0.6)",
                color: active ? "var(--accent)" : "var(--text-secondary)",
              }}
            >
              {item.icon}
              <span>{item.label}</span>
              {active && (
                <span
                  style={{
                    width: 5,
                    height: 5,
                    borderRadius: "50%",
                    background: "var(--accent)",
                    boxShadow: "var(--glow-orange)",
                    marginLeft: 2,
                  }}
                />
              )}
            </button>
          );
        })}
      </nav>

      {/* Telemetry Readout & System Status */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {inDashboard && analysisFilename && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 14px",
              borderRadius: 8,
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--text-primary)",
            }}
          >
            <HardDrive size={13} color="var(--accent)" />
            <span
              style={{
                maxWidth: 160,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                fontWeight: 600,
              }}
            >
              {analysisFilename}
            </span>
            {isMockMode && (
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 700,
                  background: "var(--chassis)",
                  color: "var(--accent)",
                  borderRadius: 4,
                  padding: "1px 5px",
                  boxShadow: "1px 1px 2px rgba(0,0,0,0.1)",
                  border: "1px solid rgba(255,255,255,0.8)",
                }}
              >
                MOCK
              </span>
            )}
          </div>
        )}

        {inDashboard && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 12px",
              borderRadius: 8,
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              fontWeight: 700,
              color: "var(--text-primary)",
            }}
          >
            <LedIndicator status="green" pulse={true} size="sm" />
            <span style={{ letterSpacing: "0.06em" }}>{formatTimer(triageTimerSeconds)}</span>
          </div>
        )}

        <LedIndicator status="orange" label="SYS ONLINE" size="sm" />

        {onOpenShortcuts && (
          <TactileButton
            variant="chassis"
            size="sm"
            onClick={onOpenShortcuts}
            title="Operator Manual / Keyboard Shortcuts (?)"
            style={{ padding: "8px 10px" }}
          >
            <HelpCircle size={14} color="var(--text-secondary)" />
          </TactileButton>
        )}
      </div>
    </header>
  );
};
