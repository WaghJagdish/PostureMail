import React from "react";
import { UploadCloud, PieChart, Table2, ZoomIn, Network } from "lucide-react";

export type ViewTab = "upload" | "overview" | "sessions" | "detail" | "correlations";

interface TabsProps {
  activeTab: ViewTab;
  onSelectTab: (tab: ViewTab) => void;
  selectedSessionId: string | null;
  totalSessionsCount?: number;
  criticalFindingsCount?: number;
}

export const Tabs: React.FC<TabsProps> = ({
  activeTab,
  onSelectTab,
  selectedSessionId,
  totalSessionsCount = 0,
  criticalFindingsCount = 0,
}) => {
  const tabs = [
    { id: "upload" as ViewTab, label: "1. Ingest & Queue", icon: UploadCloud, hotkey: "1" },
    {
      id: "overview" as ViewTab,
      label: "2. Analysis Overview",
      icon: PieChart,
      hotkey: "2",
      badge: criticalFindingsCount > 0 ? `${criticalFindingsCount} Critical` : undefined,
      badgeColor: "#ef4444",
    },
    {
      id: "sessions" as ViewTab,
      label: "3. Session Triage",
      icon: Table2,
      hotkey: "3",
      badge: totalSessionsCount > 0 ? `${totalSessionsCount.toLocaleString()}` : undefined,
    },
    {
      id: "detail" as ViewTab,
      label: "4. Forensic Deep Dive",
      icon: ZoomIn,
      hotkey: "4",
      sublabel: selectedSessionId ? selectedSessionId : "No session selected",
    },
    { id: "correlations" as ViewTab, label: "5. Corpus & Beaconing", icon: Network, hotkey: "5" },
  ];

  return (
    <nav aria-label="Main Navigation" style={{ margin: "0 16px 12px 16px", display: "flex", gap: "6px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "6px" }}>
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;

        return (
          <button
            key={tab.id}
            onClick={() => onSelectTab(tab.id)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "8px 14px",
              borderRadius: "6px 6px 0 0",
              background: isActive ? "var(--bg-surface)" : "transparent",
              border: "1px solid",
              borderColor: isActive ? "var(--border-subtle) var(--border-subtle) transparent var(--border-subtle)" : "transparent",
              color: isActive ? "#fff" : "var(--text-secondary)",
              fontWeight: isActive ? 600 : 500,
              fontSize: "12.5px",
              cursor: "pointer",
              transition: "all 0.15s ease",
              position: "relative",
            }}
          >
            <Icon size={15} color={isActive ? "#38bdf8" : "#64748b"} />
            <span>{tab.label}</span>

            {tab.sublabel && (
              <span className="font-mono" style={{ fontSize: "10.5px", color: "#38bdf8", background: "rgba(56, 189, 248, 0.1)", padding: "1px 5px", borderRadius: 4 }}>
                {tab.sublabel}
              </span>
            )}

            {tab.badge && (
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: 700,
                  background: tab.badgeColor ? "rgba(239, 68, 68, 0.15)" : "#1e293b",
                  color: tab.badgeColor || "#94a3b8",
                  border: `1px solid ${tab.badgeColor ? "rgba(239, 68, 68, 0.35)" : "var(--border-subtle)"}`,
                  padding: "1px 6px",
                  borderRadius: 9999,
                }}
              >
                {tab.badge}
              </span>
            )}

            <span style={{ fontSize: "10px", color: "var(--text-muted)", marginLeft: "2px", opacity: 0.7 }}>
              [{tab.hotkey}]
            </span>

            {isActive && (
              <div style={{ position: "absolute", bottom: -7, left: 0, right: 0, height: 2, background: "#38bdf8" }} />
            )}
          </button>
        );
      })}
    </nav>
  );
};
