import React, { useState, useMemo, useRef, useEffect } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Search, Download, CheckSquare, Square, ChevronRight, SlidersHorizontal } from "lucide-react";
import { SessionDetailSchema } from "../../api/client";
import { IndustrialCard } from "../common/IndustrialCard";
import { TactileButton } from "../common/TactileButton";

interface SessionTableViewProps {
  sessions: SessionDetailSchema[];
  selectedSessionId?: string | null;
  onSelectSession: (session: SessionDetailSchema) => void;
  onOpenVerdict?: (sessionId: string) => void;
  activeFilterPreset?: string;
  externalSearch?: string;
}

const PRESETS = [
  { id: "all", label: "ALL TRAFFIC" },
  { id: "critical", label: "CRITICAL RISK" },
  { id: "stripping", label: "STARTTLS STRIPPED" },
  { id: "anomalies", label: "ML ANOMALIES" },
  { id: "beacon_candidates", label: "BEACON SIGNALS" },
  { id: "weak_kex", label: "WEAK KEX" },
];

export const SessionTableView: React.FC<SessionTableViewProps> = ({
  sessions,
  selectedSessionId = null,
  onSelectSession,
  onOpenVerdict = () => {},
  activeFilterPreset = "all",
  externalSearch = "",
}) => {
  const [search, setSearch] = useState(externalSearch);
  const [selectedPreset, setSelectedPreset] = useState(activeFilterPreset);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [focusedIndex, setFocusedIndex] = useState(0);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const parentRef = useRef<HTMLDivElement>(null);

  useEffect(() => { if (externalSearch) setSearch(externalSearch); }, [externalSearch]);

  // Filter
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      if (selectedPreset === "beacon_candidates" && s.temporal_classification !== "BEACON_CANDIDATE") return false;
      if (selectedPreset === "critical" && s.risk_band !== "CRITICAL") return false;
      if (selectedPreset === "stripping" && s.starttls_state !== "S_STRIP_DETECTED") return false;
      if (selectedPreset === "anomalies" && !s.is_anomaly) return false;
      if (selectedPreset === "weak_kex" && !s.risk_breakdown?.component_scores?.key_exchange) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          s.id.toLowerCase().includes(q) || s.client_ip.toLowerCase().includes(q) ||
          s.server_ip.toLowerCase().includes(q) || (s.sni && s.sni.toLowerCase().includes(q)) ||
          s.protocol.toLowerCase().includes(q) || s.risk_band.toLowerCase().includes(q) ||
          (s.ja3 && s.ja3.toLowerCase().includes(q)) || s.starttls_state.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [sessions, selectedPreset, search]);

  const rowVirtualizer = useVirtualizer({
    count: filteredSessions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44,
    overscan: 20,
  });

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        if (e.key === "Escape") (e.target as HTMLElement).blur();
        return;
      }
      if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); setFocusedIndex((p) => Math.min(filteredSessions.length - 1, p + 1)); }
      else if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); setFocusedIndex((p) => Math.max(0, p - 1)); }
      else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); if (filteredSessions[focusedIndex]) onSelectSession(filteredSessions[focusedIndex]); }
      else if (e.key === "/") { e.preventDefault(); searchInputRef.current?.focus(); }
      else if (e.key === "v") { e.preventDefault(); if (filteredSessions[focusedIndex]) onOpenVerdict(filteredSessions[focusedIndex].id); }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredSessions, focusedIndex, onSelectSession, onOpenVerdict]);

  const toggleSelectAll = () => {
    setSelectedIds(selectedIds.size === filteredSessions.length ? new Set() : new Set(filteredSessions.map((s) => s.id)));
  };
  const toggleSelectOne = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = new Set(selectedIds);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelectedIds(next);
  };

  const exportSelectedAsJSON = () => {
    const targets = selectedIds.size > 0 ? sessions.filter((s) => selectedIds.has(s.id)) : filteredSessions;
    const blob = new Blob([JSON.stringify(targets, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `pecff_sessions_${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const COLS = "36px 115px 165px 165px 85px 105px 120px 95px 75px 36px";

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>

      {/* ── Switchboard Control Toolbar ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 16,
          justifyContent: "space-between",
          flexWrap: "wrap",
        }}
      >
        {/* Preset Selector Keys */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {PRESETS.map((p) => {
            const active = selectedPreset === p.id;
            return (
              <TactileButton
                key={p.id}
                size="sm"
                variant={active ? "recessed" : "chassis"}
                active={active}
                onClick={() => setSelectedPreset(p.id)}
                style={{ padding: "6px 12px", fontSize: 10.5 }}
              >
                {p.label}
              </TactileButton>
            );
          })}
        </div>

        {/* Search Slot + Export Latch */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ position: "relative" }}>
            <Search size={13} color="var(--text-muted)" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }} />
            <input
              ref={searchInputRef}
              type="search"
              className="data-slot-input"
              placeholder="FILTER SWITCHBOARD [/]..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 34, width: 240, fontSize: 11.5 }}
            />
          </div>

          <TactileButton
            variant="chassis"
            size="sm"
            onClick={exportSelectedAsJSON}
            icon={<Download size={13} />}
          >
            EXPORT ({selectedIds.size || filteredSessions.length})
          </TactileButton>
        </div>
      </div>

      {/* ── Virtualized Switchboard Frame ── */}
      <IndustrialCard
        elevation="base"
        bolted={true}
        vents={true}
        tag="RECONSTRUCTED WIRE STREAMS · VIRTUAL BUS"
        style={{ flex: 1, display: "flex", flexDirection: "column", padding: 0, overflow: "hidden" }}
      >
        {/* Table Header Bar */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: COLS,
            background: "var(--chassis)",
            borderBottom: "2px solid #babecc",
            padding: "0 18px",
            height: 42,
            alignItems: "center",
            flexShrink: 0,
          }}
        >
          <div onClick={toggleSelectAll} style={{ cursor: "pointer", display: "flex", alignItems: "center" }}>
            {selectedIds.size === filteredSessions.length && filteredSessions.length > 0
              ? <CheckSquare size={14} color="var(--accent)" />
              : <Square size={14} color="#babecc" />}
          </div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>STREAM ID</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>CLIENT ORIGIN</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>SERVER / SNI</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>PROTOCOL</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>STARTTLS</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>NIST RISK</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>TEMPORAL</div>
          <div className="stamped-label" style={{ fontSize: 9.5 }}>PAYLOAD</div>
          <div />
        </div>

        {/* Virtualized Rows */}
        <div ref={parentRef} style={{ flex: 1, overflowY: "auto", position: "relative" }}>
          <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, width: "100%", position: "relative" }}>
            {rowVirtualizer.getVirtualItems().map((virtualRow) => {
              const s = filteredSessions[virtualRow.index];
              const isSelected = selectedSessionId === s.id;
              const isFocused = focusedIndex === virtualRow.index;
              const isChecked = selectedIds.has(s.id);

              return (
                <div
                  key={s.id}
                  onClick={() => { setFocusedIndex(virtualRow.index); onSelectSession(s); }}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: `${virtualRow.size}px`,
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "grid",
                    gridTemplateColumns: COLS,
                    alignItems: "center",
                    padding: "0 18px",
                    cursor: "pointer",
                    borderBottom: "1px solid rgba(186,190,204,0.35)",
                    borderLeft: isSelected ? "4px solid var(--accent)" : "4px solid transparent",
                    background: isSelected
                      ? "rgba(51,65,85,0.12)"
                      : isFocused
                      ? "rgba(186,190,204,0.2)"
                      : virtualRow.index % 2 === 0 ? "var(--chassis)" : "var(--panel)",
                    transition: "background 100ms ease",
                  }}
                  onMouseEnter={(e) => {
                    if (!isSelected) (e.currentTarget as HTMLElement).style.background = "rgba(186,190,204,0.35)";
                  }}
                  onMouseLeave={(e) => {
                    if (!isSelected)
                      (e.currentTarget as HTMLElement).style.background =
                        virtualRow.index % 2 === 0 ? "var(--chassis)" : "var(--panel)";
                  }}
                >
                  <div onClick={(e) => toggleSelectOne(s.id, e)}>
                    {isChecked ? <CheckSquare size={13} color="var(--accent)" /> : <Square size={13} color="#babecc" />}
                  </div>

                  <div className="tabular-mono" style={{ fontSize: 10.5, color: isSelected ? "var(--accent)" : "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.id.split("-")[0]}…
                  </div>

                  <div className="tabular-mono" style={{ fontSize: 11, color: "var(--text-primary)", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.client_ip}:{s.client_port}
                  </div>

                  <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, fontWeight: 700, color: "var(--text-primary)" }}>
                    {s.sni || `${s.server_ip}:${s.server_port}`}
                  </div>

                  <div>
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 6px",
                        borderRadius: 4,
                        fontSize: 9.5,
                        fontWeight: 700,
                        background: "var(--recessed)",
                        color: "var(--text-primary)",
                        boxShadow: "var(--shadow-recessed)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {s.protocol}
                    </span>
                  </div>

                  <div>
                    {s.starttls_state === "S_STRIP_DETECTED" ? (
                      <span className="risk-plaque risk-plaque-CRITICAL" style={{ fontSize: 9 }}>STRIPPED</span>
                    ) : s.starttls_state === "S4_ENCRYPTED" ? (
                      <span className="risk-plaque risk-plaque-SECURE" style={{ fontSize: 9 }}>ENCRYPTED</span>
                    ) : (
                      <span className="tabular-mono" style={{ fontSize: 10, color: "var(--text-muted)" }}>{s.starttls_state.replace(/_/g, " ")}</span>
                    )}
                  </div>

                  <div>
                    <span className={`risk-plaque risk-plaque-${s.risk_band}`} style={{ fontSize: 9.5 }}>
                      {s.risk_score.toFixed(0)} {s.risk_band}
                    </span>
                  </div>

                  <div>
                    {s.temporal_classification === "BEACON_CANDIDATE" ? (
                      <span className="risk-plaque risk-plaque-CRITICAL" style={{ fontSize: 9 }}>BEACON</span>
                    ) : s.temporal_classification === "SUSPICIOUS_TIMING" ? (
                      <span className="risk-plaque risk-plaque-WEAK" style={{ fontSize: 9 }}>SUSP.</span>
                    ) : (
                      <span className="tabular-mono" style={{ fontSize: 10, color: "var(--text-muted)" }}>NORMAL</span>
                    )}
                  </div>

                  <div className="tabular-mono" style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    {(((s.c2s_bytes || 0) + (s.s2c_bytes || 0)) / 1024).toFixed(1)} KB
                  </div>

                  <div style={{ display: "flex", justifyContent: "center" }}>
                    <ChevronRight size={14} color={isSelected ? "var(--accent)" : "#babecc"} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Switchboard Footer Status Plate */}
        <div
          style={{
            padding: "8px 18px",
            borderTop: "1px solid #babecc",
            background: "var(--chassis)",
            display: "flex",
            justifyContent: "space-between",
            fontSize: 11,
            color: "var(--text-secondary)",
            fontFamily: "var(--font-mono)",
            flexShrink: 0,
          }}
        >
          <div>
            ACTIVE CHANNELS: <strong style={{ color: "var(--text-primary)" }}>{filteredSessions.length.toLocaleString()}</strong> OF {sessions.length.toLocaleString()}
            &nbsp;·&nbsp;<kbd style={{ background: "var(--recessed)", borderRadius: 4, padding: "2px 6px", boxShadow: "var(--shadow-recessed)" }}>j/k</kbd> SHIFT
            &nbsp;·&nbsp;<kbd style={{ background: "var(--recessed)", borderRadius: 4, padding: "2px 6px", boxShadow: "var(--shadow-recessed)" }}>Enter</kbd> DISSECT
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <SlidersHorizontal size={12} color="var(--accent)" />
            <span>VIRTUAL BUS LATENCY &lt; 200MS</span>
          </div>
        </div>
      </IndustrialCard>
    </div>
  );
};
