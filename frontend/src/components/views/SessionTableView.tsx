import React, { useState, useMemo, useRef, useEffect } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Search, Download, CheckSquare, Square, ChevronRight, SlidersHorizontal } from "lucide-react";
import { SessionDetailSchema } from "../../api/client";

interface SessionTableViewProps {
  sessions: SessionDetailSchema[];
  selectedSessionId?: string | null;
  onSelectSession: (session: SessionDetailSchema) => void;
  onOpenVerdict?: (sessionId: string) => void;
  activeFilterPreset?: string;
  externalSearch?: string;
}

const PRESETS = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical Risk" },
  { id: "stripping", label: "STARTTLS Stripped" },
  { id: "anomalies", label: "ML Anomalies" },
  { id: "beacon_candidates", label: "Beacon Candidates" },
  { id: "weak_kex", label: "Weak KEX" },
];

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "#dc2626", HIGH: "#ea580c", WEAK: "#d97706", ACCEPTABLE: "#059669", SECURE: "#0891b2",
};
const RISK_BG: Record<string, string> = {
  CRITICAL: "#fef2f2", HIGH: "#fff7ed", WEAK: "#fffbeb", ACCEPTABLE: "#ecfdf5", SECURE: "#ecfeff",
};

const RiskBadge: React.FC<{ band: string; score: number }> = ({ band, score }) => (
  <span className="font-mono tabular-nums" style={{
    display: "inline-flex", alignItems: "center", gap: 5,
    padding: "3px 8px", borderRadius: 6, fontSize: 11, fontWeight: 700,
    background: RISK_BG[band] || "#f8fafc",
    color: RISK_COLOR[band] || "#475569",
    border: `1px solid ${RISK_COLOR[band] || "#e2e6f0"}33`,
  }}>
    <span>{score.toFixed(0)}</span>
    <span className="font-display" style={{ opacity: 0.8, fontSize: 9.5, fontWeight: 800, letterSpacing: "0.04em" }}>{band}</span>
  </span>
);

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

  // Keyboard nav
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

  const COLS = "32px 110px 155px 155px 75px 95px 115px 90px 70px 38px";

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>

      {/* ── Toolbar ── */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10, marginBottom: 12,
        justifyContent: "space-between", flexWrap: "wrap",
      }}>
        {/* Preset tabs */}
        <div style={{
          display: "flex", gap: 4, background: "#fff",
          border: "1px solid #e2e6f0", borderRadius: 10, padding: 4,
          boxShadow: "0 1px 4px rgba(15,23,42,0.05)",
        }}>
          {PRESETS.map((p) => {
            const active = selectedPreset === p.id;
            return (
              <button key={p.id} onClick={() => setSelectedPreset(p.id)} style={{
                padding: "5px 13px", borderRadius: 7, border: "none", cursor: "pointer",
                fontSize: 12, fontWeight: active ? 600 : 500, whiteSpace: "nowrap",
                background: active ? "#2563eb" : "transparent",
                color: active ? "#fff" : "#64748b",
                transition: "all 0.15s ease",
              }}>
                {p.label}
              </button>
            );
          })}
        </div>

        {/* Search + actions */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ position: "relative" }}>
            <Search size={13} color="#94a3b8" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }} />
            <input
              ref={searchInputRef} type="search"
              placeholder="Filter sessions [/]…"
              value={search} onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 30, width: 220, fontSize: 13 }}
            />
          </div>
          <button onClick={exportSelectedAsJSON} className="btn btn-secondary btn-sm" style={{ gap: 5 }}>
            <Download size={13} />
            Export ({selectedIds.size || filteredSessions.length})
          </button>
        </div>
      </div>

      {/* ── Table Card ── */}
      <div style={{
        flex: 1, display: "flex", flexDirection: "column",
        background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12,
        boxShadow: "0 1px 4px rgba(15,23,42,0.06)", overflow: "hidden",
      }}>
        {/* Table Header */}
        <div className="font-display" style={{
          display: "grid", gridTemplateColumns: COLS,
          background: "#f8fafc", borderBottom: "2px solid #e2e6f0",
          padding: "0 14px", height: 40, alignItems: "center",
          fontSize: 11, fontWeight: 700, textTransform: "uppercase",
          color: "#64748b", letterSpacing: "0.06em", userSelect: "none",
          flexShrink: 0,
        }}>
          <div onClick={toggleSelectAll} style={{ cursor: "pointer", display: "flex", alignItems: "center" }}>
            {selectedIds.size === filteredSessions.length && filteredSessions.length > 0
              ? <CheckSquare size={14} color="#2563eb" />
              : <Square size={14} color="#94a3b8" />}
          </div>
          <div>Session</div>
          <div>Client</div>
          <div>Server / SNI</div>
          <div>Protocol</div>
          <div>STARTTLS</div>
          <div>Risk Score</div>
          <div>Timing</div>
          <div>Bytes</div>
          <div />
        </div>

        {/* Virtualized rows */}
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
                    position: "absolute", top: 0, left: 0, width: "100%",
                    height: `${virtualRow.size}px`, transform: `translateY(${virtualRow.start}px)`,
                    display: "grid", gridTemplateColumns: COLS,
                    alignItems: "center", padding: "0 14px",
                    fontSize: 12.5, cursor: "pointer",
                    borderBottom: "1px solid #f1f5f9",
                    borderLeft: isSelected ? `3px solid #2563eb` : "3px solid transparent",
                    background: isSelected
                      ? "#eff6ff"
                      : isFocused
                      ? "#f8fafc"
                      : virtualRow.index % 2 === 0 ? "#fff" : "#fafbfc",
                    transition: "background 0.1s ease",
                  }}
                  onMouseEnter={e => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = "#f1f5f9"; }}
                  onMouseLeave={e => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = virtualRow.index % 2 === 0 ? "#fff" : "#fafbfc"; }}
                >
                  <div onClick={(e) => toggleSelectOne(s.id, e)}>
                    {isChecked ? <CheckSquare size={13} color="#2563eb" /> : <Square size={13} color="#cbd5e1" />}
                  </div>

                  <div className="font-mono tabular-nums" style={{ fontSize: 10.5, color: isSelected ? "#2563eb" : "#7b93ab", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.id.split("-")[0]}…
                  </div>

                  <div className="font-mono tabular-nums" style={{ fontSize: 11.5, color: "#1a2d45", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.client_ip}:{s.client_port}
                  </div>

                  <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 600, color: "#0d1b2e" }}>
                    {s.sni || `${s.server_ip}:${s.server_port}`}
                  </div>

                  <div>
                    <span className="font-display" style={{
                      display: "inline-block", padding: "2px 7px", borderRadius: 5,
                      fontSize: 10.5, fontWeight: 800, background: "#dbeafe",
                      color: "#1d4ed8", letterSpacing: "0.04em",
                    }}>{s.protocol}</span>
                  </div>

                  <div>
                    {s.starttls_state === "S_STRIP_DETECTED" ? (
                      <span className="font-display" style={{ fontSize: 10.5, fontWeight: 800, color: "#dc2626", background: "#fef2f2", border: "1px solid #fecaca", padding: "2px 7px", borderRadius: 5, letterSpacing: "0.04em" }}>STRIPPED</span>
                    ) : s.starttls_state === "S4_ENCRYPTED" ? (
                      <span className="font-display" style={{ fontSize: 11, fontWeight: 700, color: "#059669" }}>● Encrypted</span>
                    ) : (
                      <span className="font-sans" style={{ fontSize: 11, color: "#94a3b8" }}>{s.starttls_state.replace(/_/g, " ")}</span>
                    )}
                  </div>

                  <div>
                    <RiskBadge band={s.risk_band} score={s.risk_score} />
                  </div>

                  <div>
                    {s.temporal_classification === "BEACON_CANDIDATE" ? (
                      <span className="font-display" style={{ fontSize: 10, fontWeight: 800, color: "#dc2626", background: "#fef2f2", border: "1px solid #fecaca", padding: "2px 6px", borderRadius: 5, letterSpacing: "0.04em" }}>BEACON</span>
                    ) : s.temporal_classification === "SUSPICIOUS_TIMING" ? (
                      <span className="font-display" style={{ fontSize: 10, fontWeight: 800, color: "#d97706", background: "#fffbeb", padding: "2px 6px", borderRadius: 5, letterSpacing: "0.04em" }}>SUSPICIOUS</span>
                    ) : (
                      <span className="font-sans" style={{ fontSize: 11, color: "#cbd5e1" }}>Normal</span>
                    )}
                  </div>

                  <div className="font-mono tabular-nums" style={{ fontSize: 11.5, color: "#64748b" }}>
                    {(((s.c2s_bytes || 0) + (s.s2c_bytes || 0)) / 1024).toFixed(1)} KB
                  </div>

                  <div style={{ display: "flex", justifyContent: "center" }}>
                    <ChevronRight size={14} color={isSelected ? "#2563eb" : "#cbd5e1"} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer status bar */}
        <div style={{
          padding: "7px 16px", borderTop: "1px solid #f1f5f9",
          background: "#f8fafc", display: "flex", justifyContent: "space-between",
          fontSize: 11.5, color: "#64748b", flexShrink: 0,
        }}>
          <div>
            Showing <strong style={{ color: "#0f172a" }}>{filteredSessions.length.toLocaleString()}</strong> of {sessions.length.toLocaleString()} sessions
            &nbsp;·&nbsp;<kbd style={{ background: "#e2e6f0", border: "1px solid #cbd5e1", borderRadius: 4, padding: "1px 5px", fontSize: 10.5, fontFamily: "JetBrains Mono, monospace", color: "#475569" }}>j/k</kbd> navigate
            &nbsp;·&nbsp;<kbd style={{ background: "#e2e6f0", border: "1px solid #cbd5e1", borderRadius: 4, padding: "1px 5px", fontSize: 10.5, fontFamily: "JetBrains Mono, monospace", color: "#475569" }}>Enter</kbd> inspect
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <SlidersHorizontal size={11} />
            TanStack Virtual · sub-200ms rendering
          </div>
        </div>
      </div>
    </div>
  );
};
