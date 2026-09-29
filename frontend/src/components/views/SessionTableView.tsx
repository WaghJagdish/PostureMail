import React, { useState, useMemo, useRef, useEffect } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  Search,
  Download,
  CheckSquare,
  Square,
  ChevronRight,
} from "lucide-react";
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
  { id: "all", label: "All Sessions" },
  { id: "beacon_candidates", label: "Beacon Candidates", beacon: true },
  { id: "critical", label: "Critical Risk (≥80)", band: "CRITICAL" },
  { id: "stripping", label: "STARTTLS Stripped", state: "S_STRIP_DETECTED" },
  { id: "anomalies", label: "Anomalous Flows (ML)", anomaly: true },
  { id: "weak_kex", label: "Weak / Static RSA", cipher: "RSA" },
  { id: "tls13", label: "TLS 1.3 Only", tls13: true },
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

  // Sync external search updates from chart clicks
  useEffect(() => {
    if (externalSearch) setSearch(externalSearch);
  }, [externalSearch]);

  // Filter sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      // 1. Preset filter
      if (selectedPreset === "beacon_candidates" && s.temporal_classification !== "BEACON_CANDIDATE") return false;
      if (selectedPreset === "critical" && s.risk_band !== "CRITICAL") return false;
      if (selectedPreset === "stripping" && s.starttls_state !== "S_STRIP_DETECTED") return false;
      if (selectedPreset === "anomalies" && !s.is_anomaly) return false;
      if (selectedPreset === "weak_kex" && !s.risk_breakdown?.component_scores?.key_exchange) return false;
      if (selectedPreset === "tls13" && !s.risk_breakdown?.weight_redistributed) return false;

      // 2. Text Search
      if (search.trim()) {
        const q = search.toLowerCase();
        const matches =
          s.id.toLowerCase().includes(q) ||
          s.client_ip.toLowerCase().includes(q) ||
          s.server_ip.toLowerCase().includes(q) ||
          (s.sni && s.sni.toLowerCase().includes(q)) ||
          s.protocol.toLowerCase().includes(q) ||
          s.risk_band.toLowerCase().includes(q) ||
          (s.ja3 && s.ja3.toLowerCase().includes(q)) ||
          (s.ja4 && s.ja4.toLowerCase().includes(q)) ||
          s.starttls_state.toLowerCase().includes(q);
        if (!matches) return false;
      }

      return true;
    });
  }, [sessions, selectedPreset, search]);

  // Virtualizer for 60fps high performance at 10,000 rows
  const rowVirtualizer = useVirtualizer({
    count: filteredSessions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 20,
  });

  // Keyboard navigation (j/k, Enter, v, /)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        if (e.key === "Escape") {
          (e.target as HTMLElement).blur();
        }
        return;
      }

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setFocusedIndex((prev) => Math.min(filteredSessions.length - 1, prev + 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setFocusedIndex((prev) => Math.max(0, prev - 1));
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (filteredSessions[focusedIndex]) {
          onSelectSession(filteredSessions[focusedIndex]);
        }
      } else if (e.key === "/") {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (e.key === "v") {
        e.preventDefault();
        if (filteredSessions[focusedIndex]) {
          onOpenVerdict(filteredSessions[focusedIndex].id);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredSessions, focusedIndex, onSelectSession, onOpenVerdict]);

  // Bulk Selection Handlers
  const toggleSelectAll = () => {
    if (selectedIds.size === filteredSessions.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredSessions.map((s) => s.id)));
    }
  };

  const toggleSelectOne = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedIds(next);
  };

  const exportSelectedAsJSON = () => {
    const targetSessions = selectedIds.size > 0 ? sessions.filter((s) => selectedIds.has(s.id)) : filteredSessions;
    const blob = new Blob([JSON.stringify(targetSessions, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pecff_sessions_export_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 135px)", margin: "0 16px" }}>
      {/* Top Filter & Action Bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, gap: 12 }}>
        {/* Presets */}
        <div style={{ display: "flex", gap: 6, overflowX: "auto", paddingBottom: 2 }}>
          {PRESETS.map((p) => {
            const isSelected = selectedPreset === p.id;
            return (
              <button
                key={p.id}
                onClick={() => setSelectedPreset(p.id)}
                style={{
                  padding: "5px 11px",
                  borderRadius: 6,
                  fontSize: 12,
                  fontWeight: isSelected ? 600 : 500,
                  background: isSelected ? "rgba(56, 189, 248, 0.15)" : "rgba(30, 41, 59, 0.5)",
                  color: isSelected ? "#38bdf8" : "var(--text-secondary)",
                  border: `1px solid ${isSelected ? "rgba(56, 189, 248, 0.4)" : "var(--border-subtle)"}`,
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  transition: "all 0.15s ease",
                }}
              >
                {p.label}
              </button>
            );
          })}
        </div>

        {/* Search & Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ position: "relative" }}>
            <Search size={14} color="#64748b" style={{ position: "absolute", left: 9, top: 8 }} />
            <input
              ref={searchInputRef}
              type="search"
              placeholder="Filter sessions [/]..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 28, width: 220, fontSize: 12 }}
            />
          </div>

          <button onClick={exportSelectedAsJSON} className="btn btn-secondary btn-sm" style={{ gap: 5 }}>
            <Download size={13} />
            <span>Export ({selectedIds.size || filteredSessions.length})</span>
          </button>
        </div>
      </div>

      {/* Table Container with Virtualization */}
      <div
        className="card"
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          background: "rgba(17, 24, 39, 0.8)",
          backdropFilter: "blur(10px)",
        }}
      >
        {/* Table Header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "36px 130px 160px 160px 80px 100px 90px 120px 80px 70px 40px",
            background: "rgba(10, 14, 23, 0.8)",
            borderBottom: "1px solid var(--border-subtle)",
            padding: "8px 12px",
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase",
            color: "var(--text-muted)",
            letterSpacing: "0.04em",
            userSelect: "none",
          }}
        >
          <div onClick={toggleSelectAll} style={{ cursor: "pointer", display: "flex", alignItems: "center" }}>
            {selectedIds.size === filteredSessions.length && filteredSessions.length > 0 ? (
              <CheckSquare size={14} color="#38bdf8" />
            ) : (
              <Square size={14} color="#64748b" />
            )}
          </div>
          <div>Session ID</div>
          <div>Client Endpoint</div>
          <div>Server / SNI</div>
          <div>Proto / Mode</div>
          <div>STARTTLS State</div>
          <div>Risk Score</div>
          <div>Temporal Timing</div>
          <div>ML (Exp)</div>
          <div>Bytes</div>
          <div style={{ textAlign: "right" }}>View</div>
        </div>

        {/* Virtualized Rows */}
        <div ref={parentRef} style={{ flex: 1, overflowY: "auto", position: "relative" }}>
          <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, width: "100%", position: "relative" }}>
            {rowVirtualizer.getVirtualItems().map((virtualRow) => {
              const session = filteredSessions[virtualRow.index];
              const isSelected = selectedSessionId === session.id;
              const isChecked = selectedIds.has(session.id);
              const isFocused = focusedIndex === virtualRow.index;

              return (
                <div
                  key={session.id}
                  onClick={() => {
                    setFocusedIndex(virtualRow.index);
                    onSelectSession(session);
                  }}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: `${virtualRow.size}px`,
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "grid",
                    gridTemplateColumns: "36px 130px 160px 160px 80px 100px 90px 120px 80px 70px 40px",
                    alignItems: "center",
                    padding: "0 12px",
                    fontSize: 12,
                    borderBottom: "1px solid rgba(255, 255, 255, 0.03)",
                    background: isSelected
                      ? "rgba(56, 189, 248, 0.12)"
                      : isFocused
                      ? "rgba(255, 255, 255, 0.04)"
                      : virtualRow.index % 2 === 0
                      ? "rgba(0, 0, 0, 0.15)"
                      : "transparent",
                    cursor: "pointer",
                    transition: "background 0.1s ease",
                  }}
                >
                  <div onClick={(e) => toggleSelectOne(session.id, e)}>
                    {isChecked ? <CheckSquare size={14} color="#38bdf8" /> : <Square size={14} color="#475569" />}
                  </div>

                  <div className="font-mono" style={{ fontSize: 11, color: isSelected ? "#38bdf8" : "#94a3b8" }}>
                    {session.id}
                  </div>

                  <div className="font-mono" style={{ fontSize: 11.5, color: "#f8fafc" }}>
                    {session.client_ip}:{session.client_port}
                  </div>

                  <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <span style={{ color: "#f8fafc", fontWeight: 500 }}>
                      {session.sni || `${session.server_ip}:${session.server_port}`}
                    </span>
                  </div>

                  <div>
                    <span className="badge" style={{ background: "#1e293b", color: "#38bdf8", padding: "1px 5px", fontSize: 10 }}>
                      {session.protocol}
                    </span>
                  </div>

                  <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {session.starttls_state === "S_STRIP_DETECTED" ? (
                      <span className="badge badge-CRITICAL" style={{ padding: "1px 5px", fontSize: 10 }}>STRIP DETECTED</span>
                    ) : session.starttls_state === "S4_ENCRYPTED" ? (
                      <span style={{ color: "#10b981", fontSize: 11, fontWeight: 500 }}>Encrypted (S4)</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)", fontSize: 11 }}>{session.starttls_state}</span>
                    )}
                  </div>

                  <div>
                    <span className={`badge badge-${session.risk_band}`} style={{ fontSize: 11, padding: "2px 7px" }}>
                      {session.risk_score.toFixed(0)} &bull; {session.risk_band}
                    </span>
                  </div>

                  <div>
                    {session.temporal_classification === "BEACON_CANDIDATE" ? (
                      <span className="badge badge-CRITICAL" style={{ fontSize: 9.5, padding: "1px 5px", background: "rgba(239, 68, 68, 0.2)", border: "1px solid #ef4444", color: "#fca5a5" }}>
                        BEACON
                      </span>
                    ) : session.temporal_classification === "SUSPICIOUS_TIMING" ? (
                      <span className="badge badge-HIGH" style={{ fontSize: 9.5, padding: "1px 5px", background: "rgba(245, 158, 11, 0.2)", border: "1px solid #f59e0b", color: "#fcd34d" }}>
                        SUSPICIOUS
                      </span>
                    ) : (
                      <span style={{ color: "var(--text-muted)", fontSize: 10.5 }}>Normal</span>
                    )}
                  </div>

                  <div>
                    {session.is_anomaly ? (
                      <span className="badge badge-WEAK" style={{ fontSize: 9.5, padding: "1px 5px", background: "rgba(168, 85, 247, 0.2)", color: "#d8b4fe" }}>
                        Exp Outlier
                      </span>
                    ) : (
                      <span style={{ color: "var(--text-muted)", fontSize: 10.5 }}>Inlier</span>
                    )}
                  </div>

                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {(((session.c2s_bytes || 0) + (session.s2c_bytes || 0)) / 1024).toFixed(1)} KB
                  </div>

                  <div style={{ textAlign: "right" }}>
                    <ChevronRight size={14} color={isSelected ? "#38bdf8" : "#64748b"} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer status bar */}
        <div style={{ padding: "6px 14px", borderTop: "1px solid var(--border-subtle)", background: "#0a0e17", display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-muted)" }}>
          <div>
            Showing <b>{filteredSessions.length.toLocaleString()}</b> of {sessions.length.toLocaleString()} flows &bull; Keyboard: <kbd className="font-mono">j/k</kbd> navigate &bull; <kbd className="font-mono">Enter</kbd> inspect &bull; <kbd className="font-mono">v</kbd> verdict
          </div>
          <div>
            Sub-200ms virtualized rendering (TanStack Virtual)
          </div>
        </div>
      </div>
    </div>
  );
};
