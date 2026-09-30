import React, { useState, useMemo } from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, LineChart, Line, CartesianGrid, Legend,
} from "recharts";
import { ShieldAlert, AlertTriangle, Lock, Activity, Layers, Filter, TrendingUp, Globe } from "lucide-react";
import { AnalysisDetailResponse, SessionDetailSchema, FindingSchema } from "../../api/client";

interface AnalysisOverviewViewProps {
  analysis: AnalysisDetailResponse;
  onFilterSessions: (filter: { risk_band?: string; protocol?: string; cipher?: string; search?: string }) => void;
}

const RISK_BAND_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  WEAK: "#d97706",
  ACCEPTABLE: "#059669",
  SECURE: "#0891b2",
};

const RISK_BG: Record<string, string> = {
  CRITICAL: "#fef2f2", HIGH: "#fff7ed", WEAK: "#fffbeb", ACCEPTABLE: "#ecfdf5", SECURE: "#ecfeff",
};

// ── Reusable card header ──
const SectionHeader: React.FC<{ icon: React.ReactNode; title: string; subtitle?: React.ReactNode }> = ({ icon, title, subtitle }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width: 32, height: 32, borderRadius: 8, background: "#f1f5f9", display: "flex", alignItems: "center", justifyContent: "center" }}>
        {icon}
      </div>
      <span className="font-display" style={{ fontSize: 14.5, fontWeight: 700, color: "#0d1b2e", letterSpacing: "-0.02em" }}>{title}</span>
    </div>
    {subtitle && <div className="font-sans" style={{ fontSize: 12, color: "#64748b" }}>{subtitle}</div>}
  </div>
);

// ── KPI metric card ──
const MetricCard: React.FC<{
  label: string; value: string | number; sub?: string;
  accent: string; accentBg: string; icon: React.ReactNode; band?: string;
}> = ({ label, value, sub, accent, accentBg, icon, band }) => (
  <div style={{
    background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12,
    padding: "16px 20px", boxShadow: "0 1px 4px rgba(15,23,42,0.06)",
    display: "flex", flexDirection: "column", gap: 8,
    borderTop: `3px solid ${accent}`,
  }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
      <span className="text-eyebrow" style={{ fontSize: 11, color: "#64748b" }}>{label}</span>
      <div style={{ width: 30, height: 30, borderRadius: 8, background: accentBg, display: "flex", alignItems: "center", justifyContent: "center" }}>
        {icon}
      </div>
    </div>
    <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
      <span className="text-kpi font-display tabular-nums" style={{ color: accent }}>{value}</span>
      {sub && <span className="font-sans" style={{ fontSize: 12, color: "#94a3b8" }}>{sub}</span>}
    </div>
    {band && (
      <span className={`badge badge-${band}`} style={{ alignSelf: "flex-start", marginTop: 2 }}>{band}</span>
    )}
  </div>
);

// ── Custom tooltip ──
const ChartTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 8, padding: "8px 12px", boxShadow: "0 4px 12px rgba(15,23,42,0.1)", fontSize: 12 }}>
      {label && <div style={{ fontWeight: 600, color: "#0f172a", marginBottom: 4 }}>{label}</div>}
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ color: p.color || "#475569" }}>{p.name}: <strong>{p.value}</strong></div>
      ))}
    </div>
  );
};

export const AnalysisOverviewView: React.FC<AnalysisOverviewViewProps> = ({ analysis, onFilterSessions }) => {
  const [timeBucket, setTimeBucket] = useState<"1h" | "1d" | "1w">("1h");

  // 1. Risk distribution
  const riskDistribution = useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, WEAK: 0, ACCEPTABLE: 0, SECURE: 0 };
    analysis.sessions.forEach((s: SessionDetailSchema) => { counts[s.risk_band] = (counts[s.risk_band] || 0) + 1; });
    return Object.keys(counts).map((band) => ({ name: band, value: counts[band], color: RISK_BAND_COLORS[band] }));
  }, [analysis.sessions]);

  // 2. STARTTLS health per MX
  const starttlsHealth = useMemo(() => {
    const mxMap: Record<string, { total: number; encrypted: number; stripped: number }> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      const mx = s.sni || s.server_ip;
      if (!mxMap[mx]) mxMap[mx] = { total: 0, encrypted: 0, stripped: 0 };
      mxMap[mx].total += 1;
      if (s.starttls_state === "S4_ENCRYPTED" || s.mode === "IMPLICIT") mxMap[mx].encrypted += 1;
      else if (s.starttls_state === "S_STRIP_DETECTED") mxMap[mx].stripped += 1;
    });
    return Object.entries(mxMap)
      .map(([mx, stats]) => ({
        mx: mx.length > 20 ? mx.substring(0, 18) + "…" : mx,
        fullMx: mx,
        successRate: Math.round((stats.encrypted / stats.total) * 100),
        strippedRate: Math.round((stats.stripped / stats.total) * 100),
        total: stats.total,
      }))
      .sort((a, b) => a.successRate - b.successRate)
      .slice(0, 7);
  }, [analysis.sessions]);

  // 3. TLS versions
  const tlsVersions = useMemo(() => {
    const map: Record<string, number> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      const v = s.risk_score <= 15 ? "TLS 1.3" : s.risk_score <= 40 ? "TLS 1.2" : s.risk_score <= 75 ? "TLS 1.0" : "SSL / Plain";
      map[v] = (map[v] || 0) + 1;
    });
    const total = analysis.sessions.length || 1;
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .map(([ver, count]) => ({
        version: ver,
        count,
        pct: Math.round((count / total) * 100),
        color: ver === "TLS 1.3" ? "#059669" : ver === "TLS 1.2" ? "#0891b2" : ver === "TLS 1.0" ? "#d97706" : "#dc2626",
      }));
  }, [analysis.sessions]);

  // 4. JA3 fingerprints
  const ja3Frequencies = useMemo(() => {
    const map: Record<string, { count: number; first: number; last: number }> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      if (s.ja3) {
        if (!map[s.ja3]) map[s.ja3] = { count: 0, first: s.first_seen, last: s.first_seen };
        map[s.ja3].count += 1;
        map[s.ja3].first = Math.min(map[s.ja3].first, s.first_seen);
        map[s.ja3].last = Math.max(map[s.ja3].last, s.first_seen);
      }
    });
    return Object.entries(map)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5)
      .map(([ja3, data]) => ({ ja3, ...data }));
  }, [analysis.sessions]);

  // 5. Time-series trend
  const timeSeriesTrend = useMemo(() => {
    if (!analysis.sessions.length) return [];
    const sorted = [...analysis.sessions].sort((a, b) => a.first_seen - b.first_seen);
    const minTime = sorted[0].first_seen;
    const maxTime = sorted[sorted.length - 1].first_seen;
    const numBuckets = timeBucket === "1h" ? 12 : timeBucket === "1d" ? 24 : 28;
    const interval = Math.max(1, (maxTime - minTime) / numBuckets);
    return Array.from({ length: numBuckets }, (_, i) => {
      const bStart = minTime + i * interval;
      const bEnd = bStart + interval;
      const bucket = sorted.filter((s) => s.first_seen >= bStart && s.first_seen < bEnd);
      const d = new Date(bStart * 1000);
      return {
        t: `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`,
        risk: bucket.length ? Math.round(bucket.reduce((a, s) => a + s.risk_score, 0) / bucket.length) : 0,
        critical: bucket.filter((s) => s.risk_band === "CRITICAL").length,
        sessions: bucket.length,
      };
    });
  }, [analysis.sessions, timeBucket]);

  const criticalCount = analysis.findings.filter((f: FindingSchema) => f.severity === "CRITICAL").length;
  const anomalyCount = analysis.sessions.filter((s: SessionDetailSchema) => s.is_anomaly).length;

  return (
    <div style={{ maxWidth: 1400, margin: "0 auto" }}>

      {/* ── KPI Row ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 14, marginBottom: 24 }}>
        <MetricCard
          label="Overall Risk Score" value={analysis.overall_risk_score.toFixed(1)} sub="/ 100"
          accent={RISK_BAND_COLORS[analysis.overall_risk_band]}
          accentBg={RISK_BG[analysis.overall_risk_band]}
          icon={<ShieldAlert size={16} color={RISK_BAND_COLORS[analysis.overall_risk_band]} />}
          band={analysis.overall_risk_band}
        />
        <MetricCard
          label="Total Sessions" value={analysis.total_sessions.toLocaleString()}
          accent="#2563eb" accentBg="#dbeafe"
          icon={<Activity size={16} color="#2563eb" />}
        />
        <MetricCard
          label="Total Packets" value={analysis.total_packets.toLocaleString()}
          accent="#0891b2" accentBg="#ecfeff"
          icon={<Globe size={16} color="#0891b2" />}
        />
        <MetricCard
          label="Critical Findings" value={criticalCount} sub={`of ${analysis.findings.length}`}
          accent="#dc2626" accentBg="#fef2f2"
          icon={<AlertTriangle size={16} color="#dc2626" />}
        />
        <MetricCard
          label="Anomalous Flows (ML)" value={anomalyCount}
          accent="#7c3aed" accentBg="#f5f3ff"
          icon={<TrendingUp size={16} color="#7c3aed" />}
        />
      </div>

      {/* ── Row 1: Donut + Findings table ── */}
      <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 16, marginBottom: 16 }}>

        {/* Risk Donut */}
        <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12, padding: 20, boxShadow: "0 1px 4px rgba(15,23,42,0.06)" }}>
          <SectionHeader icon={<ShieldAlert size={16} color="#dc2626" />} title="Risk Distribution" subtitle="Click to filter" />
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={riskDistribution} innerRadius={52} outerRadius={78} paddingAngle={2} dataKey="value"
                cursor="pointer" onClick={(e) => onFilterSessions({ risk_band: e.name })}>
                {riskDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.color} stroke="#fff" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
            {riskDistribution.filter(r => r.value > 0).map((r) => (
              <div key={r.name} onClick={() => onFilterSessions({ risk_band: r.name })}
                style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "6px 10px", borderRadius: 8, cursor: "pointer",
                  background: RISK_BG[r.name], border: `1px solid ${r.color}22`,
                  transition: "opacity 0.15s",
                }}
                onMouseEnter={e => (e.currentTarget as HTMLElement).style.opacity = "0.8"}
                onMouseLeave={e => (e.currentTarget as HTMLElement).style.opacity = "1"}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 3, background: r.color, display: "inline-block" }} />
                  <span style={{ fontSize: 12.5, fontWeight: 600, color: r.color }}>{r.name}</span>
                </div>
                <span style={{ fontSize: 13, fontWeight: 700, color: "#0f172a", fontFamily: "JetBrains Mono, monospace" }}>{r.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Critical Findings table */}
        <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12, padding: 20, boxShadow: "0 1px 4px rgba(15,23,42,0.06)", overflow: "hidden" }}>
          <SectionHeader
            icon={<AlertTriangle size={16} color="#d97706" />}
            title={`Critical Forensic Findings (${analysis.findings.length})`}
            subtitle={
              <button className="btn btn-secondary btn-sm" onClick={() => onFilterSessions({ risk_band: "CRITICAL" })} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <Filter size={12} /> View Critical
              </button>
            }
          />
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr className="font-display" style={{ borderBottom: "2px solid #f1f5f9" }}>
                  {["Severity", "Rule ID", "Finding", "Reference", ""].map((h) => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analysis.findings.slice(0, 6).map((f: FindingSchema) => (
                  <tr key={f.id} style={{ borderBottom: "1px solid #f8fafc", transition: "background 0.1s" }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#fafbfc"}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "transparent"}
                  >
                    <td style={{ padding: "10px 12px" }}>
                      <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    </td>
                    <td className="crypto-hash" style={{ padding: "10px 12px", fontWeight: 600 }}>{f.rule_id}</td>
                    <td style={{ padding: "10px 12px", maxWidth: 260 }}>
                      <div style={{ fontWeight: 600, color: "#0f172a", fontSize: 13 }}>{f.title}</div>
                      <div style={{ fontSize: 11.5, color: "#64748b", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.description}</div>
                    </td>
                    <td style={{ padding: "10px 12px", fontSize: 11.5, color: "#64748b" }}>{f.standards_ref}</td>
                    <td style={{ padding: "10px 12px" }}>
                      <button className="btn btn-secondary btn-sm" onClick={() => onFilterSessions({ search: f.session_id })}
                        style={{ fontSize: 11, padding: "3px 8px", whiteSpace: "nowrap" }}>
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
                {analysis.findings.length === 0 && (
                  <tr><td colSpan={5} style={{ padding: "24px", textAlign: "center", color: "#64748b", fontSize: 13 }}>No findings detected</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ── Row 2: STARTTLS Bar + Risk Trend Line ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>

        {/* STARTTLS health bar chart */}
        <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12, padding: 20, boxShadow: "0 1px 4px rgba(15,23,42,0.06)" }}>
          <SectionHeader icon={<Lock size={16} color="#059669" />} title="STARTTLS Upgrade Health by MX" subtitle="Worst first • Click to filter" />
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={starttlsHealth} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" horizontal={false} />
              <XAxis type="number" domain={[0, 100]} stroke="#cbd5e1" fontSize={11} unit="%" tick={{ fill: "#94a3b8" }} />
              <YAxis dataKey="mx" type="category" stroke="#f1f5f9" fontSize={11} width={120} tick={{ fill: "#475569" }} />
              <Tooltip content={<ChartTooltip />} formatter={(v: any) => [`${v}%`, "Upgrade Success"]} />
              <Bar dataKey="successRate" name="Upgrade %" fill="#2563eb" radius={[0, 4, 4, 0]} cursor="pointer"
                onClick={(d: any) => onFilterSessions({ search: d.fullMx })} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Risk trend line chart */}
        <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12, padding: 20, boxShadow: "0 1px 4px rgba(15,23,42,0.06)" }}>
          <SectionHeader
            icon={<Activity size={16} color="#2563eb" />}
            title="Cryptographic Risk Trend"
            subtitle={
              <div style={{ display: "flex", gap: 4 }}>
                {(["1h", "1d", "1w"] as const).map((b) => (
                  <button key={b} onClick={() => setTimeBucket(b)}
                    className={`btn btn-sm ${timeBucket === b ? "btn-primary" : "btn-secondary"}`}
                    style={{ padding: "3px 9px", fontSize: 11 }}>
                    {b}
                  </button>
                ))}
              </div>
            }
          />
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={timeSeriesTrend} margin={{ top: 4, right: 16, left: -24, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="t" stroke="#cbd5e1" fontSize={11} tick={{ fill: "#94a3b8" }} />
              <YAxis domain={[0, 100]} stroke="#f1f5f9" fontSize={11} tick={{ fill: "#94a3b8" }} />
              <Tooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: "#64748b" }} />
              <Line type="monotone" dataKey="risk" name="Avg Risk Score" stroke="#2563eb" strokeWidth={2} dot={{ r: 3, fill: "#2563eb" }} activeDot={{ r: 5 }} />
              <Line type="monotone" dataKey="critical" name="Critical Events" stroke="#dc2626" strokeWidth={2} dot={{ r: 3, fill: "#dc2626" }} activeDot={{ r: 5 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Row 3: TLS Versions + JA3 Fingerprints ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

        {/* TLS Versions */}
        <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12, padding: 20, boxShadow: "0 1px 4px rgba(15,23,42,0.06)" }}>
          <SectionHeader icon={<Layers size={16} color="#7c3aed" />} title="TLS Version Distribution" />
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {tlsVersions.map((t) => (
              <div key={t.version} onClick={() => onFilterSessions({ search: t.version })}
                style={{
                  display: "flex", alignItems: "center", gap: 12,
                  padding: "10px 14px", borderRadius: 10, cursor: "pointer",
                  border: "1px solid #f1f5f9", background: "#fafbfc",
                  transition: "all 0.15s ease",
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "#f1f5f9"; (e.currentTarget as HTMLElement).style.borderColor = "#e2e6f0"; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "#fafbfc"; (e.currentTarget as HTMLElement).style.borderColor = "#f1f5f9"; }}
              >
                <div style={{ width: 12, height: 12, borderRadius: 3, background: t.color, flexShrink: 0 }} />
                <span style={{ fontWeight: 600, color: "#0f172a", fontSize: 13, flex: 1 }}>{t.version}</span>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  {/* Mini progress bar */}
                  <div style={{ width: 80, height: 6, background: "#f1f5f9", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ width: `${t.pct}%`, height: "100%", background: t.color, borderRadius: 3 }} />
                  </div>
                  <span style={{ fontWeight: 700, color: "#0f172a", fontSize: 13, fontFamily: "JetBrains Mono, monospace", minWidth: 32, textAlign: "right" }}>{t.count}</span>
                  <span style={{ fontSize: 11, color: "#94a3b8", minWidth: 32, textAlign: "right" }}>{t.pct}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* JA3 Fingerprints */}
        <div style={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 12, padding: 20, boxShadow: "0 1px 4px rgba(15,23,42,0.06)" }}>
          <SectionHeader icon={<Activity size={16} color="#0891b2" />} title="Top JA3 Client Fingerprints" subtitle="Click to filter sessions" />
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {ja3Frequencies.length === 0 ? (
              <div style={{ padding: "24px", textAlign: "center", color: "#94a3b8", fontSize: 13 }}>No JA3 fingerprints in this capture</div>
            ) : ja3Frequencies.map((j, idx) => (
              <div key={j.ja3} onClick={() => onFilterSessions({ search: j.ja3 })}
                style={{
                  display: "flex", alignItems: "center", gap: 12,
                  padding: "10px 14px", borderRadius: 10, cursor: "pointer",
                  border: "1px solid #f1f5f9", background: "#fafbfc",
                  transition: "all 0.15s ease",
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "#f1f5f9"; (e.currentTarget as HTMLElement).style.borderColor = "#e2e6f0"; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "#fafbfc"; (e.currentTarget as HTMLElement).style.borderColor = "#f1f5f9"; }}
              >
                <div style={{
                  width: 24, height: 24, borderRadius: 6, background: "#dbeafe",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, color: "#2563eb", flexShrink: 0,
                }}>#{idx + 1}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="font-mono" style={{ fontSize: 11.5, color: "#2563eb", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 600 }}>
                    {j.ja3}
                  </div>
                  <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>
                    {new Date(j.first * 1000).toLocaleTimeString()} – {new Date(j.last * 1000).toLocaleTimeString()}
                  </div>
                </div>
                <div style={{
                  background: "#dbeafe", borderRadius: 8, padding: "4px 10px",
                  fontSize: 13, fontWeight: 700, color: "#1d4ed8", fontFamily: "JetBrains Mono, monospace",
                  flexShrink: 0,
                }}>{j.count}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
