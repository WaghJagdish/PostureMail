import React, { useState, useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  LineChart,
  Line,
  CartesianGrid,
} from "recharts";
import {
  ShieldAlert,
  AlertTriangle,
  Lock,
  Activity,
  Layers,
  Filter,
} from "lucide-react";
import { AnalysisDetailResponse, SessionDetailSchema, FindingSchema } from "../../api/client";

interface AnalysisOverviewViewProps {
  analysis: AnalysisDetailResponse;
  onFilterSessions: (filter: { risk_band?: string; protocol?: string; cipher?: string; search?: string }) => void;
}

const RISK_BAND_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  WEAK: "#eab308",
  ACCEPTABLE: "#10b981",
  SECURE: "#06b6d4",
};

export const AnalysisOverviewView: React.FC<AnalysisOverviewViewProps> = ({
  analysis,
  onFilterSessions,
}) => {
  const [timeBucket, setTimeBucket] = useState<"1h" | "1d" | "1w">("1h");

  // 1. Risk Distribution Data for Donut Chart
  const riskDistribution = useMemo(() => {
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      WEAK: 0,
      ACCEPTABLE: 0,
      SECURE: 0,
    };
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      counts[s.risk_band] = (counts[s.risk_band] || 0) + 1;
    });
    return Object.keys(counts).map((band) => ({
      name: band,
      value: counts[band],
      color: RISK_BAND_COLORS[band],
    }));
  }, [analysis.sessions]);

  // 2. STARTTLS Health per Destination MX (sorted worst upgrade rate first)
  const starttlsHealth = useMemo(() => {
    const mxMap: Record<string, { total: number; encrypted: number; stripped: number; refused: number }> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      const mx = s.sni || s.server_ip;
      if (!mxMap[mx]) {
        mxMap[mx] = { total: 0, encrypted: 0, stripped: 0, refused: 0 };
      }
      mxMap[mx].total += 1;
      if (s.starttls_state === "S4_ENCRYPTED" || s.mode === "IMPLICIT") {
        mxMap[mx].encrypted += 1;
      } else if (s.starttls_state === "S_STRIP_DETECTED") {
        mxMap[mx].stripped += 1;
      } else {
        mxMap[mx].refused += 1;
      }
    });

    return Object.entries(mxMap)
      .map(([mx, stats]) => ({
        mx: mx.length > 22 ? mx.substring(0, 20) + "..." : mx,
        fullMx: mx,
        successRate: Math.round((stats.encrypted / stats.total) * 100),
        stripped: stats.stripped,
        refused: stats.refused,
        total: stats.total,
      }))
      .sort((a, b) => a.successRate - b.successRate)
      .slice(0, 8);
  }, [analysis.sessions]);

  // 3. TLS Version & Cipher Suite Distribution
  const tlsVersions = useMemo(() => {
    const map: Record<string, number> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      const v = s.risk_score <= 15 ? "TLS 1.3" : s.risk_score <= 40 ? "TLS 1.2" : s.risk_score <= 75 ? "TLS 1.0" : "SSL 3.0 / Plain";
      map[v] = (map[v] || 0) + 1;
    });
    return Object.entries(map).map(([ver, count]) => ({ version: ver, count }));
  }, [analysis.sessions]);

  // 4. JA3 Top Frequencies with First/Last Seen
  const ja3Frequencies = useMemo(() => {
    const map: Record<string, { count: number; first: number; last: number; ja3: string }> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      if (s.ja3) {
        const key = s.ja3;
        if (!map[key]) {
          map[key] = { count: 0, first: s.first_seen, last: s.first_seen, ja3: s.ja3 };
        }
        map[key].count += 1;
        map[key].first = Math.min(map[key].first, s.first_seen);
        map[key].last = Math.max(map[key].last, s.first_seen);
      }
    });
    return Object.values(map)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [analysis.sessions]);

  // 5. Time-Series Risk Trend
  const timeSeriesTrend = useMemo(() => {
    if (analysis.sessions.length === 0) return [];
    const sorted = [...analysis.sessions].sort((a, b) => a.first_seen - b.first_seen);
    const minTime = sorted[0].first_seen;
    const maxTime = sorted[sorted.length - 1].first_seen;

    // Number of display buckets depends on the selected time granularity
    const numBuckets = timeBucket === "1h" ? 12 : timeBucket === "1d" ? 24 : 28;
    const interval = Math.max(1, (maxTime - minTime) / numBuckets);

    const buckets: { timeLabel: string; avgScore: number; criticalCount: number }[] = [];
    for (let i = 0; i < numBuckets; i++) {
      const bStart = minTime + i * interval;
      const bEnd = bStart + interval;
      const bucketSessions = sorted.filter((s) => s.first_seen >= bStart && s.first_seen < bEnd);
      const avg = bucketSessions.length
        ? Math.round(bucketSessions.reduce((acc, s) => acc + s.risk_score, 0) / bucketSessions.length)
        : 0;
      const crit = bucketSessions.filter((s) => s.risk_band === "CRITICAL").length;
      const d = new Date(bStart * 1000);
      buckets.push({
        timeLabel: `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`,
        avgScore: avg,
        criticalCount: crit,
      });
    }
    return buckets;
  }, [analysis.sessions, timeBucket]);

  return (
    <div style={{ padding: "8px 16px", maxWidth: 1400, margin: "0 auto" }}>
      {/* Top Metric Bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 16 }}>
        <div className="card" style={{ padding: "12px 16px", borderLeft: "4px solid #ef4444" }}>
          <div style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Overall Risk Score</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginTop: 4 }}>
            <span style={{ fontSize: 24, fontWeight: 800, color: RISK_BAND_COLORS[analysis.overall_risk_band] }}>
              {analysis.overall_risk_score.toFixed(1)}
            </span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>/ 100</span>
            <span className={`badge badge-${analysis.overall_risk_band}`} style={{ marginLeft: "auto" }}>
              {analysis.overall_risk_band}
            </span>
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Total Sessions</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginTop: 4 }}>
            {analysis.total_sessions.toLocaleString()}
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Total Packets</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: "#38bdf8", marginTop: 4 }}>
            {analysis.total_packets.toLocaleString()}
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Cryptographic Findings</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: "#f59e0b", marginTop: 4 }}>
            {analysis.findings.length}
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Anomalous Flows</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: "#a855f7", marginTop: 4 }}>
            {analysis.sessions.filter((s: SessionDetailSchema) => s.is_anomaly).length}
          </div>
        </div>
      </div>

      {/* Row 1: Interactive Donut & Top Findings */}
      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1.9fr", gap: 16, marginBottom: 16 }}>
        {/* Risk Distribution Donut (Interactive Filter) */}
        <div className="card" style={{ padding: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
              <ShieldAlert size={16} color="#38bdf8" />
              Risk Distribution (Click to Filter)
            </h3>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>NIST SP 800-57 Bands</span>
          </div>

          <div style={{ height: 210, width: "100%", display: "flex", alignItems: "center" }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskDistribution}
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                  cursor="pointer"
                  onClick={(entry) => onFilterSessions({ risk_band: entry.name })}
                >
                  {riskDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#0f172a", borderColor: "#334155", borderRadius: 6, fontSize: 12 }}
                  formatter={(val: any, name: any) => [`${val} sessions (${Math.round((Number(val) / (analysis.total_sessions || 1)) * 100)}%)`, String(name)]}
                />
              </PieChart>
            </ResponsiveContainer>

            <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 130 }}>
              {riskDistribution.map((r) => (
                <div
                  key={r.name}
                  onClick={() => onFilterSessions({ risk_band: r.name })}
                  style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 11.5, cursor: "pointer", padding: "2px 6px", borderRadius: 4, background: "rgba(255,255,255,0.02)" }}
                  title={`Filter table to ${r.name}`}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: r.color }} />
                    <span style={{ color: "#f8fafc", fontWeight: 500 }}>{r.name}</span>
                  </div>
                  <span className="font-mono" style={{ color: "var(--text-muted)", fontWeight: 600 }}>{r.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Forensic Findings Table */}
        <div className="card" style={{ padding: 18, overflowX: "auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
              <AlertTriangle size={16} color="#f59e0b" />
              Critical Forensic Findings & Policy Vetoes ({analysis.findings.length})
            </h3>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => onFilterSessions({ risk_band: "CRITICAL" })}
              style={{ fontSize: 11 }}
            >
              <Filter size={12} />
              View Critical Flows
            </button>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-subtle)", textAlign: "left", color: "var(--text-muted)", fontSize: 11 }}>
                <th style={{ padding: "6px 8px" }}>Severity</th>
                <th style={{ padding: "6px 8px" }}>Rule ID</th>
                <th style={{ padding: "6px 8px" }}>Finding Description</th>
                <th style={{ padding: "6px 8px" }}>Standard Reference</th>
                <th style={{ padding: "6px 8px", textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {analysis.findings.slice(0, 5).map((f: FindingSchema) => (
                <tr key={f.id} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.04)" }}>
                  <td style={{ padding: "8px 8px" }}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                  </td>
                  <td className="font-mono" style={{ padding: "8px 8px", color: "#38bdf8", fontSize: 11 }}>
                    {f.rule_id}
                  </td>
                  <td style={{ padding: "8px 8px", color: "#f8fafc", maxWidth: 280 }}>
                    <b>{f.title}</b>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.description}
                    </div>
                  </td>
                  <td style={{ padding: "8px 8px", color: "var(--text-secondary)", fontSize: 11 }}>
                    {f.standards_ref}
                  </td>
                  <td style={{ padding: "8px 8px", textAlign: "right" }}>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => onFilterSessions({ search: f.session_id })}
                      style={{ padding: "2px 6px", fontSize: 10.5 }}
                    >
                      Inspect &rarr;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 2: STARTTLS MX Health & Time Series Trend */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        {/* STARTTLS Health per MX */}
        <div className="card" style={{ padding: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
              <Lock size={16} color="#10b981" />
              STARTTLS Upgrade Health per Destination MX (Worst First)
            </h3>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Success %</span>
          </div>

          <div style={{ height: 210, width: "100%" }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={starttlsHealth} layout="vertical" margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" domain={[0, 100]} stroke="#64748b" fontSize={11} unit="%" />
                <YAxis dataKey="mx" type="category" stroke="#94a3b8" fontSize={11} width={130} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", borderColor: "#334155", borderRadius: 6, fontSize: 12 }}
                  formatter={(val: any) => [`${val}% Upgrade Success`, "Health"]}
                />
                <Bar
                  dataKey="successRate"
                  fill="#0284c7"
                  radius={[0, 4, 4, 0]}
                  cursor="pointer"
                  onClick={(data: any) => onFilterSessions({ search: data.fullMx })}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Trend over Capture Duration */}
        <div className="card" style={{ padding: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
              <Activity size={16} color="#38bdf8" />
              Cryptographic Risk Trend Over Time
            </h3>
            <div style={{ display: "flex", gap: 4 }}>
              {(["1h", "1d", "1w"] as const).map((b) => (
                <button
                  key={b}
                  onClick={() => setTimeBucket(b)}
                  className={`btn btn-sm ${timeBucket === b ? "btn-primary" : "btn-secondary"}`}
                  style={{ padding: "2px 8px", fontSize: 10.5 }}
                >
                  {b}
                </button>
              ))}
            </div>
          </div>

          <div style={{ height: 210, width: "100%" }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeriesTrend} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="timeLabel" stroke="#64748b" fontSize={11} />
                <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ background: "#0f172a", borderColor: "#334155", borderRadius: 6, fontSize: 12 }} />
                <Line type="monotone" dataKey="avgScore" name="Avg Risk Score" stroke="#38bdf8" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="criticalCount" name="Critical Events" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 3: TLS Versions & JA3 Top Fingerprints */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* TLS Versions */}
        <div className="card" style={{ padding: 18 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <Layers size={16} color="#a855f7" />
            Protocol & TLS Version Distribution
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {tlsVersions.map((t) => (
              <div
                key={t.version}
                onClick={() => onFilterSessions({ search: t.version })}
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 12px", borderRadius: 6, background: "rgba(0,0,0,0.25)", border: "1px solid var(--border-subtle)", cursor: "pointer" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="badge badge-SECURE" style={{ background: t.version.includes("1.3") ? "rgba(6,182,212,0.15)" : "#1e293b" }}>{t.version}</span>
                </div>
                <span className="font-mono" style={{ fontWeight: 700, color: "#f8fafc" }}>{t.count} sessions</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top JA3 Fingerprints */}
        <div className="card" style={{ padding: 18 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <Activity size={16} color="#38bdf8" />
            Top JA3 Client Fingerprints
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {ja3Frequencies.map((j) => (
              <div
                key={j.ja3}
                onClick={() => onFilterSessions({ search: j.ja3 })}
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 12px", borderRadius: 6, background: "rgba(0,0,0,0.25)", border: "1px solid var(--border-subtle)", cursor: "pointer" }}
              >
                <div>
                  <div className="font-mono" style={{ fontSize: 11, color: "#38bdf8", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {j.ja3}
                  </div>
                  <div style={{ fontSize: 10.5, color: "var(--text-muted)", marginTop: 2 }}>
                    Seen: {new Date(j.first * 1000).toLocaleTimeString()} - {new Date(j.last * 1000).toLocaleTimeString()}
                  </div>
                </div>
                <span className="font-mono" style={{ fontWeight: 700, color: "#f8fafc" }}>{j.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
