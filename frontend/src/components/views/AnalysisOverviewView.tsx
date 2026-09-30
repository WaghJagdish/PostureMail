import React, { useState, useMemo } from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, LineChart, Line, CartesianGrid, Legend,
} from "recharts";
import { ShieldAlert, AlertTriangle, Lock, Activity, Layers, Filter, TrendingUp, Globe } from "lucide-react";
import { AnalysisDetailResponse, SessionDetailSchema, FindingSchema } from "../../api/client";
import { IndustrialCard } from "../common/IndustrialCard";
import { TactileButton } from "../common/TactileButton";

interface AnalysisOverviewViewProps {
  analysis: AnalysisDetailResponse;
  onFilterSessions: (filter: { risk_band?: string; protocol?: string; cipher?: string; search?: string }) => void;
}

const RISK_BAND_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  WEAK: "#f59e0b",
  ACCEPTABLE: "#06b6d4",
  SECURE: "#10b981",
};

// ── Reusable Hardware Meter Section Header ──
const SectionHeader: React.FC<{ icon: React.ReactNode; title: string; subtitle?: React.ReactNode }> = ({ icon, title, subtitle }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div
        style={{
          width: 32,
          height: 32,
          borderRadius: 8,
          background: "var(--chassis)",
          boxShadow: "var(--shadow-floating)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {icon}
      </div>
      <span className="tabular-mono" style={{ fontSize: 13, fontWeight: 800, letterSpacing: "0.04em", color: "var(--text-primary)" }}>
        {title}
      </span>
    </div>
    {subtitle && <div className="stamped-label" style={{ fontSize: 10.5, color: "var(--text-secondary)" }}>{subtitle}</div>}
  </div>
);

// ── Tactile KPI Hardware Meter ──
const MetricCard: React.FC<{
  label: string; value: string | number; sub?: string;
  accent: string; icon: React.ReactNode; band?: string;
}> = ({ label, value, sub, accent, icon, band }) => (
  <div
    className="bolted-panel"
    style={{
      background: "var(--chassis)",
      borderRadius: 14,
      padding: "16px 18px",
      boxShadow: "var(--shadow-card)",
      border: "1px solid rgba(255,255,255,0.6)",
      display: "flex",
      flexDirection: "column",
      gap: 10,
    }}
  >
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", paddingLeft: 10 }}>
      <span className="stamped-label" style={{ fontSize: 9.5 }}>{label}</span>
      <div
        style={{
          width: 26,
          height: 26,
          borderRadius: 6,
          background: "var(--recessed)",
          boxShadow: "var(--shadow-recessed)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {icon}
      </div>
    </div>

    {/* Recessed Digital Readout */}
    <div
      style={{
        background: "var(--recessed)",
        boxShadow: "var(--shadow-recessed)",
        borderRadius: 8,
        padding: "8px 12px",
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
      }}
    >
      <span className="tabular-mono" style={{ fontSize: 22, fontWeight: 900, color: accent }}>
        {value}
      </span>
      {sub && <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>{sub}</span>}
    </div>

    {band && (
      <span className={`risk-plaque risk-plaque-${band}`} style={{ alignSelf: "flex-start" }}>
        {band}
      </span>
    )}
  </div>
);

// ── Industrial Tooltip ──
const ChartTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: "#1e242b",
        border: "1px solid #14181d",
        borderRadius: 8,
        padding: "8px 12px",
        boxShadow: "0 4px 14px rgba(0,0,0,0.4)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: "#ffffff",
      }}
    >
      {label && <div style={{ fontWeight: 700, color: "var(--accent)", marginBottom: 4 }}>{label}</div>}
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ color: p.color || "#e0e5ec", lineHeight: 1.4 }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
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
        color: ver === "TLS 1.3" ? "#10b981" : ver === "TLS 1.2" ? "#06b6d4" : ver === "TLS 1.0" ? "#f59e0b" : "#ef4444",
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

      {/* ── Top Industrial Meter Bar ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, marginBottom: 24 }}>
        <MetricCard
          label="OVERALL NIST RISK"
          value={analysis.overall_risk_score.toFixed(1)}
          sub="/ 100"
          accent={RISK_BAND_COLORS[analysis.overall_risk_band]}
          icon={<ShieldAlert size={15} color={RISK_BAND_COLORS[analysis.overall_risk_band]} />}
          band={analysis.overall_risk_band}
        />
        <MetricCard
          label="TOTAL REASSEMBLED FLOWS"
          value={analysis.total_sessions.toLocaleString()}
          accent="var(--text-primary)"
          icon={<Activity size={15} color="var(--accent)" />}
        />
        <MetricCard
          label="CAPTURED PACKETS"
          value={analysis.total_packets.toLocaleString()}
          accent="var(--text-primary)"
          icon={<Globe size={15} color="#06b6d4" />}
        />
        <MetricCard
          label="CRITICAL VETO BREACHES"
          value={criticalCount}
          sub={`OF ${analysis.findings.length}`}
          accent="#ef4444"
          icon={<AlertTriangle size={15} color="#ef4444" />}
        />
        <MetricCard
          label="94-DIM ML ANOMALIES"
          value={anomalyCount}
          accent="#8b5cf6"
          icon={<TrendingUp size={15} color="#8b5cf6" />}
        />
      </div>

      {/* ── Row 1: Donut Meter + Bolted Findings Table ── */}
      <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: 20, marginBottom: 20 }}>

        {/* Risk Distribution Meter */}
        <IndustrialCard elevation="base" bolted={true} vents={true} tag="BAND METRIC PROPORTIONS">
          <SectionHeader icon={<ShieldAlert size={15} color="var(--accent)" />} title="NIST RISK PROFILE" subtitle="CLICK TO FILTER" />
          <ResponsiveContainer width="100%" height={170}>
            <PieChart>
              <Pie
                data={riskDistribution}
                innerRadius={50}
                outerRadius={74}
                paddingAngle={3}
                dataKey="value"
                cursor="pointer"
                onClick={(e) => onFilterSessions({ risk_band: e.name })}
              >
                {riskDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.color} stroke="var(--chassis)" strokeWidth={3} />
                ))}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
            </PieChart>
          </ResponsiveContainer>

          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 10 }}>
            {riskDistribution.filter(r => r.value > 0).map((r) => (
              <div
                key={r.name}
                onClick={() => onFilterSessions({ risk_band: r.name })}
                className="tactile-btn tactile-btn-chassis"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "8px 12px",
                  borderRadius: 8,
                  fontSize: 11,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ width: 9, height: 9, borderRadius: 2, background: r.color, display: "inline-block" }} />
                  <span style={{ fontWeight: 700, color: "var(--text-primary)" }}>{r.name}</span>
                </div>
                <span className="tabular-mono" style={{ fontWeight: 800, color: r.color }}>
                  {r.value}
                </span>
              </div>
            ))}
          </div>
        </IndustrialCard>

        {/* Critical Forensic Findings Table */}
        <IndustrialCard
          elevation="base"
          bolted={true}
          vents={true}
          tag={`DIAGNOSTIC FINDINGS LOG (${analysis.findings.length})`}
          headerAction={
            <TactileButton
              variant="chassis"
              size="sm"
              onClick={() => onFilterSessions({ risk_band: "CRITICAL" })}
              icon={<Filter size={11} />}
            >
              FILTER CRITICAL
            </TactileButton>
          }
        >
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: "2px solid #babecc" }}>
                  {["SEVERITY", "RULE ID", "FINDING", "STANDARD REF", ""].map((h) => (
                    <th key={h} className="stamped-label" style={{ padding: "8px 10px", textAlign: "left", fontSize: 10, whiteSpace: "nowrap" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analysis.findings.slice(0, 6).map((f: FindingSchema) => (
                  <tr
                    key={f.id}
                    style={{ borderBottom: "1px solid rgba(186,190,204,0.35)", transition: "background 0.1s" }}
                  >
                    <td style={{ padding: "10px 8px" }}>
                      <span className={`risk-plaque risk-plaque-${f.severity}`}>{f.severity}</span>
                    </td>
                    <td className="tabular-mono" style={{ padding: "10px 8px", fontWeight: 700, color: "var(--accent)" }}>
                      {f.rule_id}
                    </td>
                    <td style={{ padding: "10px 8px", maxWidth: 280 }}>
                      <div style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: 12 }}>{f.title}</div>
                      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {f.description}
                      </div>
                    </td>
                    <td className="tabular-mono" style={{ padding: "10px 8px", fontSize: 11, color: "var(--text-muted)" }}>
                      {f.standards_ref}
                    </td>
                    <td style={{ padding: "10px 8px" }}>
                      <TactileButton
                        variant="chassis"
                        size="sm"
                        onClick={() => onFilterSessions({ search: f.session_id })}
                      >
                        INSPECT →
                      </TactileButton>
                    </td>
                  </tr>
                ))}
                {analysis.findings.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)" }}>
                      NO COMPROMISE FINDINGS RECORDED
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </IndustrialCard>
      </div>

      {/* ── Row 2: STARTTLS by MX & Risk Time-Series ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>

        {/* STARTTLS Health Bar Chart */}
        <IndustrialCard elevation="base" bolted={true} tag="STARTTLS PROTOCOL UPGRADE BY MX">
          <SectionHeader icon={<Lock size={15} color="#10b981" />} title="UPGRADE EFFICIENCY" subtitle="WORST FIRST • CLICK BAR TO FILTER" />
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={starttlsHealth} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#babecc" horizontal={false} />
              <XAxis type="number" domain={[0, 100]} stroke="#4a5568" fontSize={10} unit="%" tick={{ fill: "#4a5568" }} />
              <YAxis dataKey="mx" type="category" stroke="#4a5568" fontSize={10} width={130} tick={{ fill: "#2d3436" }} />
              <Tooltip content={<ChartTooltip />} formatter={(v: any) => [`${v}%`, "Upgrade Success"]} />
              <Bar
                dataKey="successRate"
                name="Upgrade %"
                fill="var(--accent)"
                radius={[0, 4, 4, 0]}
                cursor="pointer"
                onClick={(d: any) => onFilterSessions({ search: d.fullMx })}
              />
            </BarChart>
          </ResponsiveContainer>
        </IndustrialCard>

        {/* Cryptographic Risk Trend Line Chart */}
        <IndustrialCard
          elevation="base"
          bolted={true}
          tag="TEMPORAL RISK DRIFT"
          headerAction={
            <div style={{ display: "flex", gap: 4 }}>
              {(["1h", "1d", "1w"] as const).map((b) => (
                <TactileButton
                  key={b}
                  size="sm"
                  variant={timeBucket === b ? "recessed" : "chassis"}
                  active={timeBucket === b}
                  onClick={() => setTimeBucket(b)}
                  style={{ padding: "4px 10px", fontSize: 10 }}
                >
                  {b.toUpperCase()}
                </TactileButton>
              ))}
            </div>
          }
        >
          <SectionHeader icon={<Activity size={15} color="var(--accent)" />} title="RISK & ANOMALY TIMELINE" />
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={timeSeriesTrend} margin={{ top: 4, right: 16, left: -24, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#babecc" />
              <XAxis dataKey="t" stroke="#4a5568" fontSize={10} tick={{ fill: "#4a5568" }} />
              <YAxis domain={[0, 100]} stroke="#4a5568" fontSize={10} tick={{ fill: "#4a5568" }} />
              <Tooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 10, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }} />
              <Line type="monotone" dataKey="risk" name="AVG RISK" stroke="#2563eb" strokeWidth={2} dot={{ r: 2 }} activeDot={{ r: 5 }} />
              <Line type="monotone" dataKey="critical" name="CRITICAL PEAKS" stroke="var(--accent)" strokeWidth={2} dot={{ r: 2 }} activeDot={{ r: 5 }} />
            </LineChart>
          </ResponsiveContainer>
        </IndustrialCard>
      </div>

      {/* ── Row 3: TLS Version Racks & JA3 Fingerprints ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

        {/* TLS Version Distribution Rack */}
        <IndustrialCard elevation="base" bolted={true} tag="NEGOTIATED PROTOCOL VERSIONS">
          <SectionHeader icon={<Layers size={15} color="#8b5cf6" />} title="PROTOCOL VERSION COMPLIANCE" />
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {tlsVersions.map((t) => (
              <div
                key={t.version}
                onClick={() => onFilterSessions({ search: t.version })}
                className="tactile-btn tactile-btn-chassis"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "10px 14px",
                  borderRadius: 10,
                  cursor: "pointer",
                }}
              >
                <span style={{ width: 10, height: 10, borderRadius: 2, background: t.color, flexShrink: 0 }} />
                <span className="tabular-mono" style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: 12, flex: 1 }}>
                  {t.version}
                </span>

                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ width: 90, height: 8, background: "var(--recessed)", borderRadius: 4, overflow: "hidden", boxShadow: "var(--shadow-recessed)" }}>
                    <div style={{ width: `${t.pct}%`, height: "100%", background: t.color, borderRadius: 4 }} />
                  </div>
                  <span className="tabular-mono" style={{ fontWeight: 800, fontSize: 12, minWidth: 32, textAlign: "right" }}>
                    {t.count}
                  </span>
                  <span className="stamped-label" style={{ fontSize: 9.5, minWidth: 32, textAlign: "right" }}>
                    {t.pct}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </IndustrialCard>

        {/* JA3 Client Fingerprint Station */}
        <IndustrialCard elevation="base" bolted={true} tag="JA3 CLIENT CLASSIFICATION">
          <SectionHeader icon={<Activity size={15} color="#06b6d4" />} title="TOP JA3 CLIENT HASHES" subtitle="CLICK TO FILTER" />
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {ja3Frequencies.length === 0 ? (
              <div style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)" }}>
                NO JA3 FINGERPRINTS CAPTURED
              </div>
            ) : ja3Frequencies.map((j, idx) => (
              <div
                key={j.ja3}
                onClick={() => onFilterSessions({ search: j.ja3 })}
                className="tactile-btn tactile-btn-chassis"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "10px 14px",
                  borderRadius: 10,
                  cursor: "pointer",
                }}
              >
                <div
                  style={{
                    width: 24,
                    height: 24,
                    borderRadius: 6,
                    background: "var(--recessed)",
                    boxShadow: "var(--shadow-recessed)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontFamily: "var(--font-mono)",
                    fontSize: 10,
                    fontWeight: 800,
                    color: "var(--accent)",
                  }}
                >
                  #{idx + 1}
                </div>

                <div style={{ flex: 1, minWidth: 0, textAlign: "left" }}>
                  <div className="tabular-mono" style={{ fontSize: 11.5, color: "var(--text-primary)", fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {j.ja3}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, fontFamily: "var(--font-mono)" }}>
                    FIRST: {new Date(j.first * 1000).toLocaleTimeString()} · LAST: {new Date(j.last * 1000).toLocaleTimeString()}
                  </div>
                </div>

                <div
                  style={{
                    background: "var(--recessed)",
                    boxShadow: "var(--shadow-recessed)",
                    borderRadius: 6,
                    padding: "4px 10px",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    fontWeight: 800,
                    color: "var(--text-primary)",
                  }}
                >
                  {j.count}
                </div>
              </div>
            ))}
          </div>
        </IndustrialCard>
      </div>
    </div>
  );
};
