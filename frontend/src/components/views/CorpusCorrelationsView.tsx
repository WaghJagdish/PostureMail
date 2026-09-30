import React, { useMemo, useState } from "react";
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ZAxis,
} from "recharts";
import { Network, Activity, Radio, Info } from "lucide-react";
import { AnalysisDetailResponse, SessionDetailSchema } from "../../api/client";

interface CorpusCorrelationsViewProps {
  analysis: AnalysisDetailResponse;
  onFilterSessions: (filter: { search?: string }) => void;
}

interface TemporalGroupDisplay {
  pair: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  event_count: number;
  mean_interval: number | null;
  jitter_pct: number | null;
  cv: number | null;
  duration: number;
  behavior_score: number;
  classification: "BEACON_CANDIDATE" | "SUSPICIOUS_TIMING" | "NORMAL" | "INSUFFICIENT_DATA" | string;
  explanation: string[];
  analyst_note: string;
}

export const CorpusCorrelationsView: React.FC<CorpusCorrelationsViewProps> = ({
  analysis,
  onFilterSessions,
}) => {
  const [selectedGroup, setSelectedGroup] = useState<TemporalGroupDisplay | null>(null);

  // Derive temporal groups from backend analysis.summary_data.temporal_groups or directly compute from sessions
  const temporalGroups: TemporalGroupDisplay[] = useMemo(() => {
    const rawGroups = (analysis.summary_data as any)?.temporal_groups;
    if (Array.isArray(rawGroups) && rawGroups.length > 0) {
      return rawGroups.map((g: any) => ({
        pair: `${g.src_ip} → ${g.dst_ip}:${g.dst_port || 25}`,
        src_ip: g.src_ip,
        dst_ip: g.dst_ip,
        dst_port: g.dst_port || 25,
        protocol: g.protocol || "TCP",
        event_count: g.event_count || 0,
        mean_interval: g.mean_interval,
        jitter_pct: g.jitter_pct,
        cv: g.cv,
        duration: g.duration || 0,
        behavior_score: g.behavior_score || 0,
        classification: g.classification || "INSUFFICIENT_DATA",
        explanation: g.explanation || [],
        analyst_note: g.analyst_note || "",
      }));
    }

    // Client-side grouping fallback (deterministic implementation matching Python engine)
    const pairs: Record<string, { sessions: SessionDetailSchema[]; times: number[] }> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      const key = `${s.client_ip} → ${s.server_ip}:${s.server_port}`;
      if (!pairs[key]) pairs[key] = { sessions: [], times: [] };
      pairs[key].sessions.push(s);
      pairs[key].times.push(s.first_seen);
    });

    const calculated: TemporalGroupDisplay[] = [];

    Object.entries(pairs).forEach(([pair, group]) => {
      const sortedTimes = [...group.times].sort((a, b) => a - b);
      const count = sortedTimes.length;
      const s0 = group.sessions[0];

      if (count < 5) {
        calculated.push({
          pair,
          src_ip: s0.client_ip,
          dst_ip: s0.server_ip,
          dst_port: s0.server_port,
          protocol: s0.protocol,
          event_count: count,
          mean_interval: null,
          jitter_pct: null,
          cv: null,
          duration: count > 1 ? +(sortedTimes[count - 1] - sortedTimes[0]).toFixed(1) : 0,
          behavior_score: 0,
          classification: "INSUFFICIENT_DATA",
          explanation: [`Only ${count} communication events observed (minimum threshold is 5).`],
          analyst_note: "Insufficient observations to perform reliable temporal timing analysis.",
        });
        return;
      }

      const deltas: number[] = [];
      for (let i = 1; i < count; i++) {
        const delta = sortedTimes[i] - sortedTimes[i - 1];
        if (delta > 0) deltas.push(delta);
      }

      if (deltas.length === 0) return;

      const avg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
      const variance = deltas.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / deltas.length;
      const stdDev = Math.sqrt(variance);
      const cv = avg > 0 ? stdDev / avg : 0;
      const jitter = cv * 100;
      const duration = sortedTimes[count - 1] - sortedTimes[0];

      let score = 20; // 5+ events
      const reasons: string[] = [`${count} communication events observed (>= 5)`];

      if (avg > 0) {
        score += 20;
        reasons.push(`Mean recurrence period: ${avg.toFixed(2)}s`);
      }
      if (jitter < 15) {
        score += 30;
        reasons.push(jitter < 5 ? `Highly regular timing: Jitter is ${jitter.toFixed(2)}% (< 5%)` : `Regular timing: Jitter is ${jitter.toFixed(2)}% (< 15%)`);
      } else {
        reasons.push(`Irregular timing: Jitter is ${jitter.toFixed(2)}% (>= 15%)`);
      }
      if (cv < 0.15) {
        score += 20;
        reasons.push(`Low timing variance: Coefficient of variation is ${cv.toFixed(4)} (< 0.15)`);
      }
      if (duration >= 300) {
        score += 10;
        reasons.push(`Observed communication persisted over ${duration.toFixed(1)}s (${(duration / 60).toFixed(1)} minutes)`);
      }

      let classification: "BEACON_CANDIDATE" | "SUSPICIOUS_TIMING" | "NORMAL" = "NORMAL";
      let analystNote = "Normal or irregular timing with no meaningful evidence of automated beaconing.";

      if (score >= 70) {
        classification = "BEACON_CANDIDATE";
        analystNote = "Regular automated communication pattern requiring investigation. Timing alone does not establish malicious activity.";
      } else if (score >= 40) {
        classification = "SUSPICIOUS_TIMING";
        analystNote = "Moderate timing regularity observed, but insufficient evidence to confirm an automated beacon candidate.";
      }

      calculated.push({
        pair,
        src_ip: s0.client_ip,
        dst_ip: s0.server_ip,
        dst_port: s0.server_port,
        protocol: s0.protocol,
        event_count: count,
        mean_interval: +avg.toFixed(2),
        jitter_pct: +jitter.toFixed(2),
        cv: +cv.toFixed(4),
        duration: +duration.toFixed(1),
        behavior_score: score,
        classification,
        explanation: reasons,
        analyst_note: analystNote,
      });
    });

    return calculated.sort((a, b) => b.behavior_score - a.behavior_score);
  }, [analysis]);

  // Aggregate summary counts (§20)
  const summaryCounts = useMemo(() => {
    const rawSummary = (analysis.summary_data as any)?.temporal_summary;
    if (rawSummary && rawSummary.analyzed_groups !== undefined) {
      return {
        beaconCandidates: rawSummary.beacon_candidates || 0,
        suspiciousTiming: rawSummary.suspicious_timing || 0,
        insufficientData: rawSummary.insufficient_data || 0,
        analyzedGroups: rawSummary.analyzed_groups || 0,
      };
    }

    let beaconCandidates = 0;
    let suspiciousTiming = 0;
    let insufficientData = 0;

    temporalGroups.forEach((g) => {
      if (g.classification === "BEACON_CANDIDATE") beaconCandidates++;
      else if (g.classification === "SUSPICIOUS_TIMING") suspiciousTiming++;
      else if (g.classification === "INSUFFICIENT_DATA") insufficientData++;
    });

    return {
      beaconCandidates,
      suspiciousTiming,
      insufficientData,
      analyzedGroups: temporalGroups.length,
    };
  }, [analysis, temporalGroups]);

  // Scatter plot data
  const scatterData = useMemo(() => {
    return temporalGroups
      .filter((g) => g.mean_interval !== null && g.jitter_pct !== null)
      .map((g) => ({
        x: g.mean_interval,
        y: g.jitter_pct,
        z: g.event_count,
        name: g.pair,
        score: g.behavior_score,
        classification: g.classification,
        rawGroup: g,
      }));
  }, [temporalGroups]);

  const activeGroup = selectedGroup || temporalGroups.find((g) => g.classification === "BEACON_CANDIDATE") || temporalGroups[0] || null;

  return (
    <div style={{ padding: "8px 16px", maxWidth: 1400, margin: "0 auto" }}>
      {/* Top Banner & Context Note */}
      <div className="card" style={{ padding: 18, marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 8 }}>
              <Network size={20} color="#38bdf8" />
              Behavioral Analysis: Automated Timing & Regular Polling Detection
            </h2>
            <p style={{ fontSize: 12.5, color: "#475569", marginTop: 4, maxWidth: 900 }}>
              Evaluates inter-arrival timing regularity (mean interval, standard deviation, CoV, jitter percentage) across repeated sessions between endpoint pairs. Identifies automated beacon candidates without claiming malicious intent.
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", background: "rgba(56, 189, 248, 0.08)", border: "1px solid rgba(56, 189, 248, 0.2)", borderRadius: 6, padding: "8px 12px" }}>
            <Info size={15} color="#38bdf8" />
            <span style={{ fontSize: 11.5, color: "#94a3b8" }}>
              <strong>Evidence Fusion:</strong> Operates alongside deterministic NIST SP 800-57 risk scoring.
            </span>
          </div>
        </div>

        {/* Behavioral Analysis KPI Summary Cards (§20) */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginTop: 16 }}>
          <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.25)", borderRadius: 6, padding: "10px 14px" }}>
            <div style={{ fontSize: 11, color: "#fca5a5", fontWeight: 600 }}>Automated Timing Candidates</div>
            <div className="font-mono" style={{ fontSize: 22, fontWeight: 800, color: "#ef4444", marginTop: 2 }}>
              {summaryCounts.beaconCandidates}
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>Score &ge; 70 (Requires Investigation)</div>
          </div>

          <div style={{ background: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.25)", borderRadius: 6, padding: "10px 14px" }}>
            <div style={{ fontSize: 11, color: "#fcd34d", fontWeight: 600 }}>Suspicious Timing Patterns</div>
            <div className="font-mono" style={{ fontSize: 22, fontWeight: 800, color: "#f59e0b", marginTop: 2 }}>
              {summaryCounts.suspiciousTiming}
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>Score 40-69 (Moderate Regularity)</div>
          </div>

          <div style={{ background: "rgba(100, 116, 139, 0.1)", border: "1px solid rgba(100, 116, 139, 0.25)", borderRadius: 6, padding: "10px 14px" }}>
            <div style={{ fontSize: 11, color: "#94a3b8", fontWeight: 600 }}>Insufficient Data</div>
            <div className="font-mono" style={{ fontSize: 22, fontWeight: 800, color: "#cbd5e1", marginTop: 2 }}>
              {summaryCounts.insufficientData}
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>&lt; 5 Events (No Score Fabricated)</div>
          </div>

          <div style={{ background: "rgba(56, 189, 248, 0.08)", border: "1px solid rgba(56, 189, 248, 0.2)", borderRadius: 6, padding: "10px 14px" }}>
            <div style={{ fontSize: 11, color: "#7dd3fc", fontWeight: 600 }}>Analyzed Endpoint Pairs</div>
            <div className="font-mono" style={{ fontSize: 22, fontWeight: 800, color: "#38bdf8", marginTop: 2 }}>
              {summaryCounts.analyzedGroups}
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>Canonical 4-Tuple Flows</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Visual Scatter Plot & Inspector */}
      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1.6fr", gap: 16, marginBottom: 16 }}>
        {/* Scatter Plot */}
        <div className="card" style={{ padding: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
              <Radio size={16} color="#38bdf8" />
              Timing Interval vs. Jitter (%) Distribution
            </h3>
            <span style={{ fontSize: 11, color: "#64748b" }}>Low Jitter (&lt;15%) &bull; High Regularity</span>
          </div>

          <div style={{ height: 280, width: "100%" }}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis
                  type="number"
                  dataKey="x"
                  name="Interval (s)"
                  unit="s"
                  stroke="#64748b"
                  fontSize={11}
                  label={{ value: "Mean Recurrence Period (seconds)", position: "insideBottom", offset: -5, fill: "#94a3b8", fontSize: 11 }}
                />
                <YAxis
                  type="number"
                  dataKey="y"
                  name="Jitter (%)"
                  unit="%"
                  stroke="#64748b"
                  fontSize={11}
                  label={{ value: "Jitter (%)", angle: -90, position: "insideLeft", fill: "#94a3b8", fontSize: 11 }}
                />
                <ZAxis type="number" dataKey="z" range={[60, 400]} name="Event Count" />
                <Tooltip
                  cursor={{ strokeDasharray: "3 3" }}
                  contentStyle={{ background: "#fff", borderColor: "#e2e6f0", borderRadius: 6, fontSize: 12 }}
                  formatter={(val: any, name: any) => [val, String(name)]}
                />
                <Scatter
                  name="Endpoints"
                  data={scatterData}
                  fill="#38bdf8"
                  onClick={(entry: any) => {
                    if (entry && entry.rawGroup) setSelectedGroup(entry.rawGroup);
                  }}
                />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Explainability Inspector Box (§21) */}
        <div className="card" style={{ padding: 18 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
            <Activity size={16} color="#38bdf8" />
            Behavioral Evidence Explanation
          </h3>

          {activeGroup ? (
            <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle)", borderRadius: 6, padding: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, paddingBottom: 8, borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                <div>
                  <span style={{ fontSize: 11, color: "#64748b" }}>Target Endpoint Pair:</span>
                  <div className="font-mono" style={{ fontSize: 13, fontWeight: 700, color: "#38bdf8" }}>{activeGroup.pair}</div>
                </div>
                <div>
                  <span
                    className={`badge badge-${
                      activeGroup.classification === "BEACON_CANDIDATE"
                        ? "CRITICAL"
                        : activeGroup.classification === "SUSPICIOUS_TIMING"
                        ? "HIGH"
                        : "LOW"
                    }`}
                    style={{ fontSize: 11, padding: "4px 8px" }}
                  >
                    {activeGroup.classification.replace(/_/g, " ")}
                  </span>
                </div>
              </div>

              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", marginBottom: 6 }}>
                Why was this flagged?
              </div>
              <ul style={{ margin: "0 0 12px 18px", padding: 0, fontSize: 12, color: "#475569", lineHeight: 1.6 }}>
                {activeGroup.explanation.length > 0 ? (
                  activeGroup.explanation.map((reason, idx) => (
                    <li key={idx}><strong>•</strong> {reason}</li>
                  ))
                ) : (
                  <>
                    <li>• {activeGroup.event_count} communication events observed</li>
                    {activeGroup.mean_interval !== null && <li>• Mean interval: {activeGroup.mean_interval} seconds</li>}
                    {activeGroup.jitter_pct !== null && <li>• Jitter: {activeGroup.jitter_pct}%</li>}
                    {activeGroup.cv !== null && <li>• Coefficient of variation: {activeGroup.cv}</li>}
                    {activeGroup.duration > 0 && <li>• Communication persisted for {(activeGroup.duration / 60).toFixed(1)} minutes</li>}
                  </>
                )}
              </ul>

              <div style={{ background: "rgba(30, 41, 59, 0.5)", borderLeft: "3px solid #38bdf8", padding: "8px 12px", borderRadius: "0 4px 4px 0", marginBottom: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8", textTransform: "uppercase" }}>Forensic Interpretation</div>
                <div style={{ fontSize: 11.5, color: "#e2e8f0", marginTop: 2 }}>
                  {activeGroup.analyst_note || "Regular automated communication pattern requiring investigation. Timing alone does not establish malicious activity."}
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => onFilterSessions({ search: activeGroup.src_ip })}
                  style={{ fontSize: 11 }}
                >
                  Filter Associated Sessions ({activeGroup.event_count}) &rarr;
                </button>
              </div>
            </div>
          ) : (
            <div style={{ color: "#64748b", fontSize: 12, padding: 30, textAlign: "center" }}>
              Select an endpoint pair from the table below to inspect underlying evidence.
            </div>
          )}
        </div>
      </div>

      {/* Recommended Table (§20) */}
      <div className="card" style={{ padding: 18, overflowX: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
            <Activity size={16} color="#38bdf8" />
            Analyzed Communication Groups & Behavioral Regularity ({temporalGroups.length})
          </h3>
          <span style={{ fontSize: 11, color: "#64748b" }}>
            Sorted by Regularity Score &bull; Click row to inspect explanation
          </span>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border-subtle)", textAlign: "left", color: "#64748b", fontSize: 11 }}>
              <th style={{ padding: "8px 10px" }}>Endpoint Pair</th>
              <th style={{ padding: "8px 10px" }}>Connections</th>
              <th style={{ padding: "8px 10px" }}>Mean Interval</th>
              <th style={{ padding: "8px 10px" }}>Jitter (%)</th>
              <th style={{ padding: "8px 10px" }}>CV</th>
              <th style={{ padding: "8px 10px" }}>Score</th>
              <th style={{ padding: "8px 10px" }}>Classification</th>
              <th style={{ padding: "8px 10px", textAlign: "right" }}>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {temporalGroups.map((b, idx) => {
              const isSelected = activeGroup?.pair === b.pair;
              return (
                <tr
                  key={idx}
                  onClick={() => setSelectedGroup(b)}
                  style={{
                    borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                    cursor: "pointer",
                    background: isSelected ? "rgba(56, 189, 248, 0.08)" : undefined,
                  }}
                >
                  <td className="font-mono" style={{ padding: "9px 10px", color: "#0f172a", fontSize: 11 }}>
                    {b.pair}
                  </td>
                  <td className="font-mono" style={{ padding: "9px 10px", color: "#cbd5e1" }}>
                    {b.event_count}
                  </td>
                  <td className="font-mono" style={{ padding: "9px 10px", color: b.mean_interval !== null ? "#38bdf8" : "var(--text-muted)" }}>
                    {b.mean_interval !== null ? `${b.mean_interval}s` : "N/A"}
                  </td>
                  <td
                    className="font-mono"
                    style={{
                      padding: "9px 10px",
                      color: b.jitter_pct !== null ? (b.jitter_pct < 15 ? "#f87171" : "var(--text-secondary)") : "var(--text-muted)",
                    }}
                  >
                    {b.jitter_pct !== null ? `${b.jitter_pct}%` : "N/A"}
                  </td>
                  <td className="font-mono" style={{ padding: "9px 10px", color: b.cv !== null ? "#10b981" : "var(--text-muted)" }}>
                    {b.cv !== null ? b.cv : "N/A"}
                  </td>
                  <td className="font-mono" style={{ padding: "9px 10px", fontWeight: 700, color: b.behavior_score >= 70 ? "#ef4444" : b.behavior_score >= 40 ? "#f59e0b" : "var(--text-muted)" }}>
                    {b.behavior_score}
                  </td>
                  <td style={{ padding: "9px 10px" }}>
                    <span
                      className={`badge badge-${
                        b.classification === "BEACON_CANDIDATE"
                          ? "CRITICAL"
                          : b.classification === "SUSPICIOUS_TIMING"
                          ? "HIGH"
                          : "LOW"
                      }`}
                      style={{ fontSize: 10 }}
                    >
                      {b.classification.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td style={{ padding: "9px 10px", textAlign: "right" }}>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedGroup(b);
                      }}
                      style={{ padding: "3px 8px", fontSize: 10.5 }}
                    >
                      View &rarr;
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
