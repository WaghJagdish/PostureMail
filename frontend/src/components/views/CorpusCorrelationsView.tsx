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
import { Network, ArrowRight } from "lucide-react";
import { AnalysisDetailResponse, SessionDetailSchema } from "../../api/client";
import { IndustrialCard } from "../common/IndustrialCard";
import { TactileButton } from "../common/TactileButton";
import { LedIndicator } from "../common/LedIndicator";

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

  // Derive temporal groups
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

    // Client-side grouping fallback
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
          explanation: [`Only ${count} communication events observed (threshold >= 5).`],
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

      let score = 20;
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

  // Aggregate summary counts
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
    <div style={{ maxWidth: 1400, margin: "0 auto", paddingBottom: 32 }}>

      {/* ── Top Context Station ── */}
      <IndustrialCard elevation="base" bolted={true} vents={true} tag="TEMPORAL SIGNAL CORRELATOR & RADAR" style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 14 }}>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 800, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: 10 }} className="text-embossed-light">
              <Network size={20} color="var(--accent)" />
              AUTOMATED BEACONING & PERIODIC TIMING DISCRIMINATION
            </h2>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 4, maxWidth: 900 }}>
              Evaluates inter-arrival timing regularity (mean recurrence period, CoV, jitter percentage) across repeated sessions between endpoint pairs. Identifies automated beacon candidates without claiming malicious intent.
            </p>
          </div>

          <LedIndicator status="green" label="FFT ENGINE READY" size="sm" />
        </div>

        {/* Behavioral KPI Summary Meters */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginTop: 20 }}>
          <div
            style={{
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 10,
              padding: "12px 16px",
              borderLeft: "4px solid #ef4444",
            }}
          >
            <div className="stamped-label" style={{ fontSize: 9.5, color: "#ef4444" }}>AUTOMATED CANDIDATES</div>
            <div className="tabular-mono" style={{ fontSize: 24, fontWeight: 900, color: "var(--text-primary)", marginTop: 2 }}>
              {summaryCounts.beaconCandidates}
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
              SCORE &ge; 70 (HIGH REGULARITY)
            </div>
          </div>

          <div
            style={{
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 10,
              padding: "12px 16px",
              borderLeft: "4px solid #f59e0b",
            }}
          >
            <div className="stamped-label" style={{ fontSize: 9.5, color: "#f59e0b" }}>SUSPICIOUS TIMING</div>
            <div className="tabular-mono" style={{ fontSize: 24, fontWeight: 900, color: "var(--text-primary)", marginTop: 2 }}>
              {summaryCounts.suspiciousTiming}
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
              SCORE 40-69 (MODERATE JITTER)
            </div>
          </div>

          <div
            style={{
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 10,
              padding: "12px 16px",
              borderLeft: "4px solid #babecc",
            }}
          >
            <div className="stamped-label" style={{ fontSize: 9.5 }}>INSUFFICIENT DATA</div>
            <div className="tabular-mono" style={{ fontSize: 24, fontWeight: 900, color: "var(--text-primary)", marginTop: 2 }}>
              {summaryCounts.insufficientData}
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
              &lt; 5 SESSIONS OBSERVED
            </div>
          </div>

          <div
            style={{
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 10,
              padding: "12px 16px",
              borderLeft: "4px solid var(--accent)",
            }}
          >
            <div className="stamped-label" style={{ fontSize: 9.5, color: "var(--accent)" }}>MONITORED ENDPOINTS</div>
            <div className="tabular-mono" style={{ fontSize: 24, fontWeight: 900, color: "var(--accent)", marginTop: 2 }}>
              {summaryCounts.analyzedGroups}
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
              CANONICAL 4-TUPLE PAIRS
            </div>
          </div>
        </div>
      </IndustrialCard>

      {/* ── Main Grid: Visual Scatter Oscilloscope & Inspector ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1.6fr", gap: 20, marginBottom: 20 }}>

        {/* Scatter Plot Oscilloscope */}
        <IndustrialCard elevation="base" bolted={true} tag="RECURRENCE INTERVAL VS. JITTER (%) PLOT">
          <div style={{ height: 280, width: "100%" }}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#babecc" />
                <XAxis
                  type="number"
                  dataKey="x"
                  name="Interval (s)"
                  unit="s"
                  stroke="#4a5568"
                  fontSize={10}
                  label={{ value: "Mean Recurrence Period (seconds)", position: "insideBottom", offset: -5, fill: "#4a5568", fontSize: 10 }}
                />
                <YAxis
                  type="number"
                  dataKey="y"
                  name="Jitter (%)"
                  unit="%"
                  stroke="#4a5568"
                  fontSize={10}
                  label={{ value: "Jitter (%)", angle: -90, position: "insideLeft", fill: "#4a5568", fontSize: 10 }}
                />
                <ZAxis type="number" dataKey="z" range={[60, 400]} name="Event Count" />
                <Tooltip
                  cursor={{ strokeDasharray: "3 3" }}
                  content={({ active, payload }: any) => {
                    if (!active || !payload?.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div style={{ background: "#1e242b", border: "1px solid #14181d", borderRadius: 8, padding: "8px 12px", color: "#fff", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                        <div style={{ fontWeight: 800, color: "var(--accent)" }}>{d.name}</div>
                        <div>Interval: {d.x}s · Jitter: {d.y}%</div>
                        <div>Events: {d.z} · Score: {d.score}</div>
                      </div>
                    );
                  }}
                />
                <Scatter
                  name="Endpoints"
                  data={scatterData}
                  fill="var(--accent)"
                  onClick={(entry: any) => {
                    if (entry && entry.rawGroup) setSelectedGroup(entry.rawGroup);
                  }}
                />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </IndustrialCard>

        {/* Explainability Inspector Box */}
        <IndustrialCard elevation="base" bolted={true} tag="BEHAVIORAL EVIDENCE EXPLAINER">
          {activeGroup ? (
            <div
              style={{
                background: "var(--recessed)",
                boxShadow: "var(--shadow-recessed)",
                borderRadius: 10,
                padding: 16,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, paddingBottom: 10, borderBottom: "1px solid rgba(186,190,204,0.4)" }}>
                <div>
                  <span className="stamped-label" style={{ fontSize: 9.5 }}>TARGET ENDPOINT PAIR:</span>
                  <div className="tabular-mono" style={{ fontSize: 13, fontWeight: 800, color: "var(--accent)", marginTop: 2 }}>
                    {activeGroup.pair}
                  </div>
                </div>
                <div>
                  <span className={`risk-plaque risk-plaque-${activeGroup.classification === "BEACON_CANDIDATE" ? "CRITICAL" : activeGroup.classification === "SUSPICIOUS_TIMING" ? "WEAK" : "SECURE"}`}>
                    {activeGroup.classification.replace(/_/g, " ")}
                  </span>
                </div>
              </div>

              <div className="stamped-label" style={{ fontSize: 10, marginBottom: 6, color: "var(--text-primary)" }}>
                DIAGNOSTIC EVIDENCE METRICS:
              </div>
              <ul style={{ margin: "0 0 14px 18px", padding: 0, fontSize: 11.5, fontFamily: "var(--font-mono)", color: "var(--text-secondary)", lineHeight: 1.7 }}>
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
                  </>
                )}
              </ul>

              <div style={{ background: "var(--chassis)", borderLeft: "3px solid var(--accent)", padding: "8px 12px", borderRadius: "0 6px 6px 0", marginBottom: 14 }}>
                <div className="stamped-label" style={{ fontSize: 9.5, color: "var(--accent)" }}>ANALYST INTERPRETATION</div>
                <div style={{ fontSize: 11.5, color: "var(--text-primary)", marginTop: 2, fontFamily: "var(--font-mono)" }}>
                  {activeGroup.analyst_note || "Regular automated communication pattern requiring investigation."}
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <TactileButton
                  variant="primary"
                  size="sm"
                  onClick={() => onFilterSessions({ search: activeGroup.src_ip })}
                  iconRight={<ArrowRight size={12} />}
                >
                  FILTER IN SWITCHBOARD ({activeGroup.event_count})
                </TactileButton>
              </div>
            </div>
          ) : (
            <div style={{ color: "var(--text-muted)", fontSize: 12, padding: 30, textAlign: "center" }}>
              SELECT AN ENDPOINT PAIR TO INSPECT SKEUOMORPHIC SIGNAL PROVENANCE
            </div>
          )}
        </IndustrialCard>
      </div>

      {/* ── Communication Groups Table ── */}
      <IndustrialCard elevation="base" bolted={true} vents={true} tag={`ANALYZED FLOW RACK (${temporalGroups.length})`}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
            <thead>
              <tr style={{ borderBottom: "2px solid #babecc", textAlign: "left" }}>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>ENDPOINT PAIR</th>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>EVENTS</th>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>PERIOD</th>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>JITTER</th>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>COV</th>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>SCORE</th>
                <th className="stamped-label" style={{ padding: "8px 10px" }}>CLASSIFICATION</th>
                <th className="stamped-label" style={{ padding: "8px 10px", textAlign: "right" }}></th>
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
                      borderBottom: "1px solid rgba(186,190,204,0.35)",
                      cursor: "pointer",
                      background: isSelected ? "rgba(255, 71, 87, 0.08)" : undefined,
                      borderLeft: isSelected ? "3px solid var(--accent)" : "3px solid transparent",
                    }}
                  >
                    <td className="tabular-mono" style={{ padding: "9px 10px", fontWeight: 700, color: "var(--text-primary)" }}>
                      {b.pair}
                    </td>
                    <td className="tabular-mono" style={{ padding: "9px 10px" }}>
                      {b.event_count}
                    </td>
                    <td className="tabular-mono" style={{ padding: "9px 10px", color: b.mean_interval !== null ? "var(--accent)" : "var(--text-muted)" }}>
                      {b.mean_interval !== null ? `${b.mean_interval}s` : "N/A"}
                    </td>
                    <td
                      className="tabular-mono"
                      style={{
                        padding: "9px 10px",
                        color: b.jitter_pct !== null ? (b.jitter_pct < 15 ? "#ef4444" : "var(--text-secondary)") : "var(--text-muted)",
                      }}
                    >
                      {b.jitter_pct !== null ? `${b.jitter_pct}%` : "N/A"}
                    </td>
                    <td className="tabular-mono" style={{ padding: "9px 10px", color: b.cv !== null ? "#10b981" : "var(--text-muted)" }}>
                      {b.cv !== null ? b.cv : "N/A"}
                    </td>
                    <td className="tabular-mono" style={{ padding: "9px 10px", fontWeight: 800, color: b.behavior_score >= 70 ? "#ef4444" : b.behavior_score >= 40 ? "#f59e0b" : "var(--text-muted)" }}>
                      {b.behavior_score}
                    </td>
                    <td style={{ padding: "9px 10px" }}>
                      <span className={`risk-plaque risk-plaque-${b.classification === "BEACON_CANDIDATE" ? "CRITICAL" : b.classification === "SUSPICIOUS_TIMING" ? "WEAK" : "SECURE"}`} style={{ fontSize: 9.5 }}>
                        {b.classification.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td style={{ padding: "9px 10px", textAlign: "right" }}>
                      <TactileButton
                        variant="chassis"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedGroup(b);
                        }}
                      >
                        DISSECT →
                      </TactileButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </IndustrialCard>
    </div>
  );
};
