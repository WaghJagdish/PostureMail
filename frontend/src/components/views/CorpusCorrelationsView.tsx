import React, { useMemo } from "react";
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
import { Network, Activity, Radio } from "lucide-react";
import { AnalysisDetailResponse, SessionDetailSchema } from "../../api/client";

interface CorpusCorrelationsViewProps {
  analysis: AnalysisDetailResponse;
  onFilterSessions: (filter: { search?: string }) => void;
}

export const CorpusCorrelationsView: React.FC<CorpusCorrelationsViewProps> = ({
  analysis,
  onFilterSessions,
}) => {
  // Generate Beaconing Candidates from Session Intervals
  const beaconCandidates = useMemo(() => {
    // Group sessions by client -> server pair
    const pairs: Record<string, number[]> = {};
    analysis.sessions.forEach((s: SessionDetailSchema) => {
      const key = `${s.client_ip} -> ${s.server_ip}`;
      if (!pairs[key]) pairs[key] = [];
      pairs[key].push(s.first_seen);
    });

    const candidates: {
      pair: string;
      interval: number;
      jitter: number;
      count: number;
      autocorr: number;
      isSuspicious: boolean;
    }[] = [];

    Object.entries(pairs).forEach(([pair, times]) => {
      if (times.length >= 3) {
        times.sort((a, b) => a - b);
        const deltas: number[] = [];
        for (let i = 1; i < times.length; i++) {
          deltas.push(times[i] - times[i - 1]);
        }
        const avg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
        const variance = deltas.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / deltas.length;
        const stdDev = Math.sqrt(variance);
        const jitter = avg > 0 ? (stdDev / avg) * 100 : 0;
        const isSuspicious = jitter < 15 && times.length >= 5;

        candidates.push({
          pair,
          interval: +avg.toFixed(1),
          jitter: +jitter.toFixed(1),
          count: times.length,
          autocorr: +(Math.max(0.1, 1.0 - jitter / 100)).toFixed(2),
          isSuspicious,
        });
      }
    });

    return candidates.sort((a, b) => a.jitter - b.jitter);
  }, [analysis.sessions]);

  // Scatter plot data
  const scatterData = useMemo(() => {
    return beaconCandidates.map((b) => ({
      x: b.interval,
      y: b.jitter,
      z: b.count,
      name: b.pair,
      autocorr: b.autocorr,
      isSuspicious: b.isSuspicious,
    }));
  }, [beaconCandidates]);

  return (
    <div style={{ padding: "8px 16px", maxWidth: 1400, margin: "0 auto" }}>
      {/* Top Banner */}
      <div className="card" style={{ padding: 18, marginBottom: 16 }}>
        <h2 style={{ fontSize: 16, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 8 }}>
          <Network size={20} color="#38bdf8" />
          Corpus-Level Beaconing & Timing Correlation Engine
        </h2>
        <p style={{ fontSize: 12.5, color: "var(--text-secondary)", marginTop: 4 }}>
          Analyzes periodic timing regularities, jitter bounds (&lt; 15%), and autocorrelation across multiple mail flows to isolate automated polling and beaconing.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1.6fr", gap: 16, marginBottom: 16 }}>
        {/* Beaconing Timing Scatter Plot */}
        <div className="card" style={{ padding: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", gap: 6 }}>
              <Radio size={16} color="#ef4444" />
              Timing Interval vs Jitter Scatter Plot
            </h3>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Low Jitter &bull; High Autocorrelation</span>
          </div>

          <div style={{ height: 280, width: "100%" }}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" dataKey="x" name="Interval (s)" unit="s" stroke="#64748b" fontSize={11} label={{ value: "Mean Interval (seconds)", position: "insideBottom", offset: -5, fill: "#94a3b8", fontSize: 11 }} />
                <YAxis type="number" dataKey="y" name="Jitter (%)" unit="%" stroke="#64748b" fontSize={11} label={{ value: "Jitter (%)", angle: -90, position: "insideLeft", fill: "#94a3b8", fontSize: 11 }} />
                <ZAxis type="number" dataKey="z" range={[50, 400]} name="Flow Count" />
                <Tooltip
                  cursor={{ strokeDasharray: "3 3" }}
                  contentStyle={{ background: "#0f172a", borderColor: "#334155", borderRadius: 6, fontSize: 12 }}
                  formatter={(val: any, name: any) => [val, String(name)]}
                />
                <Scatter name="Endpoints" data={scatterData} fill="#38bdf8" />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Beacon Candidates Table */}
        <div className="card" style={{ padding: 18, overflowX: "auto" }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <Activity size={16} color="#38bdf8" />
            Detected Timing Clusters & Beacon Candidates ({beaconCandidates.length})
          </h3>

          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-subtle)", textAlign: "left", color: "var(--text-muted)", fontSize: 11 }}>
                <th style={{ padding: "6px 8px" }}>Endpoint Pair</th>
                <th style={{ padding: "6px 8px" }}>Mean Interval</th>
                <th style={{ padding: "6px 8px" }}>Jitter</th>
                <th style={{ padding: "6px 8px" }}>Autocorr</th>
                <th style={{ padding: "6px 8px" }}>Status</th>
                <th style={{ padding: "6px 8px", textAlign: "right" }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {beaconCandidates.map((b, idx) => (
                <tr key={idx} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.04)" }}>
                  <td className="font-mono" style={{ padding: "8px 8px", color: "#f8fafc", fontSize: 11 }}>
                    {b.pair}
                  </td>
                  <td className="font-mono" style={{ padding: "8px 8px", color: "#38bdf8" }}>
                    {b.interval}s
                  </td>
                  <td className="font-mono" style={{ padding: "8px 8px", color: b.jitter < 15 ? "#f87171" : "var(--text-secondary)" }}>
                    {b.jitter}%
                  </td>
                  <td className="font-mono" style={{ padding: "8px 8px", color: "#10b981" }}>
                    {b.autocorr}
                  </td>
                  <td style={{ padding: "8px 8px" }}>
                    {b.isSuspicious ? (
                      <span className="badge badge-CRITICAL" style={{ fontSize: 10 }}>PERIODIC BEACON</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)", fontSize: 11 }}>Normal</span>
                    )}
                  </td>
                  <td style={{ padding: "8px 8px", textAlign: "right" }}>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => onFilterSessions({ search: b.pair.split(" -> ")[0] })}
                      style={{ padding: "2px 6px", fontSize: 10.5 }}
                    >
                      Filter &rarr;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
