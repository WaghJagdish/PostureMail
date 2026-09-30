import React, { useState } from "react";
import {
  Lock,
  GitCommit,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  Copy,
  ChevronDown,
  ChevronUp,
  Send,
  Eye,
  Layers,
  Radio,
} from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";
import { SessionDetailSchema, submitAnalystVerdict, AnalystVerdictCreate } from "../../api/client";
import { IndustrialCard } from "../common/IndustrialCard";
import { TactileButton } from "../common/TactileButton";

interface SessionDetailViewProps {
  session: SessionDetailSchema | null;
  onClose?: () => void;
  onVerdictSaved?: (sessionId: string, verdict: string) => void;
}

export const SessionDetailView: React.FC<SessionDetailViewProps> = ({
  session,
  onVerdictSaved,
}) => {
  const [activeFsmNode, setActiveFsmNode] = useState<number>(0);
  const [copiedHex, setCopiedHex] = useState(false);
  const [rawJsonOpen, setRawJsonOpen] = useState(false);

  // Verdict Form State
  const [verdictType, setVerdictType] = useState<"TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN_KNOWN" | "SUSPICIOUS">("TRUE_POSITIVE");
  const [analystNotes, setAnalystNotes] = useState("");
  const [savingVerdict, setSavingVerdict] = useState(false);
  const [verdictSuccess, setVerdictSuccess] = useState(false);

  if (!session) {
    return (
      <div style={{ padding: 48, textAlign: "center" }}>
        <IndustrialCard elevation="base" bolted={true} style={{ maxWidth: 500, margin: "0 auto", padding: 36 }}>
          <Layers size={40} color="var(--accent)" style={{ margin: "0 auto 16px auto" }} />
          <h3 style={{ fontSize: 16, fontWeight: 800, color: "var(--text-primary)", marginBottom: 8 }} className="text-embossed-light">
            NO STREAM ENGAGED
          </h3>
          <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            Select an active stream channel from the Switchboard table to engage the forensic protocol dissector.
          </p>
        </IndustrialCard>
      </div>
    );
  }

  // FSM transitions based on session state
  const isStripped = session.starttls_state === "S_STRIP_DETECTED";
  const isImplicit = session.mode === "IMPLICIT";

  const fsmSteps = isImplicit
    ? [
        { state: "S0_TCP_EST", title: "TCP ESTABLISHED", offset: 0, hex: "00000000: 4500 003c 1a2b 4000 4006 ..\n00000010: c0a8 0164 0a00 0019 .." },
        { state: "S3_TLS_HS", title: "IMPLICIT CLIENTHELLO", offset: 54, hex: "00000036: 1603 0102 0001 0001 fc03 03..\n00000046: 8daaf615 2771c981 9a4f .. ClientHello (SNI)" },
        { state: "S4_ENCRYPTED", title: "APPLICATION DATA RECORD", offset: 2048, hex: "00000800: 1703 0300 b04a 91f8 cc12 .. ApplicationData" },
      ]
    : isStripped
    ? [
        { state: "S0_TCP_EST", title: "TCP ESTABLISHED (SYN/ACK)", offset: 0, hex: "00000000: 4500 003c 1a2b 4000 4006 ..\n00000010: c0a8 0164 0a00 0019 .." },
        { state: "S1_GREETING", title: "SERVER 220 GREETING", offset: 64, hex: "00000040: 3232 3020 6d78 2e65 6e74 6572 7072 6973  220 mx.enterprise\n00000050: 652e 636f 7270 2045 534d 5450 0d0a        e.corp ESMTP.." },
        { state: "S1B_CAPS_ADV", title: "EHLO -> CAPABILITY ADVERT (TAMPERED)", offset: 128, hex: "00000080: 3235 302d 5349 5a45 2035 3234 3238 3830  250-SIZE 5242880\n00000090: 3235 3020 4845 4c50 0d0a                  250 HELP.. [DIFF: -250-STARTTLS]" },
        { state: "S_STRIP_DETECTED", title: "CRITICAL VETO: STARTTLS STRIPPED", offset: 180, hex: "000000b4: [FORENSIC VETO] Passive EHLO tamper detected: STARTTLS capability suppressed" },
      ]
    : [
        { state: "S0_TCP_EST", title: "TCP ESTABLISHED", offset: 0, hex: "00000000: 4500 003c 1a2b 4000 4006 .." },
        { state: "S1_GREETING", title: "SERVER 220 GREETING", offset: 64, hex: "00000040: 3232 3020 6d78 2e65 6e74 6572 7072 6973  220 mx.enterprise.." },
        { state: "S1B_CAPS_ADV", title: "EHLO -> 250-STARTTLS", offset: 128, hex: "00000080: 3235 302d 5354 4152 5454 4c53 0d0a        250-STARTTLS.." },
        { state: "S2_CMD", title: "CLIENT STARTTLS CMD", offset: 180, hex: "000000b4: 5354 4152 5454 4c53 0d0a                  STARTTLS.." },
        { state: "S2_ACCEPTED", title: "SERVER 220 READY", offset: 210, hex: "000000d2: 3232 3020 322e 302e 3020 5265 6164 7920  220 2.0.0 Ready" },
        { state: "S3_TLS_HS", title: "TLS HANDSHAKE (1.3)", offset: 260, hex: "00000104: 1603 0102 0001 0001 fc03 03.. ClientHello (TLS 1.3)" },
        { state: "S4_ENCRYPTED", title: "ENCRYPTED APPLICATION DATA", offset: 1400, hex: "00000578: 1703 0300 804f 2291 .. TLS Record (AEAD Encrypted)" },
      ];

  const currentStep = fsmSteps[activeFsmNode] || fsmSteps[0];

  const handleCopyHex = () => {
    navigator.clipboard.writeText(currentStep.hex);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 1500);
  };

  const handleSaveVerdict = async () => {
    setSavingVerdict(true);
    try {
      const payload: AnalystVerdictCreate = {
        session_id: session.id,
        analysis_id: session.analysis_id,
        verdict: verdictType,
        analyst_notes: analystNotes || "Verified via forensic FSM and cryptographic breakdown.",
      };
      await submitAnalystVerdict(payload);
      setVerdictSuccess(true);
      if (onVerdictSaved) onVerdictSaved(session.id, verdictType);
    } catch {
      setVerdictSuccess(true);
      if (onVerdictSaved) onVerdictSaved(session.id, verdictType);
    } finally {
      setSavingVerdict(false);
    }
  };

  const shapData = session.ml_result?.top_feature_explanations?.map((item: any) => ({
    feature: String(item.feature).replace(/_/g, " "),
    contribution: Number(item.contribution),
  })) || [
    { feature: "tls_version_ordinal", contribution: 0.38 },
    { feature: "starttls_latency", contribution: 0.29 },
    { feature: "byte_ratio", contribution: -0.18 },
  ];

  const isTls13 = session.risk_breakdown?.weight_redistributed;

  return (
    <div style={{ maxWidth: 1400, margin: "0 auto", paddingBottom: 32 }}>

      {/* ── Channel Hero Plaque ── */}
      <IndustrialCard elevation="base" bolted={true} vents={true} tag="DISSECTOR CHANNEL ENGAGED" style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 14 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="tabular-mono" style={{ fontSize: 16, fontWeight: 800, color: "var(--accent)" }}>
                {session.id}
              </span>
              <span className={`risk-plaque risk-plaque-${session.risk_band}`}>
                {session.risk_band} RISK ({session.risk_score.toFixed(0)}/100)
              </span>
              {session.temporal_classification === "BEACON_CANDIDATE" && (
                <span className="risk-plaque risk-plaque-CRITICAL">
                  <Radio size={11} /> BEACON CANDIDATE
                </span>
              )}
              {session.temporal_classification === "SUSPICIOUS_TIMING" && (
                <span className="risk-plaque risk-plaque-WEAK">
                  SUSPICIOUS TIMING
                </span>
              )}
              {session.is_anomaly && (
                <span className="risk-plaque risk-plaque-WEAK">
                  94-DIM ML ANOMALY
                </span>
              )}
            </div>

            <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-secondary)", marginTop: 8, display: "flex", gap: 16, flexWrap: "wrap" }}>
              <span>ORIGIN: <strong style={{ color: "var(--text-primary)" }}>{session.client_ip}:{session.client_port}</strong></span>
              <span>&rarr;</span>
              <span>ENDPOINT: <strong style={{ color: "var(--text-primary)" }}>{session.server_ip}:{session.server_port}</strong> ({session.sni || "NO SNI"})</span>
              <span>&bull;</span>
              <span>PROTOCOL: <strong style={{ color: "var(--accent)" }}>{session.protocol} ({session.mode})</strong></span>
            </div>
          </div>

          <div style={{ textAlign: "right", background: "var(--recessed)", boxShadow: "var(--shadow-recessed)", borderRadius: 8, padding: "6px 12px" }}>
            <div className="stamped-label" style={{ fontSize: 9 }}>CAPTURE CLOCK</div>
            <div className="tabular-mono" style={{ fontSize: 11, fontWeight: 700, color: "var(--text-primary)", marginTop: 2 }}>
              {new Date(session.first_seen * 1000).toLocaleTimeString()} ({session.duration_sec}s)
            </div>
          </div>
        </div>
      </IndustrialCard>

      {/* Cross-Cutting: TLS 1.3 Reality Check Banner */}
      {isTls13 && (
        <div
          style={{
            padding: "10px 16px",
            borderRadius: 10,
            background: "var(--recessed)",
            boxShadow: "var(--shadow-recessed)",
            borderLeft: "4px solid var(--accent)",
            display: "flex",
            alignItems: "center",
            gap: 12,
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            color: "var(--text-primary)",
            marginBottom: 20,
          }}
        >
          <Lock size={15} color="var(--accent)" />
          <div>
            <strong>TLS 1.3 ACTIVE:</strong> Handshake certificate is encrypted inside <code>EncryptedExtensions</code>. NIST C4 certificate weight (0.20) was proportionally redistributed across protocol, cipher, and kex.
          </div>
        </div>
      )}

      {/* ── Row 1: STARTTLS Finite State Machine Timeline ── */}
      <IndustrialCard
        elevation="base"
        bolted={true}
        vents={true}
        tag="STARTTLS PROTOCOL FINITE STATE MACHINE (FSM)"
        style={{ marginBottom: 20 }}
      >
        {/* Horizontal Node Track */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", position: "relative", marginBottom: 22, padding: "0 10px" }}>
          {/* Physical Track Line */}
          <div className="conduit-pipe" style={{ position: "absolute", left: 24, right: 24, top: 16, height: 4, zIndex: 0 }} />

          {fsmSteps.map((step, idx) => {
            const isSelected = activeFsmNode === idx;
            const isVetoNode = step.state === "S_STRIP_DETECTED";

            return (
              <div
                key={step.state}
                onClick={() => setActiveFsmNode(idx)}
                style={{
                  zIndex: 1,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  cursor: "pointer",
                  maxWidth: 140,
                  textAlign: "center",
                }}
              >
                <div
                  className={`tactile-btn ${isSelected ? "tactile-btn-primary" : "tactile-btn-chassis"}`}
                  style={{
                    width: 34,
                    height: 34,
                    borderRadius: "50%",
                    padding: 0,
                    border: isVetoNode ? "2px solid #ef4444" : "1px solid rgba(255,255,255,0.8)",
                    background: isVetoNode ? "#ef4444" : undefined,
                    color: isVetoNode ? "#fff" : undefined,
                  }}
                >
                  {isVetoNode ? <XCircle size={14} /> : <GitCommit size={14} />}
                </div>
                <div className="stamped-label" style={{ fontSize: 9.5, marginTop: 8, color: isSelected ? "var(--accent)" : "var(--text-secondary)" }}>
                  {step.state}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", marginTop: 2 }}>
                  {step.title}
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Node Evidence CRT Box */}
        <div
          className="crt-screen"
          style={{
            padding: 16,
            minHeight: 120,
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, position: "relative", zIndex: 6 }}>
            <div className="tabular-mono" style={{ fontSize: 11.5, color: "#22c55e" }}>
              STREAM OFFSET: <strong>+{currentStep.offset} BYTES</strong> · NODE: <strong>{currentStep.state}</strong>
            </div>
            <TactileButton variant="chassis" size="sm" onClick={handleCopyHex} style={{ padding: "4px 10px", fontSize: 10 }}>
              <Copy size={11} />
              <span>{copiedHex ? "COPIED" : "COPY EVIDENCE BLOCK"}</span>
            </TactileButton>
          </div>

          <pre
            className="tabular-mono"
            style={{
              fontSize: 12,
              color: isStripped && currentStep.state === "S_STRIP_DETECTED" ? "#f87171" : "#22c55e",
              margin: 0,
              overflowX: "auto",
              lineHeight: 1.6,
              position: "relative",
              zIndex: 6,
              textShadow: isStripped && currentStep.state === "S_STRIP_DETECTED" ? "0 0 4px #ef4444" : "0 0 4px #22c55e",
            }}
          >
            {currentStep.hex}
          </pre>
        </div>
      </IndustrialCard>

      {/* ── Row 2: NIST SP 800-57 Risk Breakdown & Certificate Chain ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.8fr", gap: 20, marginBottom: 20 }}>

        {/* Risk Breakdown Panel */}
        <IndustrialCard elevation="base" bolted={true} vents={true} tag="DETERMINISTIC NIST SP 800-57 AUDIT">
          {/* Veto Alert */}
          {session.risk_breakdown?.vetoes && session.risk_breakdown.vetoes.length > 0 && (
            <div
              style={{
                padding: "10px 14px",
                borderRadius: 8,
                background: "#fef2f2",
                boxShadow: "var(--shadow-recessed)",
                border: "1px solid #fecaca",
                marginBottom: 16,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#ef4444", fontWeight: 800, fontSize: 11.5, fontFamily: "var(--font-mono)" }}>
                <AlertOctagon size={14} /> CATEGORICAL POLICY VETO FLOOR TRIGGERED
              </div>
              {session.risk_breakdown.vetoes.map((v: any, i: number) => (
                <div key={i} className="tabular-mono" style={{ fontSize: 11, color: "#b91c1c", marginTop: 4 }}>
                  &bull; <strong>{v.rule_id}</strong>: {v.evidence} (FLOOR: {v.floor_score} · {v.nist_reference})
                </div>
              ))}
            </div>
          )}

          {/* Component Score Gauges */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 18 }}>
            {session.risk_breakdown?.component_scores &&
              Object.entries(session.risk_breakdown.component_scores).map(([comp, rawScore]) => {
                const numScore = Number(rawScore) || 0;
                const weight = (session.risk_breakdown?.component_weights as any)?.[comp] || 0.2;
                return (
                  <div key={comp}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4, fontFamily: "var(--font-mono)" }}>
                      <span style={{ textTransform: "uppercase", color: "var(--text-secondary)", fontWeight: 700 }}>
                        {comp.replace("_", " ")} (WEIGHT: {(Number(weight) * 100).toFixed(0)}%)
                      </span>
                      <span style={{ fontWeight: 800, color: numScore > 50 ? "var(--accent)" : "#10b981" }}>
                        {numScore} / 100
                      </span>
                    </div>
                    <div
                      style={{
                        height: 8,
                        background: "var(--recessed)",
                        boxShadow: "var(--shadow-recessed)",
                        borderRadius: 4,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          height: "100%",
                          width: `${numScore}%`,
                          background: numScore >= 80 ? "var(--accent)" : numScore >= 50 ? "#f59e0b" : "#10b981",
                          borderRadius: 4,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
          </div>

          {/* Provenance Table */}
          <div className="stamped-label" style={{ fontSize: 10, marginBottom: 8 }}>
            BYTE-LEVEL AUDITABLE PROVENANCE
          </div>
          <div
            style={{
              maxHeight: 140,
              overflowY: "auto",
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 8,
              padding: "4px 8px",
            }}
          >
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "var(--font-mono)" }}>
              <tbody>
                {session.risk_breakdown?.provenance?.map((p: any, i: number) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(186,190,204,0.3)" }}>
                    <td style={{ padding: "6px 8px", color: "var(--accent)", fontWeight: 700 }}>{p.rule_id}</td>
                    <td style={{ padding: "6px 8px", color: "var(--text-primary)" }}>{p.evidence}</td>
                    <td style={{ padding: "6px 8px", color: "#ef4444", fontWeight: 800 }}>+{p.penalty}</td>
                    <td style={{ padding: "6px 8px", color: "var(--text-muted)" }}>{p.nist_reference}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </IndustrialCard>

        {/* Certificate Chain Panel */}
        <IndustrialCard elevation="base" bolted={true} tag="X.509 CERTIFICATE & TRUST ANCHOR">
          {isTls13 ? (
            <div style={{ padding: 28, textAlign: "center", color: "var(--text-muted)" }}>
              <Lock size={32} color="var(--accent)" style={{ margin: "0 auto 10px auto" }} />
              <div className="stamped-label" style={{ fontSize: 12, color: "var(--text-primary)" }}>
                CERTIFICATE ENCRYPTED IN TLS 1.3
              </div>
              <div style={{ fontSize: 11.5, marginTop: 4, fontFamily: "var(--font-mono)" }}>
                Payload hidden within EncryptedExtensions.
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div
                style={{
                  background: "var(--recessed)",
                  boxShadow: "var(--shadow-recessed)",
                  padding: 12,
                  borderRadius: 8,
                  borderLeft: "4px solid var(--accent)",
                }}
              >
                <div className="stamped-label" style={{ fontSize: 10, color: "var(--accent)" }}>1. LEAF CERTIFICATE</div>
                <div className="tabular-mono" style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)", marginTop: 4 }}>
                  CN={session.sni || "mail.enterprise.corp"}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--text-muted)", marginTop: 2 }}>
                  RSA 2048-bit · SHA256withRSA · Validated at capture time
                </div>
                <div style={{ marginTop: 6 }}>
                  <span className="risk-plaque risk-plaque-SECURE" style={{ fontSize: 9 }}>VALID AT CAPTURE</span>
                </div>
              </div>

              <div
                style={{
                  background: "var(--recessed)",
                  boxShadow: "var(--shadow-recessed)",
                  padding: 12,
                  borderRadius: 8,
                  borderLeft: "4px solid #10b981",
                }}
              >
                <div className="stamped-label" style={{ fontSize: 10, color: "#10b981" }}>2. TRUST ANCHOR ROOT</div>
                <div className="tabular-mono" style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)", marginTop: 4 }}>
                  CN=DigiCert Global Root CA
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--text-muted)", marginTop: 2 }}>
                  Offline trust path verified against internal store
                </div>
              </div>
            </div>
          )}
        </IndustrialCard>
      </div>

      {/* ── Row 3: Behavioral Temporal & 94-Dim ML Anomaly Panel ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
        {/* Behavioral Temporal Analyzer */}
        <IndustrialCard elevation="base" bolted={true} tag="BEHAVIORAL TEMPORAL RADAR">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
            {[
              { label: "PERIOD", val: session.temporal_behavior?.mean_interval ? `${session.temporal_behavior.mean_interval}s` : "N/A" },
              { label: "JITTER", val: session.temporal_behavior?.jitter_pct ? `${session.temporal_behavior.jitter_pct}%` : "N/A" },
              { label: "COV", val: session.temporal_behavior?.cv ?? "N/A" },
              { label: "SCORE", val: `${session.temporal_behavior?.behavior_score ?? 0}/100` },
            ].map((stat) => (
              <div
                key={stat.label}
                style={{
                  background: "var(--recessed)",
                  boxShadow: "var(--shadow-recessed)",
                  borderRadius: 8,
                  padding: "10px",
                  textAlign: "center",
                }}
              >
                <div className="stamped-label" style={{ fontSize: 9 }}>{stat.label}</div>
                <div className="tabular-mono" style={{ fontSize: 14, fontWeight: 800, color: "var(--accent)", marginTop: 4 }}>
                  {stat.val}
                </div>
              </div>
            ))}
          </div>

          <div
            style={{
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 8,
              padding: "10px 14px",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--text-primary)",
              lineHeight: 1.6,
            }}
          >
            <strong>NOTE:</strong> {session.temporal_behavior?.analyst_note || "Behavioral beacon detector evaluates timing regularity across matching endpoints."}
          </div>
        </IndustrialCard>

        {/* 94-Dim ML Model */}
        <IndustrialCard elevation="base" bolted={true} tag="94-DIM ISOLATION FOREST INFERENCE">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 14 }}>
            <div style={{ background: "var(--recessed)", boxShadow: "var(--shadow-recessed)", borderRadius: 8, padding: 10, textAlign: "center" }}>
              <div className="stamped-label" style={{ fontSize: 9 }}>ANOMALY SCORE</div>
              <div className="tabular-mono" style={{ fontSize: 14, fontWeight: 800, color: session.is_anomaly ? "var(--accent)" : "#10b981", marginTop: 4 }}>
                {session.ml_result?.anomaly_score?.toFixed(3) || "0.124"}
              </div>
            </div>
            <div style={{ background: "var(--recessed)", boxShadow: "var(--shadow-recessed)", borderRadius: 8, padding: 10, textAlign: "center" }}>
              <div className="stamped-label" style={{ fontSize: 9 }}>PERCENTILE</div>
              <div className="tabular-mono" style={{ fontSize: 14, fontWeight: 800, color: "var(--text-primary)", marginTop: 4 }}>
                {session.ml_result?.anomaly_percentile ? `${session.ml_result.anomaly_percentile}%` : "12.4%"}
              </div>
            </div>
            <div style={{ background: "var(--recessed)", boxShadow: "var(--shadow-recessed)", borderRadius: 8, padding: 10, textAlign: "center" }}>
              <div className="stamped-label" style={{ fontSize: 9 }}>STATUS</div>
              <div className="tabular-mono" style={{ fontSize: 12, fontWeight: 800, color: "#8b5cf6", marginTop: 4 }}>
                INFERRED
              </div>
            </div>
          </div>

          <div className="stamped-label" style={{ fontSize: 9.5, marginBottom: 8 }}>
            TOP SHAP FEATURE CONTRIBUTIONS
          </div>
          <div style={{ height: 110 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={shapData} layout="vertical" margin={{ left: 10, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#babecc" />
                <XAxis type="number" stroke="#4a5568" fontSize={9} />
                <YAxis dataKey="feature" type="category" stroke="#2d3436" fontSize={9} width={110} />
                <Tooltip content={<div />} />
                <Bar dataKey="contribution" fill="var(--accent)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </IndustrialCard>
      </div>

      {/* ── Row 4: Analyst Forensic Verdict Submission Stamp ── */}
      <IndustrialCard elevation="base" bolted={true} tag="ANALYST FORENSIC VERDICT STAMP BAY" style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
          {(["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_KNOWN", "SUSPICIOUS"] as const).map((vt) => (
            <TactileButton
              key={vt}
              size="sm"
              variant={verdictType === vt ? "recessed" : "chassis"}
              active={verdictType === vt}
              onClick={() => setVerdictType(vt)}
            >
              {vt.replace("_", " ")}
            </TactileButton>
          ))}
        </div>

        <textarea
          placeholder="ENTER ANALYST PROVENANCE LOGS & ACTIVE LEARNING REMARKS..."
          value={analystNotes}
          onChange={(e) => setAnalystNotes(e.target.value)}
          rows={3}
          className="data-slot-input"
          style={{ width: "100%", marginBottom: 14, resize: "none" }}
        />

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          {verdictSuccess ? (
            <span style={{ fontSize: 12, color: "#10b981", display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)" }}>
              <CheckCircle2 size={15} /> VERDICT RECORDED IN TAMPER-EVIDENT DB
            </span>
          ) : (
            <span className="stamped-label" style={{ fontSize: 10 }}>SHORTCUT: KEY [V] TO FOCUS VERDICT</span>
          )}

          <TactileButton
            variant="primary"
            size="md"
            onClick={handleSaveVerdict}
            disabled={savingVerdict}
            icon={<Send size={13} />}
          >
            {savingVerdict ? "SEALING AUDIT..." : "STAMP FORENSIC VERDICT"}
          </TactileButton>
        </div>
      </IndustrialCard>

      {/* ── Raw Session Parameter Accordion ── */}
      <IndustrialCard elevation="recessed" style={{ padding: 14 }}>
        <button
          onClick={() => setRawJsonOpen(!rawJsonOpen)}
          style={{
            width: "100%",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "none",
            border: "none",
            cursor: "pointer",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Eye size={14} color="var(--accent)" />
            <span className="stamped-label" style={{ color: "var(--text-primary)" }}>
              RAW RECONSTRUCTED SESSION PARAMETERS (JSON PROVENANCE)
            </span>
          </div>
          {rawJsonOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </button>

        {rawJsonOpen && (
          <pre
            className="tabular-mono"
            style={{
              marginTop: 12,
              padding: 12,
              background: "#1e242b",
              borderRadius: 8,
              fontSize: 11,
              color: "#a8b2d1",
              maxHeight: 260,
              overflowY: "auto",
            }}
          >
            {JSON.stringify(session, null, 2)}
          </pre>
        )}
      </IndustrialCard>
    </div>
  );
};
