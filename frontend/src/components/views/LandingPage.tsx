import React, { useEffect, useRef, useState } from "react";
import { ArrowRight, Zap, Lock, BarChart2, Search, ChevronRight, Shield, Terminal, Cpu } from "lucide-react";
import { LedIndicator } from "../common/LedIndicator";
import { TactileButton } from "../common/TactileButton";
import { IndustrialCard } from "../common/IndustrialCard";

interface LandingPageProps {
  onEnterConsole: () => void;
  onGoToIngestion: () => void;
}

/* ── Live Oscilloscope Packet Visualizer ── */
const OscilloscopeCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    let offset = 0;
    const draw = () => {
      const W = canvas.width;
      const H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      // Oscilloscope background grid
      ctx.strokeStyle = "rgba(34, 197, 94, 0.12)";
      ctx.lineWidth = 1;
      for (let x = 0; x < W; x += 30) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, H);
        ctx.stroke();
      }
      for (let y = 0; y < H; y += 30) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(W, y);
        ctx.stroke();
      }

      // Signal wave 1 (Phosphor Green Cryptographic Stream)
      ctx.beginPath();
      ctx.strokeStyle = "#22c55e";
      ctx.lineWidth = 2;
      ctx.shadowColor = "#22c55e";
      ctx.shadowBlur = 8;
      for (let x = 0; x < W; x++) {
        const y =
          H / 2 +
          Math.sin((x + offset) * 0.04) * 28 +
          Math.sin((x + offset * 1.5) * 0.08) * 12 +
          (x % 40 === 0 ? (Math.random() - 0.5) * 20 : 0);
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      // Signal wave 2 (Metallic Slate Steel STARTTLS Transition Peak)
      ctx.beginPath();
      ctx.strokeStyle = "#64748b";
      ctx.lineWidth = 1.5;
      ctx.shadowColor = "#64748b";
      ctx.shadowBlur = 6;
      for (let x = 0; x < W; x++) {
        const y =
          H / 2 + 35 +
          Math.cos((x - offset * 0.8) * 0.03) * 20 +
          Math.sin((x + offset) * 0.02) * 10;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      ctx.shadowBlur = 0;
      offset += 1.5;
      animRef.current = requestAnimationFrame(draw);
    };

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, []);

  return <canvas ref={canvasRef} style={{ width: "100%", height: "100%", display: "block" }} />;
};

export const LandingPage: React.FC<LandingPageProps> = ({ onEnterConsole, onGoToIngestion }) => {
  const [scanY, setScanY] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setScanY((p) => (p + 1) % 100), 30);
    return () => clearInterval(t);
  }, []);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--chassis)",
        color: "var(--text-primary)",
        position: "relative",
      }}
    >
      {/* ── Industrial Top Navigation Console ── */}
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 100,
          background: "var(--chassis)",
          borderBottom: "1px solid #babecc",
          boxShadow: "0 6px 14px rgba(186,190,204,0.6), inset 0 1px 0 #ffffff",
          padding: "0 36px",
          height: 64,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {/* Unit Brand Module */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "6px 14px",
              background: "var(--chassis)",
              borderRadius: 10,
              boxShadow: "var(--shadow-card)",
              border: "1px solid rgba(255,255,255,0.7)",
            }}
          >
            <img
              src="/relic-logo.png?v=2"
              alt="Relic Logo"
              style={{ width: 24, height: 24, objectFit: "contain", filter: "drop-shadow(0 1px 2px rgba(15, 23, 42, 0.15))" }}
            />
            <img
              src="/relic-wordmark.png?v=2"
              alt="RELIC"
              style={{ height: 15, width: "auto", objectFit: "contain", filter: "drop-shadow(0 1px 1px rgba(15, 23, 42, 0.18))" }}
            />
            <span
              className="stamped-label"
              style={{
                borderLeft: "1px solid #babecc",
                paddingLeft: 10,
                color: "var(--accent)",
                fontSize: 10,
              }}
            >
              PECFF INDUSTRIAL RACK
            </span>
          </div>

          <div className="vent-grille" style={{ marginLeft: 6 }}>
            <div className="vent-slot" />
            <div className="vent-slot" />
            <div className="vent-slot" />
          </div>
        </div>

        {/* Console Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <LedIndicator status="green" label="STATION ARMED" size="sm" />
          <TactileButton variant="chassis" size="md" onClick={onGoToIngestion}>
            LOAD CAPTURE
          </TactileButton>
          <TactileButton
            variant="primary"
            size="md"
            onClick={onEnterConsole}
            iconRight={<ArrowRight size={14} />}
          >
            INITIALIZE CONSOLE
          </TactileButton>
        </div>
      </header>

      {/* ── Hero Hardware Section ── */}
      <section
        style={{
          maxWidth: 1300,
          margin: "0 auto",
          padding: "64px 36px 54px",
          display: "grid",
          gridTemplateColumns: "1.1fr 0.9fr",
          gap: 60,
          alignItems: "center",
        }}
      >
        {/* LEFT COLUMN: Controls & Specification */}
        <div>
          {/* Stamped Specification Plate */}
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 20,
              background: "var(--recessed)",
              boxShadow: "var(--shadow-recessed)",
              borderRadius: 8,
              padding: "6px 14px",
            }}
          >
            <LedIndicator status="orange" size="sm" pulse={true} />
            <span
              className="tabular-mono"
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.08em",
                color: "var(--text-primary)",
                textTransform: "uppercase",
              }}
            >
              SPEC: NIST SP 800-57 · RFC 7525 · ZERO NET I/O
            </span>
          </div>

          <h1
            style={{
              fontSize: "clamp(34px, 3.8vw, 50px)",
              fontWeight: 800,
              lineHeight: 1.12,
              letterSpacing: "-0.03em",
              marginBottom: 18,
              color: "#0f172a",
            }}
          >
            Passive Email <br />
            <span
              style={{
                color: "#475569",
                display: "inline-block",
                textShadow: "0 1px 1px rgba(255,255,255,0.9)",
              }}
            >
              Cryptographic Forensics
            </span>
          </h1>

          <p
            style={{
              fontSize: 15,
              color: "var(--text-secondary)",
              lineHeight: 1.7,
              maxWidth: 500,
              marginBottom: 32,
            }}
          >
            Tactile forensic workstation engineered for air-gapped PCAP email protocol analysis.
            Reassembles TCP streams, evaluates deterministic NIST SP 800-57 risk scores,
            detects STARTTLS downgrades, and trains 94-dimensional unsupervised anomaly models.
          </p>

          {/* Primary Hardware Action Buttons */}
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 38 }}>
            <TactileButton
              variant="primary"
              size="lg"
              onClick={onGoToIngestion}
              icon={<Zap size={16} />}
            >
              START INGESTION BAY
            </TactileButton>
            <TactileButton
              variant="chassis"
              size="lg"
              onClick={onEnterConsole}
              iconRight={<ChevronRight size={16} />}
            >
              LOAD TELEMETRY FIXTURES
            </TactileButton>
          </div>

          {/* Stamped Numeric Readout Gauges */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 32 }}>
            {[
              { label: "DOWNGRADE VETOES", value: "9 RULES", note: "RFC 7525 / NIST" },
              { label: "FEATURE VECTOR", value: "94-DIM", note: "ISOLATION FOREST" },
              { label: "RISK FORMULA", value: "PURE DET.", note: "C1–C5 METRIC" },
            ].map((stat) => (
              <div
                key={stat.label}
                style={{
                  background: "var(--recessed)",
                  boxShadow: "var(--shadow-recessed)",
                  borderRadius: 12,
                  padding: "14px 16px",
                  textAlign: "center",
                }}
              >
                <div
                  className="tabular-mono"
                  style={{
                    fontSize: 20,
                    fontWeight: 800,
                    color: "var(--text-primary)",
                    letterSpacing: "-0.02em",
                  }}
                >
                  {stat.value}
                </div>
                <div
                  className="stamped-label"
                  style={{ fontSize: 9.5, marginTop: 4, color: "var(--accent)" }}
                >
                  {stat.label}
                </div>
                <div
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 8.5,
                    color: "var(--text-muted)",
                    marginTop: 2,
                  }}
                >
                  {stat.note}
                </div>
              </div>
            ))}
          </div>

          {/* Bolted Feature Tags */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {[
              { icon: <Lock size={12} color="var(--accent)" />, label: "STARTTLS FSM" },
              { icon: <Search size={12} color="var(--accent)" />, label: "CIPHER & PFS" },
              { icon: <BarChart2 size={12} color="var(--accent)" />, label: "C2 BEACONING" },
              { icon: <Shield size={12} color="var(--accent)" />, label: "X.509 PKI AUDIT" },
            ].map((f) => (
              <div
                key={f.label}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "6px 12px",
                  background: "var(--chassis)",
                  borderRadius: 8,
                  boxShadow: "var(--shadow-card)",
                  border: "1px solid rgba(255,255,255,0.7)",
                  fontFamily: "var(--font-mono)",
                  fontSize: 10.5,
                  fontWeight: 700,
                  color: "var(--text-primary)",
                }}
              >
                {f.icon}
                <span>{f.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT COLUMN: 3D Physical Hardware Console Simulation */}
        <div>
          <div
            className="bolted-panel"
            style={{
              background: "#242b35",
              borderRadius: 20,
              padding: "20px 22px",
              boxShadow: "16px 16px 32px var(--shadow-dark), -12px -12px 28px var(--shadow-light), inset 1px 1px 0 rgba(255,255,255,0.15)",
              border: "2px solid #14181d",
              position: "relative",
            }}
          >
            {/* Console Instrument Bezel Header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                paddingBottom: 14,
                marginBottom: 14,
                borderBottom: "1px solid rgba(255,255,255,0.1)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 10, paddingLeft: 12 }}>
                <Terminal size={15} color="#22c55e" />
                <span
                  className="tabular-mono"
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: "#e0e5ec",
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                  }}
                >
                  OSCILLOSCOPE · RASTER SCAN CH-1
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ display: "flex", gap: 3 }}>
                  <div className="vent-slot" style={{ background: "#14181d", height: 16 }} />
                  <div className="vent-slot" style={{ background: "#14181d", height: 16 }} />
                  <div className="vent-slot" style={{ background: "#14181d", height: 16 }} />
                </div>
                <LedIndicator status="green" label="CH-1 LOCK" size="sm" />
              </div>
            </div>

            {/* CRT Screen Display */}
            <div
              className="crt-screen"
              style={{
                height: 280,
                position: "relative",
                marginBottom: 16,
              }}
            >
              <OscilloscopeCanvas />

              {/* Dynamic Scanline Overlay */}
              <div
                style={{
                  position: "absolute",
                  left: 0,
                  right: 0,
                  height: 2,
                  background: "linear-gradient(90deg, transparent, rgba(34, 197, 94, 0.7), transparent)",
                  top: `${scanY * 2.8}px`,
                  pointerEvents: "none",
                  zIndex: 6,
                }}
              />

              {/* Stamped Live Telemetry Overlays */}
              <div
                style={{
                  position: "absolute",
                  top: 10,
                  left: 12,
                  zIndex: 10,
                  fontFamily: "var(--font-mono)",
                  fontSize: 10,
                  color: "#22c55e",
                  lineHeight: 1.4,
                  textShadow: "0 0 4px #22c55e",
                }}
              >
                <div>[PROT] SMTP/TLS 1.3 (0x0304)</div>
                <div>[SUITE] TLS_AES_256_GCM_SHA384</div>
                <div>[JA4] t13d1516h2_8daaf6152771</div>
              </div>

              <div
                style={{
                  position: "absolute",
                  bottom: 10,
                  right: 12,
                  zIndex: 10,
                  fontFamily: "var(--font-mono)",
                  fontSize: 10,
                  color: "var(--accent)",
                  lineHeight: 1.4,
                  textAlign: "right",
                  textShadow: "0 0 4px var(--accent)",
                }}
              >
                <div>VETO: PROTO-NO-TLS-AUTH [PASS]</div>
                <div>NIST RISK: 18.2 [SECURE]</div>
              </div>
            </div>

            {/* Physical Telemetry Bar */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: 8,
                background: "#14181d",
                borderRadius: 10,
                padding: "10px",
                border: "1px solid rgba(255,255,255,0.06)",
              }}
            >
              {[
                { label: "SESSIONS", val: "1,024", color: "#e0e5ec" },
                { label: "CRITICAL", val: "47", color: "var(--accent)" },
                { label: "ANOMALIES", val: "12", color: "#f59e0b" },
                { label: "NIST SCORE", val: "78.4", color: "#22c55e" },
              ].map((m) => (
                <div key={m.label} style={{ textAlign: "center" }}>
                  <div
                    className="tabular-mono"
                    style={{ fontSize: 15, fontWeight: 800, color: m.color }}
                  >
                    {m.val}
                  </div>
                  <div
                    className="stamped-label"
                    style={{ fontSize: 8.5, color: "#a8b2d1", marginTop: 2 }}
                  >
                    {m.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── How It Works (Physical Module Conduit Rack) ── */}
      <section
        style={{
          maxWidth: 1300,
          margin: "0 auto",
          padding: "40px 36px 80px",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div className="stamped-label" style={{ color: "var(--accent)", marginBottom: 6 }}>
            ARCHITECTURE PIPELINE
          </div>
          <h2 style={{ fontSize: 26, fontWeight: 800 }} className="text-embossed-light">
            Zero-Interception Mechanical Forensic Pipeline
          </h2>
        </div>

        {/* Physical Conduit Connecting Modules */}
        <div style={{ position: "relative" }}>
          <div
            className="conduit-pipe"
            style={{
              position: "absolute",
              top: 40,
              left: "10%",
              right: "10%",
              zIndex: 0,
            }}
          />

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: 20,
              position: "relative",
              zIndex: 1,
            }}
          >
            {[
              {
                step: "01",
                tag: "BAY-1",
                title: "PCAP INGESTION",
                desc: "Microsecond & nanosecond PCAP/PCAPNG link-layer streaming with SHA-256 deduplication.",
                icon: <Zap size={18} color="var(--accent)" />,
              },
              {
                step: "02",
                tag: "BAY-2",
                title: "STREAM REASSEMBLY",
                desc: "Bounded-memory TCP reassembly with LRU eviction and SMTP/IMAP/POP3 STARTTLS state tracking.",
                icon: <Terminal size={18} color="var(--accent)" />,
              },
              {
                step: "03",
                tag: "BAY-3",
                title: "NIST RISK SCORER",
                desc: "Deterministic evaluation across C1–C5 components with mandatory categorical floor vetoes.",
                icon: <Shield size={18} color="var(--accent)" />,
              },
              {
                step: "04",
                tag: "BAY-4",
                title: "94-DIM ML ENGINE",
                desc: "IsolationForest anomaly inference, beacon periodicity FFT, and court-admissible audit reports.",
                icon: <Cpu size={18} color="var(--accent)" />,
              },
            ].map((module) => (
              <IndustrialCard
                key={module.step}
                elevation="base"
                bolted={true}
                vents={true}
                tag={`${module.tag} · STEP ${module.step}`}
              >
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: "50%",
                    background: "var(--chassis)",
                    boxShadow: "var(--shadow-floating)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    margin: "0 auto 14px",
                  }}
                >
                  {module.icon}
                </div>
                <div
                  className="tabular-mono"
                  style={{
                    fontSize: 13,
                    fontWeight: 800,
                    textAlign: "center",
                    marginBottom: 8,
                    color: "var(--text-primary)",
                  }}
                >
                  {module.title}
                </div>
                <p
                  style={{
                    fontSize: 12,
                    color: "var(--text-secondary)",
                    lineHeight: 1.6,
                    textAlign: "center",
                  }}
                >
                  {module.desc}
                </p>
              </IndustrialCard>
            ))}
          </div>
        </div>
      </section>

      {/* ── Stamped Industrial Footer ── */}
      <footer
        style={{
          borderTop: "1px solid #babecc",
          boxShadow: "inset 0 1px 0 #ffffff",
          padding: "24px 36px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          background: "var(--chassis)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <img
            src="/relic-logo.png?v=2"
            alt="Relic"
            style={{ width: 22, height: 22, objectFit: "contain", opacity: 0.9 }}
          />
          <span
            className="stamped-label"
            style={{ fontSize: 11, color: "var(--text-primary)" }}
          >
            RELIC PECFF FORENSICS · UNIT S/N #2026-SIH
          </span>
        </div>
        <div
          className="tabular-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          COMPLIANT: NIST SP 800-57 PT 1 REV 5 · RFC 7525 · RFC 8314 · ZERO EXTERNAL NET I/O
        </div>
      </footer>
    </div>
  );
};
