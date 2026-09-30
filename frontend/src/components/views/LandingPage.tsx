import React, { useEffect, useRef, useState } from "react";
import { ArrowRight, Zap, Lock, BarChart2, Search, ChevronRight, Shield } from "lucide-react";

interface LandingPageProps {
  onEnterConsole: () => void;
  onGoToIngestion: () => void;
}

/* ── Relic brand constants ── */
const RELIC_NAVY   = "#0d1b2e";
const RELIC_BLUE   = "#1e6fc8";
const RELIC_BRIGHT = "#38b6ff";
const RELIC_STEEL  = "#2a5b8a";

/* ── Animated canvas network visualizer ── */
const PacketVisualizer: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef   = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    type Node = { x: number; y: number; vx: number; vy: number; r: number; color: string };
    type Packet = { ci: number; t: number; speed: number; color: string };

    const COLORS = [RELIC_BLUE, RELIC_BRIGHT, RELIC_STEEL, "#60c8ff", "#1e90ff"];
    const W = canvas.width, H = canvas.height;
    const nodes: Node[] = Array.from({ length: 20 }, () => ({
      x: 40 + Math.random() * (W - 80), y: 40 + Math.random() * (H - 80),
      vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
      r: 3 + Math.random() * 3, color: COLORS[Math.floor(Math.random() * COLORS.length)],
    }));

    // build edges for close nodes
    const edges: [number, number][] = [];
    for (let i = 0; i < nodes.length; i++)
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
        if (Math.sqrt(dx*dx + dy*dy) < 150) edges.push([i, j]);
      }

    const packets: Packet[] = Array.from({ length: 14 }, () => ({
      ci: Math.floor(Math.random() * edges.length),
      t: Math.random(),
      speed: 0.005 + Math.random() * 0.007,
      color: COLORS[Math.floor(Math.random() * COLORS.length)],
    }));

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      nodes.forEach((n) => {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 20 || n.x > W - 20) n.vx *= -1;
        if (n.y < 20 || n.y > H - 20) n.vy *= -1;
      });
      // edges
      edges.forEach(([a, b]) => {
        ctx.beginPath(); ctx.moveTo(nodes[a].x, nodes[a].y); ctx.lineTo(nodes[b].x, nodes[b].y);
        ctx.strokeStyle = "rgba(30,111,200,0.1)"; ctx.lineWidth = 1; ctx.stroke();
      });
      // packets
      packets.forEach((p) => {
        p.t += p.speed; if (p.t >= 1) p.t = 0;
        const [ai, bi] = edges[p.ci];
        const x = nodes[ai].x + (nodes[bi].x - nodes[ai].x) * p.t;
        const y = nodes[ai].y + (nodes[bi].y - nodes[ai].y) * p.t;
        ctx.beginPath(); ctx.arc(x, y, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = p.color; ctx.globalAlpha = 0.9; ctx.fill(); ctx.globalAlpha = 1;
      });
      // nodes
      nodes.forEach((n) => {
        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 5);
        grd.addColorStop(0, n.color + "30"); grd.addColorStop(1, n.color + "00");
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r * 5, 0, Math.PI * 2); ctx.fillStyle = grd; ctx.fill();
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fillStyle = n.color; ctx.globalAlpha = 0.85; ctx.fill(); ctx.globalAlpha = 1;
      });
      animRef.current = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, []);

  return <canvas ref={canvasRef} style={{ width: "100%", height: "100%", display: "block" }} />;
};

/* ── Feature pill ── */
const Feature: React.FC<{ icon: React.ReactNode; label: string }> = ({ icon, label }) => (
  <div style={{
    display: "flex", alignItems: "center", gap: 8, padding: "8px 14px",
    background: "rgba(30,111,200,0.05)", border: "1px solid rgba(30,111,200,0.14)",
    borderRadius: 8, fontSize: 12.5, fontWeight: 600, color: "#1a2d45",
    fontFamily: "var(--font-display)", letterSpacing: "-0.01em",
  }}>
    {icon} {label}
  </div>
);

/* ── Stat card ── */
const StatCard: React.FC<{ value: string; label: string }> = ({ value, label }) => (
  <div style={{
    background: "#fff", border: "1px solid #dde2ee", borderRadius: 12,
    padding: "14px 20px", boxShadow: "0 2px 8px rgba(13,27,46,0.07)",
    textAlign: "center", minWidth: 100,
  }}>
    <div className="font-display tabular-nums" style={{
      fontSize: 24, fontWeight: 900, letterSpacing: "-0.03em",
      background: `linear-gradient(135deg, ${RELIC_BLUE}, ${RELIC_BRIGHT})`,
      WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
    }}>
      {value}
    </div>
    <div className="text-eyebrow" style={{ fontSize: 10.5, color: "#7b93ab", marginTop: 4 }}>
      {label}
    </div>
  </div>
);

export const LandingPage: React.FC<LandingPageProps> = ({ onEnterConsole, onGoToIngestion }) => {
  const [scanY, setScanY] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setScanY((p) => (p + 1) % 100), 28);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{ minHeight: "100vh", background: "linear-gradient(150deg, #f0f4ff 0%, #f4f6fb 55%, #eaf4fb 100%)" }}>

      {/* ── Navbar ── */}
      <nav style={{
        position: "sticky", top: 0, zIndex: 100,
        background: "rgba(255,255,255,0.9)", backdropFilter: "blur(16px)",
        borderBottom: "1px solid #dde2ee",
        padding: "0 40px", height: 60,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        boxShadow: "0 1px 4px rgba(13,27,46,0.06)",
      }}>
        {/* Logo + wordmark */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <img src="/relic-logo.png" alt="Relic Logo" style={{ width: 34, height: 34, objectFit: "contain" }} />
          <img src="/relic-wordmark.png" alt="RELIC" style={{ height: 26, width: "auto", objectFit: "contain", display: "block" }} />
          <span style={{
            fontSize: 9.5, fontWeight: 700, letterSpacing: "0.12em", color: RELIC_BLUE,
            textTransform: "uppercase", borderLeft: "1px solid #dde2ee", paddingLeft: 10,
          }}>
            Forensics Platform
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={onGoToIngestion}>Analyze File</button>
          <button className="btn btn-primary btn-sm" onClick={onEnterConsole} style={{ gap: 6 }}>
            Open Console <ArrowRight size={13} />
          </button>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section style={{
        maxWidth: 1280, margin: "0 auto",
        padding: "80px 40px 64px",
        display: "grid", gridTemplateColumns: "1fr 1fr",
        gap: 72, alignItems: "center",
      }}>
        {/* LEFT — CTA */}
        <div className="fade-up">
          {/* Brand showcase badge */}
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
            <img
              src="/relic-logo.png"
              alt="Relic Logo"
              style={{ width: 48, height: 48, objectFit: "contain", filter: "drop-shadow(0 4px 14px rgba(30,111,200,0.3))" }}
            />
            <img
              src="/relic-wordmark.png"
              alt="RELIC"
              style={{ height: 42, width: "auto", objectFit: "contain", filter: "drop-shadow(0 2px 8px rgba(13,27,46,0.12))" }}
            />
          </div>

          {/* Status badge */}
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8, marginBottom: 24,
            background: "rgba(30,111,200,0.08)", border: "1px solid rgba(30,111,200,0.2)",
            borderRadius: 9999, padding: "5px 14px",
          }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: RELIC_BRIGHT, display: "inline-block" }} className="pulse-active" />
            <span style={{ fontSize: 12, fontWeight: 600, color: RELIC_BLUE, letterSpacing: "0.04em" }}>
              NIST SP 800-57 · RFC 7525 · STARTTLS Detection
            </span>
          </div>

          <h1 style={{
            fontSize: "clamp(36px, 4.2vw, 54px)", fontWeight: 900,
            lineHeight: 1.08, letterSpacing: "-0.03em", color: RELIC_NAVY, marginBottom: 20,
          }}>
            Passive Email<br />
            <span className="relic-gradient-text">Crypto Forensics</span>
          </h1>

          <p style={{ fontSize: 16.5, color: "#3d566e", lineHeight: 1.75, maxWidth: 480, marginBottom: 36 }}>
            Deep-inspect PCAP captures for STARTTLS downgrade attacks, weak cipher suites,
            certificate anomalies and beacon patterns — fully passive, zero interception.
          </p>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 40 }}>
            <button className="btn btn-primary btn-lg" onClick={onGoToIngestion} style={{ gap: 8 }}>
              <Zap size={17} /> Start Analysis
            </button>
            <button className="btn btn-secondary btn-lg" onClick={onEnterConsole} style={{ gap: 8 }}>
              View Demo <ChevronRight size={16} />
            </button>
          </div>

          {/* Stats */}
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 24 }}>
            <StatCard value="9" label="Downgrade Detectors" />
            <StatCard value="94-dim" label="ML Feature Vector" />
            <StatCard value="NIST" label="SP 800-57 Scoring" />
          </div>

          {/* Feature pills */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            <Feature icon={<Lock size={13} color={RELIC_BLUE} />} label="STARTTLS FSM Tracking" />
            <Feature icon={<Search size={13} color={RELIC_BLUE} />} label="Cipher Suite Analysis" />
            <Feature icon={<BarChart2 size={13} color={RELIC_BLUE} />} label="Corpus Beaconing" />
            <Feature icon={<Shield size={13} color={RELIC_BLUE} />} label="X.509 Certificate Parsing" />
          </div>
        </div>

        {/* RIGHT — Interactive visualizer panel */}
        <div style={{ position: "relative" }}>
          {/* Panel */}
          <div style={{
            borderRadius: 20, overflow: "hidden",
            border: "1.5px solid rgba(30,111,200,0.18)",
            boxShadow: "0 12px 48px rgba(13,27,46,0.12), 0 2px 8px rgba(30,111,200,0.08)",
            background: "#fff",
            animation: "glow-ring 4.5s ease-in-out infinite",
          }}>
            {/* Title bar */}
            <div style={{
              padding: "10px 18px", borderBottom: "1px solid #dde2ee",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              background: RELIC_NAVY,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                <img src="/relic-logo.png" alt="Relic" style={{ width: 22, height: 22, objectFit: "contain" }} />
                <div style={{ background: "rgba(255,255,255,0.95)", padding: "2px 7px", borderRadius: 4, display: "flex", alignItems: "center" }}>
                  <img src="/relic-wordmark.png" alt="RELIC" style={{ height: 14, width: "auto", objectFit: "contain" }} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: RELIC_BRIGHT, letterSpacing: "0.06em" }}>
                  · LIVE FORENSIC ENGINE
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 7, height: 7, borderRadius: "50%", background: RELIC_BRIGHT }} className="pulse-active" />
                <span style={{ fontSize: 10.5, color: RELIC_BRIGHT, fontWeight: 700 }}>ACTIVE</span>
              </div>
            </div>

            {/* Canvas */}
            <div style={{ height: 300, position: "relative", overflow: "hidden", background: "#f8fbff" }}>
              <PacketVisualizer />
              {/* Scan line */}
              <div style={{
                position: "absolute", left: 0, right: 0, height: 1.5,
                background: `linear-gradient(90deg, transparent, ${RELIC_BRIGHT}60, transparent)`,
                top: `${scanY * 3}px`, pointerEvents: "none", transition: "top 0.03s linear",
              }} />
            </div>

            {/* Stats bar */}
            <div style={{
              display: "grid", gridTemplateColumns: "repeat(4,1fr)",
              borderTop: "1px solid #dde2ee", background: "#fff",
            }}>
              {[
                { label: "Sessions",   value: "1,024", color: RELIC_BLUE },
                { label: "Critical",   value: "47",    color: "#dc2626" },
                { label: "Weak TLS",   value: "129",   color: "#d97706" },
                { label: "Risk Score", value: "78.4",  color: RELIC_STEEL },
              ].map((s) => (
                <div key={s.label} style={{ textAlign: "center", padding: "12px 8px", borderRight: "1px solid #f4f6fb" }}>
                  <div style={{ fontSize: 17, fontWeight: 800, color: s.color, fontFamily: "JetBrains Mono, monospace" }}>{s.value}</div>
                  <div style={{ fontSize: 10.5, color: "#7b93ab", fontWeight: 500, marginTop: 2 }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Floating annotation cards */}
          <div style={{
            position: "absolute", top: -14, right: -14,
            background: "#fff", border: "1px solid rgba(220,38,38,0.25)",
            borderRadius: 10, padding: "9px 14px",
            boxShadow: "0 4px 16px rgba(220,38,38,0.12)",
            animation: "float 4.5s ease-in-out infinite",
          }}>
            <div style={{ fontSize: 10, color: "#7b93ab", fontWeight: 600, textTransform: "uppercase" }}>Detected</div>
            <div style={{ fontSize: 13, fontWeight: 800, color: "#dc2626" }}>STARTTLS Downgrade</div>
          </div>

          <div style={{
            position: "absolute", bottom: 64, left: -18,
            background: "#fff", border: "1px solid rgba(30,111,200,0.2)",
            borderRadius: 10, padding: "9px 14px",
            boxShadow: "0 4px 16px rgba(30,111,200,0.12)",
            animation: "float 5.5s ease-in-out infinite 1.2s",
          }}>
            <div style={{ fontSize: 10, color: "#7b93ab", fontWeight: 600, textTransform: "uppercase" }}>Cipher Suite</div>
            <div className="font-mono" style={{ fontSize: 11.5, fontWeight: 700, color: RELIC_BLUE }}>
              TLS_AES_256_GCM_SHA384
            </div>
          </div>
        </div>
      </section>

      {/* ── How it Works ── */}
      <section style={{ maxWidth: 1280, margin: "0 auto", padding: "32px 40px 80px" }}>
        <div style={{ textAlign: "center", marginBottom: 44 }}>
          <div className="text-eyebrow" style={{ marginBottom: 8 }}>
            HOW IT WORKS
          </div>
          <h2 style={{ fontSize: 28, fontWeight: 800, color: RELIC_NAVY, letterSpacing: "-0.03em" }}>
            Zero-configuration passive pipeline
          </h2>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 18 }}>
          {[
            { step: "01", emoji: "📁", title: "Upload PCAP", desc: "Drag & drop your capture. Magic-byte validated, SHA-256 deduplicated instantly." },
            { step: "02", emoji: "🔬", title: "Parse & Classify", desc: "TCP reassembly, SMTP/IMAP/POP3 detection and STARTTLS state-machine traversal." },
            { step: "03", emoji: "📊", title: "Score & Detect", desc: "NIST SP 800-57 deterministic risk + 94-dim IsolationForest ML anomaly scoring." },
            { step: "04", emoji: "📋", title: "Triage Dashboard", desc: "Session table, corpus correlations, beacon detection and forensic verdicts." },
          ].map((item) => (
            <div key={item.step} style={{
              background: "#fff", border: "1px solid #dde2ee", borderRadius: 14,
              padding: "24px 20px", boxShadow: "0 2px 8px rgba(13,27,46,0.06)",
              textAlign: "center", position: "relative", overflow: "hidden",
            }}>
              {/* accent top bar */}
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, ${RELIC_BLUE}, ${RELIC_BRIGHT})` }} />
              <div style={{
                width: 48, height: 48, borderRadius: 14, margin: "12px auto 14px",
                background: "linear-gradient(135deg, rgba(30,111,200,0.08), rgba(56,182,255,0.12))",
                display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22,
              }}>{item.emoji}</div>
              <div className="text-eyebrow tabular-nums" style={{ fontSize: 10.5, marginBottom: 6 }}>
                STEP {item.step}
              </div>
              <div className="font-display" style={{ fontSize: 15, fontWeight: 700, color: RELIC_NAVY, marginBottom: 8, letterSpacing: "-0.015em" }}>
                {item.title}
              </div>
              <div style={{ fontSize: 12.5, color: "#3d566e", lineHeight: 1.65 }}>{item.desc}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Footer ── */}
      <footer style={{
        borderTop: "1px solid #dde2ee", padding: "20px 40px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: "#fff",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <img src="/relic-logo.png" alt="Relic" style={{ width: 24, height: 24, objectFit: "contain", opacity: 0.85 }} />
          <img src="/relic-wordmark.png" alt="RELIC" style={{ height: 18, width: "auto", objectFit: "contain", opacity: 0.9 }} />
        </div>
        <div style={{ fontSize: 11.5, color: "#7b93ab" }}>
          Passive Email Cryptographic Forensics Platform · Built for SIH · NIST SP 800-57 · RFC 7525 · RFC 8314
        </div>
      </footer>
    </div>
  );
};
