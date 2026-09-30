import React, { useState } from "react";
import {
  UploadCloud, AlertCircle, XCircle, Play, CheckCircle2,
  Database, Cpu, Shield, BarChart2, ChevronRight, Sparkles, HardDrive,
} from "lucide-react";
import { uploadPcapFile, requestPresignedUpload, fetchTaskStatus, cancelTask, TaskStatusResponse } from "../../api/client";
import { IndustrialCard } from "../common/IndustrialCard";
import { TactileButton } from "../common/TactileButton";
import { LedIndicator } from "../common/LedIndicator";

interface IngestionPageProps {
  onAnalysisReady: (analysisId: string) => void;
  onLoadDemo: () => void;
}

type TabId = "upload" | "demo";

const DEMO_FEATURES = [
  { icon: <Cpu size={14} color="var(--accent)" />, label: "1,024 pre-analyzed sessions" },
  { icon: <Shield size={14} color="var(--accent)" />, label: "47 critical risk findings" },
  { icon: <BarChart2 size={14} color="var(--accent)" />, label: "Corpus beaconing detectors" },
  { icon: <Database size={14} color="var(--accent)" />, label: "94-dim ML anomaly scoring" },
];

export const IngestionPage: React.FC<IngestionPageProps> = ({ onAnalysisReady, onLoadDemo }) => {
  const [activeTab, setActiveTab] = useState<TabId>("upload");
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [usePresigned, setUsePresigned] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeTask, setActiveTask] = useState<TaskStatusResponse | null>(null);
  const pollIntervalRef = React.useRef<number | null>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") setDragActive(true);
    else if (e.type === "dragleave") setDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) { setFile(e.dataTransfer.files[0]); setErrorMsg(null); }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) { setFile(e.target.files[0]); setErrorMsg(null); }
  };

  const startUpload = async () => {
    if (!file) return;
    setUploading(true); setErrorMsg(null);
    try {
      if (usePresigned || file.size > 2 * 1024 * 1024 * 1024) {
        const presign = await requestPresignedUpload(file.name, file.size);
        await fetch(presign.upload_url, {
          method: "PUT", body: file,
          headers: { "Content-Type": "application/vnd.tcpdump.pcap" },
        });
        setActiveTask({
          task_id: `task-${presign.analysis_id}`, state: "PARSING", progress: 0.1,
          stage_detail: "Ingested via direct S3 PUT, queued for shard parsing",
          packets_processed: 0, analysis_id: presign.analysis_id,
        });
      } else {
        const uploadRes = await uploadPcapFile(file);
        if (uploadRes.is_duplicate && uploadRes.duplicate_of) {
          onAnalysisReady(uploadRes.duplicate_of); setUploading(false); return;
        }
        setActiveTask({
          task_id: uploadRes.task_id, state: "PARSING", progress: 0.1,
          stage_detail: "Validating capture magic bytes and dispatching sharded chord",
          packets_processed: 0, analysis_id: uploadRes.analysis_id,
        });
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Upload failed"); setUploading(false);
    }
  };

  // Poll task
  React.useEffect(() => {
    if (!activeTask || activeTask.state === "SUCCESS" || activeTask.state === "FAILURE" || activeTask.state === "REVOKED") {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      return;
    }
    let ws: WebSocket | null = null;
    let wsConnected = false;
    try {
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${window.location.host}/api/v1/tasks/${activeTask.task_id}/stream`);
      ws.onopen = () => { wsConnected = true; if (pollIntervalRef.current) { clearInterval(pollIntervalRef.current); pollIntervalRef.current = null; } };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.payload) {
            setActiveTask(data.payload);
            if (data.payload.state === "SUCCESS" && data.payload.analysis_id) onAnalysisReady(data.payload.analysis_id);
          }
        } catch { /* ignore */ }
      };
      ws.onerror = () => { wsConnected = false; };
      ws.onclose = () => { wsConnected = false; };
    } catch { wsConnected = false; }

    pollIntervalRef.current = window.setInterval(async () => {
      if (wsConnected) return;
      try {
        const updated = await fetchTaskStatus(activeTask.task_id);
        setActiveTask(updated);
        if (updated.state === "SUCCESS" && updated.analysis_id) onAnalysisReady(updated.analysis_id);
        if (updated.state === "SUCCESS" || updated.state === "FAILURE" || updated.state === "REVOKED") {
          if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
        }
      } catch { /* silent */ }
    }, 1500);

    return () => { if (pollIntervalRef.current) clearInterval(pollIntervalRef.current); if (ws) ws.close(); };
  }, [activeTask?.task_id, activeTask?.state, onAnalysisReady]);

  return (
    <div style={{ minHeight: "calc(100vh - 60px)", background: "var(--chassis)", padding: "40px 0" }}>
      <div style={{ maxWidth: 960, margin: "0 auto", padding: "0 24px" }}>

        {/* Page Title & Bay Identification */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: 12,
                background: "var(--chassis)",
                boxShadow: "var(--shadow-card)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                border: "1px solid rgba(255,255,255,0.8)",
              }}
            >
              <HardDrive size={24} color="var(--accent)" />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <h1 style={{ fontSize: 22, fontWeight: 800 }} className="text-embossed-light">
                  FORENSIC INGESTION BAY
                </h1>
                <span className="stamped-label" style={{ color: "var(--accent)" }}>
                  MODULE #BAY-01
                </span>
              </div>
              <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 2 }}>
                Load network capture media into the passive protocol parsing and NIST scoring pipeline.
              </p>
            </div>
          </div>

          <LedIndicator status="green" label="CHASSIS READY" size="md" />
        </div>

        {/* Mode Selector Push Keys */}
        <div style={{ display: "flex", gap: 10, marginBottom: 24 }}>
          <TactileButton
            variant={activeTab === "upload" ? "recessed" : "chassis"}
            size="md"
            active={activeTab === "upload"}
            onClick={() => setActiveTab("upload")}
            icon={<UploadCloud size={14} />}
          >
            CAPTURE LOADING BAY
          </TactileButton>

          <TactileButton
            variant={activeTab === "demo" ? "recessed" : "chassis"}
            size="md"
            active={activeTab === "demo"}
            onClick={() => setActiveTab("demo")}
            icon={<Sparkles size={14} />}
          >
            CALIBRATED DEMO CASSETTE
          </TactileButton>
        </div>

        {/* ── UPLOAD BAY TAB ── */}
        {activeTab === "upload" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 24, alignItems: "start" }}>
            {/* Primary Ingestion Well */}
            <IndustrialCard
              elevation="base"
              bolted={true}
              vents={true}
              tag="PCAP / PCAPNG INGESTION WELL"
            >
              <p style={{ fontSize: 12.5, color: "var(--text-secondary)", marginBottom: 18 }}>
                Hardware streaming with microsecond timestamp normalization, 802.1Q VLAN unwrapping, and SHA-256 integrity verification.
              </p>

              {/* Recessed Tape Drop Well */}
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => document.getElementById("file-input")?.click()}
                style={{
                  background: dragActive ? "#c8d0de" : "var(--recessed)",
                  boxShadow: "var(--shadow-recessed)",
                  borderRadius: 14,
                  padding: "44px 24px",
                  textAlign: "center",
                  cursor: "pointer",
                  border: dragActive ? "2px dashed var(--accent)" : "2px dashed #babecc",
                  transition: "all 150ms ease",
                  marginBottom: 20,
                  position: "relative",
                }}
              >
                <input
                  id="file-input"
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={handleFileChange}
                  style={{ display: "none" }}
                />

                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
                  <div
                    style={{
                      width: 58,
                      height: 58,
                      borderRadius: "50%",
                      background: "var(--chassis)",
                      boxShadow: "var(--shadow-floating)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <UploadCloud size={28} color="var(--accent)" />
                  </div>

                  {file ? (
                    <div>
                      <div className="tabular-mono" style={{ fontWeight: 800, fontSize: 14, color: "var(--text-primary)" }}>
                        {file.name}
                      </div>
                      <div className="stamped-label" style={{ marginTop: 4, color: "var(--accent)" }}>
                        {(file.size / (1024 * 1024)).toFixed(2)} MB · READY FOR INGESTION
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 14, color: "var(--text-primary)" }}>
                        INSERT PCAP OR PCAPNG CAPTURE
                      </div>
                      <div className="stamped-label" style={{ marginTop: 6, fontSize: 10, color: "var(--text-muted)" }}>
                        DROP FILE OR CLICK TO ENGAGE MEDIA · UP TO 10 GIB
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Hardware Controls Row */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--text-secondary)", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={usePresigned}
                    onChange={(e) => setUsePresigned(e.target.checked)}
                    style={{ accentColor: "var(--accent)" }}
                  />
                  <span>PRESIGNED DIRECT S3 STREAM (&gt; 2 GIB)</span>
                </label>

                <div style={{ display: "flex", gap: 10 }}>
                  {file && (
                    <TactileButton
                      variant="chassis"
                      size="sm"
                      onClick={(e) => { e.stopPropagation(); setFile(null); }}
                    >
                      EJECT
                    </TactileButton>
                  )}
                  <TactileButton
                    variant="primary"
                    size="md"
                    disabled={!file || uploading}
                    onClick={startUpload}
                    icon={<Play size={13} />}
                  >
                    {uploading ? "ANALYZING TAPE..." : "ENGAGE ANALYSIS"}
                  </TactileButton>
                </div>
              </div>

              {/* Error Plaque */}
              {errorMsg && (
                <div
                  style={{
                    marginTop: 18,
                    padding: "12px 16px",
                    borderRadius: 10,
                    background: "#fef2f2",
                    boxShadow: "inset 2px 2px 4px rgba(239,68,68,0.2)",
                    border: "1px solid #fecaca",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    color: "#b91c1c",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                  }}
                >
                  <AlertCircle size={16} />
                  <span>{errorMsg}</span>
                </div>
              )}
            </IndustrialCard>

            {/* Side Specification Plates */}
            <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
              <IndustrialCard elevation="base" bolted={true} tag="VALIDATED FORMATS">
                {[
                  "Classic PCAP (μs / ns)",
                  "PCAPNG Multi-Interface",
                  "802.1Q / QinQ VLANs",
                  "GZIP Compressed (.gz)",
                ].map((format) => (
                  <div
                    key={format}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      marginBottom: 10,
                      fontFamily: "var(--font-mono)",
                      fontSize: 11,
                      color: "var(--text-primary)",
                    }}
                  >
                    <CheckCircle2 size={13} color="#22c55e" />
                    <span>{format}</span>
                  </div>
                ))}
              </IndustrialCard>

              <IndustrialCard
                elevation="recessed"
                tag="AIR-GAP SECURITY GUARANTEE"
                style={{ padding: "16px 20px" }}
              >
                <p style={{ fontSize: 11.5, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                  Strictly <strong>passive network forensics</strong>. Zero outbound packets, zero DNS queries, zero online CRL/OCSP requests. Evidentiary provenance maintained in-process.
                </p>
              </IndustrialCard>
            </div>
          </div>
        )}

        {/* ── PIPELINE MONITOR INSTRUMENT ── */}
        {activeTask && (
          <IndustrialCard
            elevation="dark"
            bolted={true}
            tag="REAL-TIME TELEMETRY ENGINE"
            style={{ marginTop: 28 }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <LedIndicator
                  status={activeTask.state === "SUCCESS" ? "green" : activeTask.state === "FAILURE" ? "red" : "orange"}
                  size="md"
                />
                <div>
                  <div className="tabular-mono" style={{ fontSize: 14, fontWeight: 800, color: "#ffffff" }}>
                    PIPELINE TASK: {activeTask.task_id}
                  </div>
                  <div
                    className="tabular-mono"
                    style={{ fontSize: 11, color: "#a8b2d1", marginTop: 3 }}
                  >
                    STAGE: <strong style={{ color: "var(--accent)" }}>{activeTask.state}</strong> · {activeTask.stage_detail}
                  </div>
                </div>
              </div>

              {activeTask.state !== "SUCCESS" && activeTask.state !== "FAILURE" && (
                <TactileButton
                  variant="chassis"
                  size="sm"
                  onClick={async () => {
                    try { await cancelTask(activeTask.task_id); setActiveTask((prev) => prev ? { ...prev, state: "REVOKED" } : null); } catch { /* ignore */ }
                  }}
                  icon={<XCircle size={13} />}
                >
                  ABORT
                </TactileButton>
              )}

              {activeTask.state === "SUCCESS" && activeTask.analysis_id && (
                <TactileButton
                  variant="primary"
                  size="md"
                  onClick={() => onAnalysisReady(activeTask.analysis_id!)}
                  iconRight={<CheckCircle2 size={14} />}
                >
                  VIEW TELEMETRY DASHBOARD
                </TactileButton>
              )}
            </div>

            {/* Recessed Hardware Gauge */}
            <div
              style={{
                background: "#14181d",
                borderRadius: 9999,
                height: 12,
                overflow: "hidden",
                boxShadow: "inset 0 2px 4px rgba(0,0,0,0.8)",
                marginBottom: 16,
                padding: "2px",
              }}
            >
              <div
                style={{
                  width: `${Math.min(100, Math.max(5, (activeTask.progress || 0) * 100))}%`,
                  height: "100%",
                  borderRadius: 9999,
                  background: activeTask.state === "SUCCESS"
                    ? "linear-gradient(90deg, #10b981, #22c55e)"
                    : activeTask.state === "FAILURE"
                    ? "#ef4444"
                    : "linear-gradient(90deg, var(--accent), #ff7a88)",
                  boxShadow: "0 0 10px rgba(255,71,87,0.8)",
                  transition: "width 0.4s var(--ease-spring)",
                }}
              />
            </div>

            {/* Instrument Readout Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14 }}>
              {[
                { label: "PROGRESS", value: `${Math.round((activeTask.progress || 0) * 100)}%` },
                { label: "PACKETS REASSEMBLED", value: (activeTask.packets_processed || 0).toLocaleString() },
                { label: "ESTIMATED ETA", value: activeTask.eta_seconds ? `${activeTask.eta_seconds}s` : "ACTIVE" },
              ].map((m) => (
                <div
                  key={m.label}
                  style={{
                    background: "#14181d",
                    borderRadius: 10,
                    padding: "12px 16px",
                    border: "1px solid rgba(255,255,255,0.06)",
                  }}
                >
                  <div className="stamped-label" style={{ fontSize: 9.5, color: "#a8b2d1" }}>
                    {m.label}
                  </div>
                  <div
                    className="tabular-mono"
                    style={{ fontSize: 16, fontWeight: 800, color: "#ffffff", marginTop: 4 }}
                  >
                    {m.value}
                  </div>
                </div>
              ))}
            </div>
          </IndustrialCard>
        )}

        {/* ── DEMO CASSETTE TAB ── */}
        {activeTab === "demo" && (
          <div style={{ maxWidth: 640, margin: "0 auto" }}>
            <IndustrialCard elevation="base" bolted={true} vents={true} tag="PRE-RECORDED TELEMETRY CASSETTE">
              <div style={{ textAlign: "center", padding: "10px 14px 20px" }}>
                <h2 style={{ fontSize: 20, fontWeight: 800, marginBottom: 8 }} className="text-embossed-light">
                  1,024-SESSION ENTERPRISE CORPUS
                </h2>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.7, marginBottom: 28 }}>
                  Pre-assembled forensic tape containing real STARTTLS protocol downgrades, weak DH groups, expired X.509 certificates, cleartext credentials, and periodic C2 beaconing.
                </p>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 30, textAlign: "left" }}>
                  {DEMO_FEATURES.map((f) => (
                    <div
                      key={f.label}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "12px 14px",
                        background: "var(--recessed)",
                        boxShadow: "var(--shadow-recessed)",
                        borderRadius: 10,
                        fontFamily: "var(--font-mono)",
                        fontSize: 11.5,
                        fontWeight: 600,
                        color: "var(--text-primary)",
                      }}
                    >
                      {f.icon}
                      <span>{f.label}</span>
                    </div>
                  ))}
                </div>

                <TactileButton
                  variant="primary"
                  size="lg"
                  onClick={onLoadDemo}
                  style={{ width: "100%", justifyContent: "center" }}
                  icon={<Sparkles size={16} />}
                  iconRight={<ChevronRight size={16} />}
                >
                  LOAD PRE-RECORDED CASSETTE INTO SWITCHBOARD
                </TactileButton>
                <div className="stamped-label" style={{ marginTop: 12, fontSize: 10, color: "var(--text-muted)" }}>
                  INSTANT MOUNT · ZERO I/O LATENCY · AUDIT-GRADE PROVENANCE
                </div>
              </div>
            </IndustrialCard>
          </div>
        )}
      </div>
    </div>
  );
};
