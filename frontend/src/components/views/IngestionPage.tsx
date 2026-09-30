import React, { useState } from "react";
import {
  UploadCloud, FileCheck, AlertCircle, XCircle, Play, CheckCircle2, Zap,
  Database, Cpu, Shield, BarChart2, ChevronRight, Sparkles,
} from "lucide-react";
import { uploadPcapFile, requestPresignedUpload, fetchTaskStatus, cancelTask, TaskStatusResponse } from "../../api/client";

const RELIC_BLUE  = "#1e6fc8";
const RELIC_NAVY  = "#0d1b2e";

interface IngestionPageProps {
  onAnalysisReady: (analysisId: string) => void;
  onLoadDemo: () => void;
}

type TabId = "upload" | "demo";

const DEMO_FEATURES = [
  { icon: <Cpu size={15} color="#2563eb" />, label: "1,024 pre-analyzed sessions" },
  { icon: <Shield size={15} color="#dc2626" />, label: "47 critical risk findings" },
  { icon: <BarChart2 size={15} color="#d97706" />, label: "Corpus beaconing detectors" },
  { icon: <Database size={15} color="#4f46e5" />, label: "94-dim ML anomaly scoring" },
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

  const stateColor = (state: string) => {
    if (state === "SUCCESS") return "#059669";
    if (state === "FAILURE") return "#dc2626";
    return "#2563eb";
  };

  return (
    <div style={{ minHeight: "calc(100vh - 56px)", background: "#f5f6fa", padding: "40px 0" }}>
      <div style={{ maxWidth: 860, margin: "0 auto", padding: "0 24px" }}>

        {/* Page title */}
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 28 }}>
          <img
            src="/relic-logo.png"
            alt="Relic"
            style={{ width: 44, height: 44, objectFit: "contain", filter: "drop-shadow(0 2px 8px rgba(30,111,200,0.2))" }}
          />
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <img
                src="/relic-wordmark.png"
                alt="RELIC"
                style={{ height: 28, width: "auto", objectFit: "contain", display: "block" }}
              />
              <span style={{ fontSize: 18, fontWeight: 800, color: RELIC_NAVY, letterSpacing: "-0.01em", borderLeft: "2px solid #dde2ee", paddingLeft: 12 }}>
                Forensic Ingestion
              </span>
            </div>
            <p style={{ color: "#7b93ab", marginTop: 4, fontSize: 13.5, fontWeight: 500 }}>
              Upload a PCAP/PCAPNG capture or explore the Relic demo corpus instantly.
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div style={{
          display: "inline-flex", background: "#fff",
          border: "1px solid #e2e6f0", borderRadius: 10,
          padding: 4, marginBottom: 28, boxShadow: "0 1px 4px rgba(15,23,42,0.06)",
        }}>
          {(["upload", "demo"] as TabId[]).map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab)} style={{
              padding: "7px 20px", borderRadius: 7, border: "none", cursor: "pointer",
              fontSize: 13, fontWeight: 600, transition: "all 0.15s ease",
              background: activeTab === tab ? `linear-gradient(135deg, ${RELIC_BLUE}, #2a5b8a)` : "transparent",
              color: activeTab === tab ? "#fff" : "#64748b",
              display: "flex", alignItems: "center", gap: 7,
            }}>
              {tab === "upload" ? <UploadCloud size={14} /> : <Sparkles size={14} />}
              {tab === "upload" ? "Upload Capture" : "Demo Dataset"}
            </button>
          ))}
        </div>

        {/* ── UPLOAD TAB ── */}
        {activeTab === "upload" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 20, alignItems: "start" }}>
            {/* Drop zone card */}
            <div className="card" style={{ padding: 28 }}>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: "#0f172a", marginBottom: 4, display: "flex", alignItems: "center", gap: 8 }}>
                <FileCheck size={17} color="#2563eb" /> Ingest PCAP / PCAPNG File
              </h3>
              <p style={{ fontSize: 12.5, color: "#64748b", marginBottom: 20 }}>
                Strict passive ingestion — validates magic bytes, strips L2 headers, computes SHA-256 on-the-fly.
              </p>

              {/* Drop zone */}
              <div
                onDragEnter={handleDrag} onDragLeave={handleDrag}
                onDragOver={handleDrag} onDrop={handleDrop}
                onClick={() => document.getElementById("file-input")?.click()}
                style={{
                  border: `2px dashed ${dragActive ? "#2563eb" : "#c8d0e0"}`,
                  borderRadius: 12, padding: "40px 24px", textAlign: "center",
                  background: dragActive ? "#eff6ff" : "#f8fafc",
                  cursor: "pointer", transition: "all 0.15s ease",
                  marginBottom: 20,
                }}
              >
                <input
                  id="file-input" type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={handleFileChange}
                  style={{ display: "none" }}
                />
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
                  <div style={{
                    width: 52, height: 52, borderRadius: "50%",
                    background: dragActive ? "#dbeafe" : "#f1f5f9",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    transition: "all 0.15s ease",
                  }}>
                    <UploadCloud size={26} color={dragActive ? "#2563eb" : "#94a3b8"} />
                  </div>
                  {file ? (
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 14, color: "#0f172a" }}>{file.name}</div>
                      <div style={{ fontSize: 12, color: "#64748b", marginTop: 3 }}>
                        {(file.size / (1024 * 1024)).toFixed(2)} MB · Ready for analysis
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 14, color: "#334155" }}>
                        Drop PCAP file here, or click to browse
                      </div>
                      <div style={{ fontSize: 12, color: "#94a3b8", marginTop: 4 }}>
                        .pcap, .pcapng, .cap · Up to 10 GB
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Options row */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "#64748b", cursor: "pointer" }}>
                  <input type="checkbox" checked={usePresigned} onChange={(e) => setUsePresigned(e.target.checked)} style={{ accentColor: "#2563eb" }} />
                  Use presigned S3 URL (captures &gt; 2 GiB)
                </label>
                <div style={{ display: "flex", gap: 8 }}>
                  {file && (
                    <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); setFile(null); }}>
                      Clear
                    </button>
                  )}
                  <button className="btn btn-primary" disabled={!file || uploading} onClick={startUpload} style={{ gap: 7 }}>
                    <Play size={14} />
                    {uploading ? "Analyzing…" : "Start Forensic Analysis"}
                  </button>
                </div>
              </div>

              {/* Error */}
              {errorMsg && (
                <div style={{
                  marginTop: 16, padding: "10px 14px", borderRadius: 8,
                  background: "#fef2f2", border: "1px solid #fecaca",
                  display: "flex", alignItems: "center", gap: 8, color: "#dc2626", fontSize: 12.5,
                }}>
                  <AlertCircle size={15} /> {errorMsg}
                </div>
              )}
            </div>

            {/* Sidebar info */}
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div className="card" style={{ padding: 18 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#64748b", letterSpacing: "0.06em", marginBottom: 12 }}>SUPPORTED FORMATS</div>
                {["Classic PCAP (microsecond/nanosecond)", "PCAPNG Section Header Block", "802.1Q VLAN capture files", "Compressed captures (.gz)"].map((f) => (
                  <div key={f} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, fontSize: 12.5, color: "#334155" }}>
                    <CheckCircle2 size={13} color="#059669" /> {f}
                  </div>
                ))}
              </div>
              <div className="card" style={{ padding: 18, background: "#fffbeb", border: "1px solid #fde68a" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#92400e", letterSpacing: "0.06em", marginBottom: 6 }}>PRIVACY NOTE</div>
                <p style={{ fontSize: 12, color: "#78350f", lineHeight: 1.6 }}>
                  All analysis is <strong>passive</strong> — no packets are modified, forwarded, or decrypted. Files are stored locally.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ── PIPELINE MONITOR ── */}
        {activeTask && (
          <div className="card" style={{ padding: 24, marginTop: 20, borderLeft: `3px solid ${stateColor(activeTask.state)}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <Zap size={18} color={stateColor(activeTask.state)} />
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "#0f172a" }}>
                    Forensic Pipeline Execution
                  </div>
                  <div style={{ fontSize: 11.5, color: "#64748b", marginTop: 2 }}>
                    Stage: <strong style={{ color: stateColor(activeTask.state) }}>{activeTask.state}</strong>
                    &nbsp;·&nbsp;{activeTask.stage_detail}
                  </div>
                </div>
              </div>
              {activeTask.state !== "SUCCESS" && activeTask.state !== "FAILURE" && (
                <button className="btn btn-danger btn-sm" onClick={async () => {
                  try { await cancelTask(activeTask.task_id); setActiveTask((prev) => prev ? { ...prev, state: "REVOKED" } : null); } catch { /**/ }
                }}>
                  <XCircle size={13} /> Cancel
                </button>
              )}
              {activeTask.state === "SUCCESS" && activeTask.analysis_id && (
                <button className="btn btn-primary btn-sm" onClick={() => onAnalysisReady(activeTask.analysis_id!)}
                  style={{ background: "#059669", borderColor: "#047857", gap: 6 }}>
                  <CheckCircle2 size={13} /> Open Dashboard
                </button>
              )}
            </div>

            {/* Progress bar */}
            <div style={{ background: "#f1f5f9", borderRadius: 9999, height: 8, overflow: "hidden", marginBottom: 16 }}>
              <div style={{
                width: `${Math.min(100, Math.max(5, (activeTask.progress || 0) * 100))}%`,
                height: "100%", borderRadius: 9999,
                background: activeTask.state === "SUCCESS" ? "linear-gradient(90deg,#059669,#10b981)" :
                  activeTask.state === "FAILURE" ? "#dc2626" : "linear-gradient(90deg,#2563eb,#4f46e5)",
                transition: "width 0.4s ease",
              }} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12 }}>
              {[
                { label: "Progress", value: `${Math.round((activeTask.progress || 0) * 100)}%` },
                { label: "Packets Processed", value: (activeTask.packets_processed || 0).toLocaleString() },
                { label: "ETA", value: activeTask.eta_seconds ? `${activeTask.eta_seconds}s` : "Calculating…" },
              ].map((s) => (
                <div key={s.label} style={{ background: "#f8fafc", borderRadius: 8, padding: "10px 14px", border: "1px solid #e2e6f0" }}>
                  <div style={{ fontSize: 10.5, color: "#94a3b8", textTransform: "uppercase", fontWeight: 600 }}>{s.label}</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#0f172a", marginTop: 2 }}>{s.value}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── DEMO TAB ── */}
        {activeTab === "demo" && (
          <div className="card" style={{ padding: 36, textAlign: "center", maxWidth: 560, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 10, marginBottom: 18 }}>
              <img src="/relic-logo.png" alt="Relic" style={{ width: 38, height: 38, objectFit: "contain", filter: "drop-shadow(0 2px 6px rgba(30,111,200,0.25))" }} />
              <img src="/relic-wordmark.png" alt="RELIC" style={{ height: 28, width: "auto", objectFit: "contain" }} />
            </div>

            <h2 style={{ fontSize: 22, fontWeight: 800, color: RELIC_NAVY, marginBottom: 8 }}>
              1,024-Session Enterprise Corpus
            </h2>
            <p style={{ color: "#64748b", fontSize: 14, lineHeight: 1.7, marginBottom: 28 }}>
              Explore a pre-analyzed enterprise mail capture with real downgrade attacks, weak
              ciphers, expired certificates, and beaconing patterns — no file upload required.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 32, textAlign: "left" }}>
              {DEMO_FEATURES.map((f) => (
                <div key={f.label} style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "12px 16px", background: "#f8fafc",
                  border: "1px solid #e2e6f0", borderRadius: 10,
                  fontSize: 13, fontWeight: 500, color: "#334155",
                }}>
                  {f.icon} {f.label}
                </div>
              ))}
            </div>

            <button className="btn btn-primary btn-lg" onClick={onLoadDemo} style={{ width: "100%", justifyContent: "center", gap: 8 }}>
              <Sparkles size={17} />
              Load Demo Dataset
              <ChevronRight size={16} />
            </button>
            <p style={{ marginTop: 12, fontSize: 12, color: "#94a3b8" }}>
              Instant load · No upload · Read-only corpus
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
