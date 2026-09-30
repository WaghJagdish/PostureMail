import React, { useState, useEffect, useRef } from "react";
import { UploadCloud, FileCheck, AlertCircle, XCircle, Play, CheckCircle2, Zap } from "lucide-react";
import { uploadPcapFile, requestPresignedUpload, fetchTaskStatus, cancelTask, TaskStatusResponse } from "../../api/client";

interface UploadQueueViewProps {
  onAnalysisReady: (analysisId: string) => void;
  isMockMode: boolean;
}

export const UploadQueueView: React.FC<UploadQueueViewProps> = ({
  onAnalysisReady,
  isMockMode: _isMockMode,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [usePresigned, setUsePresigned] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Active Task Tracking
  const [activeTask, setActiveTask] = useState<TaskStatusResponse | null>(null);
  const pollIntervalRef = useRef<number | null>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setErrorMsg(null);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setErrorMsg(null);
    }
  };

  const startUpload = async () => {
    if (!file) return;

    setUploading(true);
    setErrorMsg(null);

    try {
      if (usePresigned || file.size > 2 * 1024 * 1024 * 1024) {
        // Presigned S3 Upload Path
        const presign = await requestPresignedUpload(file.name, file.size);
        await fetch(presign.upload_url, {
          method: "PUT",
          body: file,
          headers: { "Content-Type": "application/vnd.tcpdump.pcap" },
        });
        setActiveTask({
          task_id: `task-${presign.analysis_id}`,
          state: "PARSING",
          progress: 0.1,
          stage_detail: "Ingested via direct S3 PUT, queued for shard parsing",
          packets_processed: 0,
          analysis_id: presign.analysis_id,
        });
      } else {
        // Direct Multipart Streaming Path
        const uploadRes = await uploadPcapFile(file);

        if (uploadRes.is_duplicate && uploadRes.duplicate_of) {
          // Deduplication hit -> direct open
          onAnalysisReady(uploadRes.duplicate_of);
          setUploading(false);
          return;
        }

        setActiveTask({
          task_id: uploadRes.task_id,
          state: "PARSING",
          progress: 0.1,
          stage_detail: "Validating capture magic bytes and dispatching sharded chord",
          packets_processed: 0,
          analysis_id: uploadRes.analysis_id,
        });
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Upload failed");
      setUploading(false);
    }
  };

  // Poll Task Status or WebSocket Stream
  useEffect(() => {
    if (!activeTask || activeTask.state === "SUCCESS" || activeTask.state === "FAILURE" || activeTask.state === "REVOKED") {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      return;
    }

    // Try WebSocket connection first; fall back to polling if it fails
    let ws: WebSocket | null = null;
    let wsConnected = false;

    try {
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${window.location.host}/api/v1/tasks/${activeTask.task_id}/stream`);
      ws.onopen = () => {
        wsConnected = true;
        // Stop any existing poll when WS connects
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current);
          pollIntervalRef.current = null;
        }
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.payload) {
            setActiveTask(data.payload);
            if (data.payload.state === "SUCCESS" && data.payload.analysis_id) {
              onAnalysisReady(data.payload.analysis_id);
            }
          }
        } catch {
          // Ignore malformed WS frames
        }
      };
      ws.onerror = () => {
        wsConnected = false;
      };
      ws.onclose = () => {
        wsConnected = false;
      };
    } catch {
      wsConnected = false;
    }

    // Start polling as a fallback (will be cancelled if WS connects successfully)
    pollIntervalRef.current = window.setInterval(async () => {
      // Skip polling if WebSocket is connected
      if (wsConnected) return;
      try {
        const updated = await fetchTaskStatus(activeTask.task_id);
        setActiveTask(updated);
        if (updated.state === "SUCCESS" && updated.analysis_id) {
          onAnalysisReady(updated.analysis_id);
        }
        if (updated.state === "SUCCESS" || updated.state === "FAILURE" || updated.state === "REVOKED") {
          if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
        }
      } catch {
        // Silent poll error
      }
    }, 1500);

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      if (ws) ws.close();
    };
  }, [activeTask?.task_id, activeTask?.state, onAnalysisReady]);

  const handleCancelTask = async () => {
    if (!activeTask) return;
    try {
      await cancelTask(activeTask.task_id);
      setActiveTask((prev) => (prev ? { ...prev, state: "REVOKED", stage_detail: "Analysis task cancelled by analyst" } : null));
    } catch (err: any) {
      setErrorMsg(err.message);
    }
  };

  return (
    <div style={{ padding: "8px 16px", maxWidth: 1200, margin: "0 auto" }}>
      {/* Upload Box */}
      <div className="card" style={{ padding: 24, marginBottom: 24, background: "rgba(17, 24, 39, 0.6)", backdropFilter: "blur(12px)" }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4, color: "#fff", display: "flex", alignItems: "center", gap: 8 }}>
          <UploadCloud size={20} color="#38bdf8" />
          Ingest Mail Capture File (PCAP / PCAPNG)
        </h2>
        <p style={{ fontSize: 12.5, color: "var(--text-secondary)", marginBottom: 20 }}>
          Strict passive ingestion. Validates magic bytes, strips L2 headers, unwraps 802.1Q VLANs, and computes SHA-256 on-the-fly.
        </p>

        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          style={{
            border: `2px dashed ${dragActive ? "#38bdf8" : "#334155"}`,
            borderRadius: 10,
            padding: "36px 20px",
            textAlign: "center",
            background: dragActive ? "rgba(56, 189, 248, 0.05)" : "rgba(15, 23, 42, 0.4)",
            cursor: "pointer",
            transition: "all 0.15s ease",
          }}
          onClick={() => document.getElementById("file-input")?.click()}
        >
          <input
            id="file-input"
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={handleFileChange}
            style={{ display: "none" }}
          />

          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
            <div style={{ width: 48, height: 48, borderRadius: "50%", background: "rgba(56, 189, 248, 0.1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <FileCheck size={26} color="#38bdf8" />
            </div>

            {file ? (
              <div>
                <div className="font-mono" style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>
                  {file.name}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                  {(file.size / (1024 * 1024)).toFixed(2)} MB &bull; Ready for passive analysis
                </div>
              </div>
            ) : (
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>
                  Drag & Drop PCAP file here, or click to browse
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                  Supports classic PCAP (microsecond/nanosecond) and PCAPNG up to 10+ GB
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Options & Action */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 18 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--text-secondary)", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={usePresigned}
              onChange={(e) => setUsePresigned(e.target.checked)}
              style={{ accentColor: "#0284c7" }}
            />
            <span>Enable direct S3 presigned PUT URL upload (Recommended for captures &gt; 2 GiB)</span>
          </label>

          <div style={{ display: "flex", gap: 10 }}>
            {file && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={(e) => {
                  e.stopPropagation();
                  setFile(null);
                }}
              >
                Clear
              </button>
            )}
            <button
              className="btn btn-primary"
              disabled={!file || uploading}
              onClick={startUpload}
              style={{ padding: "8px 20px" }}
            >
              <Play size={14} />
              <span>{uploading ? "Analyzing..." : "Start Forensic Analysis"}</span>
            </button>
          </div>
        </div>

        {errorMsg && (
          <div style={{ marginTop: 16, padding: "10px 14px", borderRadius: 6, background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.3)", display: "flex", alignItems: "center", gap: 8, color: "#f87171", fontSize: 12.5 }}>
            <AlertCircle size={16} />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Live Pipeline Task Execution Monitor */}
      {activeTask && (
        <div className="card" style={{ padding: 20, borderLeft: "4px solid #38bdf8", background: "rgba(17, 24, 39, 0.85)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <Zap size={18} color="#38bdf8" />
              <div>
                <h3 style={{ fontSize: 15, fontWeight: 700, color: "#fff" }}>
                  Forensic Pipeline Execution: <span className="font-mono" style={{ fontSize: 13, color: "#38bdf8" }}>{activeTask.task_id}</span>
                </h3>
                <div style={{ fontSize: 11.5, color: "var(--text-secondary)" }}>
                  Stage: <b style={{ color: "#f8fafc" }}>{activeTask.state}</b> &bull; {activeTask.stage_detail}
                </div>
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              {activeTask.state !== "SUCCESS" && activeTask.state !== "FAILURE" && (
                <button onClick={handleCancelTask} className="btn btn-danger btn-sm" style={{ gap: 4 }}>
                  <XCircle size={13} />
                  <span>Cancel</span>
                </button>
              )}
              {activeTask.state === "SUCCESS" && activeTask.analysis_id && (
                <button
                  onClick={() => onAnalysisReady(activeTask.analysis_id!)}
                  className="btn btn-primary btn-sm"
                  style={{ gap: 4, background: "#10b981", borderColor: "#059669" }}
                >
                  <CheckCircle2 size={13} />
                  <span>Open Triage Console</span>
                </button>
              )}
            </div>
          </div>

          {/* Progress Bar */}
          <div style={{ background: "#0d131f", borderRadius: 9999, height: 10, overflow: "hidden", border: "1px solid var(--border-subtle)", margin: "14px 0" }}>
            <div
              style={{
                width: `${Math.min(100, Math.max(5, (activeTask.progress || 0) * 100))}%`,
                height: "100%",
                background: activeTask.state === "SUCCESS" ? "linear-gradient(90deg, #059669, #10b981)" : activeTask.state === "FAILURE" ? "#ef4444" : "linear-gradient(90deg, #0284c7, #38bdf8)",
                transition: "width 0.3s ease",
              }}
            />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 14 }}>
            <div style={{ background: "rgba(0, 0, 0, 0.25)", padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 10.5, textTransform: "uppercase", color: "var(--text-muted)" }}>Progress</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{Math.round((activeTask.progress || 0) * 100)}%</div>
            </div>
            <div style={{ background: "rgba(0, 0, 0, 0.25)", padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 10.5, textTransform: "uppercase", color: "var(--text-muted)" }}>Packets Processed</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{(activeTask.packets_processed || 0).toLocaleString()}</div>
            </div>
            <div style={{ background: "rgba(0, 0, 0, 0.25)", padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 10.5, textTransform: "uppercase", color: "var(--text-muted)" }}>Sharded Chord</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#38bdf8" }}>4 Flow-Safe Workers</div>
            </div>
            <div style={{ background: "rgba(0, 0, 0, 0.25)", padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 10.5, textTransform: "uppercase", color: "var(--text-muted)" }}>ETA</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#10b981" }}>{activeTask.eta_seconds ? `${activeTask.eta_seconds}s` : "Calculating..."}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
