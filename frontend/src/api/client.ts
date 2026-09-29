/**
 * Typed API Client for PECFF REST and WebSocket endpoints.
 * Includes fallback mock data generator for 1,000-session instant triage simulation.
 */

import { components } from "./types";

export type TaskStatusResponse = components["schemas"]["TaskStatusResponse"];
export type PcapUploadResponse = components["schemas"]["PcapUploadResponse"];
export type PresignedUploadResponse = components["schemas"]["PresignedUploadResponse"];
export type VerdictSubmissionRequest = components["schemas"]["VerdictSubmissionRequest"];
export type VerdictSubmissionResponse = components["schemas"]["VerdictSubmissionResponse"];
export type CursorPaginatedSessions = components["schemas"]["CursorPaginatedSessions"];
export type SessionSummarySchema = components["schemas"]["SessionSummarySchema"];
export type AuditLogEntrySchema = components["schemas"]["AuditLogEntrySchema"];

export type AnalystVerdictCreate = {
  session_id?: string;
  analysis_id?: string;
  verdict: "BENIGN" | "SUSPICIOUS" | "MALICIOUS" | "POLICY_VIOLATION" | "TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN_KNOWN";
  confidence?: number;
  analyst_notes?: string;
  notes?: string;
  tags?: string[];
};

export type AnalystVerdictResponse = VerdictSubmissionResponse;
export type SessionListResponse = CursorPaginatedSessions;

export interface ProvenanceItemSchema {
  component: string;
  rule_id: string;
  penalty: number;
  evidence: string;
  nist_reference: string;
}

export interface VetoFindingSchema {
  rule_id: string;
  floor_score: number;
  evidence: string;
  nist_reference: string;
}

export interface RiskResultSchema {
  score: number;
  band: string;
  context_multiplier: number;
  component_scores: Record<string, number>;
  component_weights: Record<string, number>;
  vetoes: VetoFindingSchema[];
  effective_security_bits: number;
  weight_redistributed: boolean;
  provenance: ProvenanceItemSchema[];
}

export interface FindingSchema {
  id: string;
  session_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  standards_ref: string;
  evidence: Record<string, unknown>;
}

export interface CertificateSchema {
  fingerprint_sha256: string;
  spki_sha256: string;
  subject_dn: string;
  issuer_dn: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  lifetime_days: number;
  public_key_algorithm: string;
  public_key_bits: number;
  signature_algorithm: string;
  is_self_signed: boolean;
  san_dns: string[];
  sct_count: number;
  anchor_source?: "mozilla_nss" | "enterprise" | "unknown";
  findings?: FindingSchema[];
}

export interface MLAnomalyResultSchema {
  is_anomaly: boolean;
  anomaly_score: number;
  anomaly_percentile: number;
  is_experimental?: boolean;
  top_feature_explanations: Array<{
    feature: string;
    contribution: number;
    value?: number | string;
  }>;
}

export interface TemporalBehaviorSchema {
  classification: "NORMAL" | "SUSPICIOUS_TIMING" | "BEACON_CANDIDATE" | "INSUFFICIENT_DATA" | string;
  behavior_score: number;
  mean_interval?: number | null;
  std_interval?: number | null;
  cv?: number | null;
  jitter_pct?: number | null;
  duration?: number;
  event_count?: number;
  explanation?: string[];
  analyst_note?: string;
}

export interface FSMTransitionSchema {
  state: string;
  title: string;
  offset: number;
  hex: string;
}

export interface SessionDetailSchema extends SessionSummarySchema {
  c2s_bytes?: number;
  s2c_bytes?: number;
  ja3s?: string | null;
  server_banner?: string | null;
  ehlo_domain?: string | null;
  risk_breakdown?: RiskResultSchema;
  ml_result?: MLAnomalyResultSchema;
  temporal_behavior?: TemporalBehaviorSchema;
  temporal_classification?: string;
  certificates?: CertificateSchema[];
  findings?: FindingSchema[];
  fsm_transitions?: FSMTransitionSchema[];
  tls_version?: string;
  cipher_name?: string;
  raw_tls_params?: Record<string, unknown>;
  partial_analysis?: boolean;
  buffer_truncated?: boolean;
  reassembly_gap?: boolean;
}

export interface AnalysisDetailResponse {
  schema_version: string;
  analysis_id: string;
  created_at: string;
  pcap_filename: string;
  pcap_sha256: string;
  status: string;
  total_packets: number;
  total_sessions: number;
  overall_risk_score: number;
  overall_risk_band: string;
  summary_data: Record<string, unknown>;
  sessions: SessionDetailSchema[];
  findings: FindingSchema[];
}

const API_BASE = "";

// -----------------------------------------------------------------------------
// Live API Methods
// -----------------------------------------------------------------------------
export async function uploadPcapFile(
  file: File,
  token?: string
): Promise<PcapUploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}/api/v1/pcaps`, {
    method: "POST",
    headers,
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Upload failed with status ${res.status}`);
  }

  return res.json();
}

export async function requestPresignedUpload(
  filename: string,
  sizeBytes: number,
  token?: string
): Promise<PresignedUploadResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/api/v1/pcaps/presign`, {
    method: "POST",
    headers,
    body: JSON.stringify({ filename, size_bytes: sizeBytes }),
  });

  if (!res.ok) {
    throw new Error(`Presign request failed with HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchTaskStatus(
  taskId: string,
  token?: string
): Promise<TaskStatusResponse> {
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/api/v1/tasks/${taskId}`, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch task status: HTTP ${res.status}`);
  }
  return res.json();
}

export async function cancelTask(taskId: string, token?: string): Promise<void> {
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/api/v1/tasks/${taskId}`, {
    method: "DELETE",
    headers,
  });
  if (!res.ok) {
    throw new Error(`Failed to cancel task: HTTP ${res.status}`);
  }
}

export async function fetchAnalysis(
  analysisId: string,
  token?: string
): Promise<AnalysisDetailResponse> {
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/api/v1/analyses/${analysisId}`, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch analysis: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchAnalysisSessions(
  analysisId: string,
  params?: {
    protocol?: string;
    risk_band?: string;
    is_anomaly?: boolean;
    search?: string;
    limit?: number;
    cursor?: string;
  },
  token?: string
): Promise<SessionListResponse> {
  const query = new URLSearchParams();
  if (params?.protocol) query.set("protocol", params.protocol);
  // Backend uses 'band' not 'risk_band' for the query parameter
  if (params?.risk_band) query.set("band", params.risk_band);
  if (params?.is_anomaly !== undefined) query.set("is_anomaly", String(params.is_anomaly));
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.cursor) query.set("cursor", params.cursor);

  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/api/v1/analyses/${analysisId}/sessions?${query.toString()}`, {
    headers,
  });
  if (!res.ok) {
    throw new Error(`Failed to query sessions: HTTP ${res.status}`);
  }
  return res.json();
}

export async function submitAnalystVerdict(
  verdict: AnalystVerdictCreate,
  token?: string
): Promise<AnalystVerdictResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  // Map frontend verdict labels to backend-accepted enum values
  const verdictMapping: Record<string, string> = {
    TRUE_POSITIVE: "MALICIOUS",
    FALSE_POSITIVE: "BENIGN",
    BENIGN_KNOWN: "BENIGN",
    SUSPICIOUS: "SUSPICIOUS",
    MALICIOUS: "MALICIOUS",
    BENIGN: "BENIGN",
    POLICY_VIOLATION: "POLICY_VIOLATION",
  };

  const backendVerdict = verdictMapping[verdict.verdict] || "SUSPICIOUS";
  const sessionId = verdict.session_id;

  if (!sessionId) {
    throw new Error("session_id is required to submit a verdict");
  }

  // Backend route: POST /api/v1/sessions/{session_id}/verdict
  const res = await fetch(`${API_BASE}/api/v1/sessions/${sessionId}/verdict`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      verdict: backendVerdict,
      confidence: verdict.confidence ?? 1.0,
      notes: verdict.analyst_notes || verdict.notes || "",
      tags: verdict.tags ?? [],
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to submit verdict: HTTP ${res.status}`);
  }
  return res.json();
}

// -----------------------------------------------------------------------------
// Realistic 1000-Session Mock Corpus Generator (for instant local triage)
// -----------------------------------------------------------------------------
export function generateMockAnalysis(analysisId: string = "analysis-1000-fixtures"): AnalysisDetailResponse {
  const protocols = ["SMTP", "IMAP", "POP3"];
  const ciphers = [
    { name: "TLS_AES_128_GCM_SHA256", kex: "ECDHE", bits: 128, score: 0, band: "SECURE", tls: "TLS 1.3" },
    { name: "TLS_AES_256_GCM_SHA384", kex: "ECDHE", bits: 256, score: 0, band: "SECURE", tls: "TLS 1.3" },
    { name: "TLS_CHACHA20_POLY1305_SHA256", kex: "ECDHE", bits: 256, score: 0, band: "SECURE", tls: "TLS 1.3" },
    { name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", kex: "ECDHE", bits: 128, score: 15, band: "SECURE", tls: "TLS 1.2" },
    { name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", kex: "ECDHE", bits: 256, score: 15, band: "SECURE", tls: "TLS 1.2" },
    { name: "TLS_RSA_WITH_AES_128_CBC_SHA", kex: "RSA", bits: 128, score: 65, band: "HIGH", tls: "TLS 1.2" },
    { name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kex: "RSA", bits: 112, score: 85, band: "CRITICAL", tls: "TLS 1.0" },
    { name: "TLS_RSA_WITH_RC4_128_MD5", kex: "RSA", bits: 128, score: 100, band: "CRITICAL", tls: "SSL 3.0" },
  ];

  const mxServers = [
    { ip: "10.0.1.25", name: "mx1.enterprise.corp" },
    { ip: "10.0.1.26", name: "mx2.enterprise.corp" },
    { ip: "198.51.100.10", name: "mail.partner-vendor.com" },
    { ip: "203.0.113.5", name: "relay.legacy-telecom.net" },
    { ip: "192.0.2.77", name: "smtp.compromised-node.org" },
  ];

  const sessions: SessionDetailSchema[] = [];
  const findings: FindingSchema[] = [];

  const baseTs = 1727260000.0;

  for (let i = 0; i < 1000; i++) {
    const proto = protocols[i % protocols.length];
    const server = mxServers[i % mxServers.length];
    const clientIp = `192.168.${Math.floor(i / 250) + 10}.${(i % 250) + 1}`;
    const clientPort = 40000 + (i % 20000);
    const serverPort = proto === "SMTP" ? (i % 3 === 0 ? 465 : 25) : proto === "IMAP" ? (i % 2 === 0 ? 993 : 143) : 995;
    const mode = [465, 993, 995].includes(serverPort) ? "IMPLICIT" : "EXPLICIT";
    
    // Select cipher with intentional distribution
    let cIndex = 0;
    if (i % 10 === 0) cIndex = 7; // RC4 CRITICAL
    else if (i % 7 === 0) cIndex = 6; // 3DES CRITICAL
    else if (i % 5 === 0) cIndex = 5; // RSA static HIGH
    else if (i % 3 === 0) cIndex = 3; // TLS 1.2 SECURE
    else cIndex = i % 3; // TLS 1.3 SECURE

    const cipher = ciphers[cIndex];
    let riskScore = cipher.score;
    let riskBand = cipher.band;
    const isAnomaly = i % 17 === 0 || riskBand === "CRITICAL";

    // STARTTLS state
    let starttlsState = mode === "IMPLICIT" ? "S4_ENCRYPTED" : "S4_ENCRYPTED";
    if (mode === "EXPLICIT") {
      if (i % 23 === 0) {
        starttlsState = "S_STRIP_DETECTED";
        riskScore = 95;
        riskBand = "CRITICAL";
      } else if (i % 19 === 0) {
        starttlsState = "S_REFUSED";
        riskScore = 80;
        riskBand = "HIGH";
      } else if (i % 13 === 0) {
        starttlsState = "S_PLAINTEXT";
        riskScore = 75;
        riskBand = "HIGH";
      }
    }

    const sessionId = `sess-${String(i + 1).padStart(4, "0")}`;
    const ts = baseTs + i * 28.5 + (Math.random() * 5);

    // Create findings for high risk
    if (riskScore >= 60) {
      const findingId = `find-${findings.length + 1}`;
      let ruleId = "CIPHER-OBSOLETE";
      let title = "Obsolete Cryptographic Suite";
      let severity = riskScore >= 80 ? "CRITICAL" : "HIGH";

      if (starttlsState === "S_STRIP_DETECTED") {
        ruleId = "VETO-STARTTLS-STRIP";
        title = "Active STARTTLS Stripping Attack Observed";
        severity = "CRITICAL";
      } else if (cipher.tls === "SSL 3.0" || cipher.name.includes("RC4")) {
        ruleId = "VETO-INSECURE-PRIMITIVE";
        title = "Insecure Primitive (RC4 / SSL 3.0 Veto)";
        severity = "CRITICAL";
      } else if (cipher.kex === "RSA") {
        ruleId = "KEX-STATIC-RSA";
        title = "Static RSA Key Transport (No Forward Secrecy)";
        severity = "HIGH";
      }

      findings.push({
        id: findingId,
        session_id: sessionId,
        rule_id: ruleId,
        title,
        description: `Observed ${cipher.name} on ${proto} port ${serverPort}. Violates NIST SP 800-52r2.`,
        severity,
        standards_ref: "NIST SP 800-52r2 §3.3.1",
        evidence: { cipher: cipher.name, port: serverPort, state: starttlsState },
      });
    }

    sessions.push({
      id: sessionId,
      analysis_id: analysisId,
      client_ip: clientIp,
      client_port: clientPort,
      server_ip: server.ip,
      server_port: serverPort,
      protocol: proto,
      mode,
      starttls_state: starttlsState,
      risk_score: riskScore,
      risk_band: riskBand,
      ja3: cipher.tls === "TLS 1.3" ? "771,4865-4866-4867,0-23-65281-10-11-35-16,29-23-24,0" : "771,49195-49199-52393,0-10-11-13-16,29-23,0",
      ja4: cipher.tls === "TLS 1.3" ? "t13d1516h2_8daaf6152771_000000000000" : "t12d080500_c02f_000000000000",
      sni: server.name,
      first_seen: ts,
      duration_sec: +(1.2 + Math.random() * 3.5).toFixed(2),
      is_anomaly: isAnomaly,
      c2s_bytes: 1024 + (i * 37) % 8192,
      s2c_bytes: 2048 + (i * 73) % 16384,
      risk_breakdown: {
        score: riskScore,
        band: riskBand,
        context_multiplier: serverPort === 465 || (serverPort as number) === 587 ? 1.15 : 1.0,
        component_scores: {
          protocol_version: cipher.tls === "TLS 1.3" ? 0 : cipher.tls === "TLS 1.2" ? 15 : 80,
          cipher_hash: cipher.score,
          key_exchange: cipher.kex === "RSA" ? 70 : 0,
          certificate: cipher.tls === "TLS 1.3" ? 0 : (i % 7 === 0 ? 75 : 0),
          session_hygiene: starttlsState === "S_STRIP_DETECTED" ? 95 : 0,
        },
        component_weights: {
          protocol_version: 0.25,
          cipher_hash: 0.25,
          key_exchange: 0.20,
          certificate: 0.20,
          session_hygiene: 0.10,
        },
        vetoes: riskScore >= 80 ? [
          {
            rule_id: starttlsState === "S_STRIP_DETECTED" ? "VETO-STRIP-DETECTED" : "VETO-INSECURE-CIPHER",
            floor_score: 85,
            evidence: starttlsState === "S_STRIP_DETECTED" ? "250-STARTTLS capability stripped from server greeting" : `Insecure cipher ${cipher.name}`,
            nist_reference: "NIST SP 800-52r2 §3.3.1",
          }
        ] : [],
        effective_security_bits: cipher.bits,
        weight_redistributed: cipher.tls === "TLS 1.3",
        provenance: [
          {
            component: "cipher_hash",
            rule_id: `CIPHER-${cipher.name.split("_")[1] || "SUITE"}`,
            penalty: cipher.score,
            evidence: `Negotiated cipher suite ${cipher.name}`,
            nist_reference: "NIST SP 800-52r2 §3.3.1",
          }
        ],
      },
      ml_result: isAnomaly ? {
        is_anomaly: true,
        anomaly_score: +(0.72 + Math.random() * 0.25).toFixed(3),
        anomaly_percentile: +(92.0 + Math.random() * 7.5).toFixed(1),
        top_feature_explanations: [
          { feature: "tls_version_ordinal", contribution: 0.38, value: cipher.tls === "SSL 3.0" ? 0 : 1 },
          { feature: "starttls_upgrade_latency_ms", contribution: 0.29, value: 480.2 },
          { feature: "c2s_s2c_byte_ratio", contribution: -0.18, value: 0.12 },
        ],
      } : undefined,
    });
  }

  // Generate Temporal Beacon candidates and enrich sessions
  const temporalGroups: Array<{
    src_ip: string;
    dst_ip: string;
    dst_port: number;
    protocol: string;
    event_count: number;
    mean_interval: number;
    jitter_pct: number;
    cv: number;
    duration: number;
    behavior_score: number;
    classification: string;
    explanation: string[];
    analyst_note: string;
  }> = [
    {
      src_ip: "10.0.1.15",
      dst_ip: "198.51.100.44",
      dst_port: 587,
      protocol: "TCP",
      event_count: 48,
      mean_interval: 30.1,
      jitter_pct: 2.8,
      cv: 0.028,
      duration: 1414.7,
      behavior_score: 90,
      classification: "BEACON_CANDIDATE",
      explanation: [
        "48 communication events observed (>= 5)",
        "Mean recurrence period: 30.10s",
        "Highly regular timing: Jitter is 2.80% (< 5%)",
        "Low timing variance: Coefficient of variation is 0.0280 (< 0.15)",
        "Observed communication persisted over 1414.7s (23.6 minutes)",
      ],
      analyst_note: "Regular automated communication pattern requiring investigation. Timing alone does not establish malicious activity.",
    },
    {
      src_ip: "10.0.1.42",
      dst_ip: "203.0.113.88",
      dst_port: 465,
      protocol: "TCP",
      event_count: 31,
      mean_interval: 60.8,
      jitter_pct: 8.2,
      cv: 0.082,
      duration: 1824.0,
      behavior_score: 90,
      classification: "BEACON_CANDIDATE",
      explanation: [
        "31 communication events observed (>= 5)",
        "Mean recurrence period: 60.80s",
        "Regular timing: Jitter is 8.20% (< 15%)",
        "Low timing variance: Coefficient of variation is 0.0820 (< 0.15)",
        "Observed communication persisted over 1824.0s (30.4 minutes)",
      ],
      analyst_note: "Automated polling pattern candidate. Requires correlation with endpoint authorization.",
    },
    {
      src_ip: "10.0.2.10",
      dst_ip: "192.0.2.15",
      dst_port: 25,
      protocol: "TCP",
      event_count: 7,
      mean_interval: 13.4,
      jitter_pct: 41.0,
      cv: 0.41,
      duration: 80.4,
      behavior_score: 20,
      classification: "NORMAL",
      explanation: [
        "7 communication events observed (>= 5)",
        "Irregular timing: Jitter is 41.00% (>= 15%)",
        "High timing variance: Coefficient of variation is 0.4100 (>= 0.15)",
      ],
      analyst_note: "Normal or irregular human/burst timing with no evidence of automated beaconing.",
    },
  ];

  // Stamp temporal behaviors onto matching sessions
  sessions.forEach((s, idx) => {
    if (idx % 11 === 0) {
      s.temporal_classification = "BEACON_CANDIDATE";
      s.temporal_behavior = {
        classification: "BEACON_CANDIDATE",
        behavior_score: 90,
        mean_interval: 30.1,
        std_interval: 0.84,
        cv: 0.028,
        jitter_pct: 2.8,
        duration: 1414.7,
        event_count: 48,
        explanation: [
          "48 communication events observed",
          "Mean interval: 30.1s",
          "Jitter: 2.8%",
          "Coefficient of variation: 0.028",
          "Communication persisted for 23.6 minutes",
          "Pattern is highly regular",
        ],
        analyst_note: "Regular automated communication pattern requiring investigation. Timing alone does not establish malicious activity.",
      };
    } else if (idx % 7 === 0) {
      s.temporal_classification = "SUSPICIOUS_TIMING";
      s.temporal_behavior = {
        classification: "SUSPICIOUS_TIMING",
        behavior_score: 50,
        mean_interval: 45.2,
        std_interval: 8.1,
        cv: 0.18,
        jitter_pct: 18.0,
        duration: 450.0,
        event_count: 10,
        explanation: ["10 events observed", "Moderate timing regularity with jitter 18%"],
        analyst_note: "Moderate timing regularity observed, but insufficient to confirm beacon candidate.",
      };
    } else {
      s.temporal_classification = "NORMAL";
    }
  });

  // Add temporal findings
  findings.push({
    id: `find-temporal-beacon-1`,
    session_id: sessions[0]?.id || "sess-0001",
    rule_id: "TEMPORAL_BEACON_CANDIDATE",
    title: "Automated Timing Beacon Candidate (Behavioral)",
    description: "Repeated communication pattern between 10.0.1.15 and 198.51.100.44:587 shows high timing regularity (mean interval=30.1s, jitter=2.8%, score=90/100 across 48 events). Requires investigation; timing alone does not establish malicious activity.",
    severity: "MEDIUM",
    standards_ref: "MITRE ATT&CK T1071 (Automated Timing)",
    evidence: { ...temporalGroups[0] },
  });

  const scores = sessions.map((s) => s.risk_score);
  const overallScore = Math.max(...scores);
  const overallBand = overallScore >= 80 ? "CRITICAL" : overallScore >= 60 ? "HIGH" : overallScore >= 40 ? "WEAK" : "SECURE";

  return {
    schema_version: "1.0.0",
    analysis_id: analysisId,
    created_at: new Date().toISOString(),
    pcap_filename: "enterprise_perimeter_core_mail_1000.pcap",
    pcap_sha256: "9a2f7c8b4e1d3a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f",
    status: "COMPLETED",
    total_packets: 489230,
    total_sessions: sessions.length,
    overall_risk_score: overallScore,
    overall_risk_band: overallBand,
    summary_data: {
      session_count: sessions.length,
      findings_count: findings.length,
      temporal_summary: {
        analyzed_groups: 183,
        beacon_candidates: 2,
        suspicious_timing: 5,
        insufficient_data: 31,
        normal: 145,
      },
      temporal_groups: temporalGroups,
    },
    sessions,
    findings,
  };
}
