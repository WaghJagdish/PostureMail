import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SessionDetailView } from "../components/views/SessionDetailView";
import { SessionDetailSchema } from "../api/client";

const mockSessionWithVeto: SessionDetailSchema = {
  id: "sess-0042",
  analysis_id: "test-analysis-uuid",
  client_ip: "192.168.1.100",
  client_port: 54321,
  server_ip: "10.0.1.25",
  server_port: 25,
  protocol: "SMTP",
  mode: "EXPLICIT",
  starttls_state: "S_STRIP_DETECTED",
  risk_score: 95,
  risk_band: "CRITICAL",
  ja3: "771,49195-49199-52393,0-10-11-13-16,29-23,0",
  ja4: "t12d080500_c02f_000000000000",
  sni: "mx1.enterprise.corp",
  first_seen: 1727260000.0,
  duration_sec: 2.45,
  is_anomaly: true,
  c2s_bytes: 2048,
  s2c_bytes: 4096,
  risk_breakdown: {
    score: 95,
    band: "CRITICAL",
    context_multiplier: 1.0,
    component_scores: {
      protocol_version: 15,
      cipher_hash: 15,
      key_exchange: 0,
      certificate: 0,
      session_hygiene: 95,
    },
    component_weights: {
      protocol_version: 0.25,
      cipher_hash: 0.25,
      key_exchange: 0.20,
      certificate: 0.20,
      session_hygiene: 0.10,
    },
    vetoes: [
      {
        rule_id: "VETO-STRIP-DETECTED",
        floor_score: 85,
        evidence: "250-STARTTLS capability stripped from server greeting",
        nist_reference: "NIST SP 800-52r2 §3.3.1",
      },
    ],
    effective_security_bits: 128,
    weight_redistributed: false,
    provenance: [
      {
        component: "session_hygiene",
        rule_id: "HYGIENE-STARTTLS-STRIP",
        penalty: 95,
        evidence: "Passive EHLO tamper detected: STARTTLS capability suppressed",
        nist_reference: "RFC 3207 §4 / NIST SP 800-52r2 §3.3.1",
      },
    ],
  },
  ml_result: {
    is_anomaly: true,
    anomaly_score: 0.88,
    anomaly_percentile: 98.5,
    top_feature_explanations: [
      { feature: "starttls_latency_ms", contribution: 0.42, value: 850.5 },
      { feature: "tls_version_ordinal", contribution: 0.31, value: 0 },
    ],
  },
  certificates: [],
  findings: [
    {
      id: "f-001",
      session_id: "sess-0042",
      rule_id: "VETO-STARTTLS-STRIP",
      title: "Active STARTTLS Stripping Attack Observed",
      description: "250-STARTTLS removed in transit.",
      severity: "CRITICAL",
      standards_ref: "NIST SP 800-52r2 §3.3.1",
      evidence: { state: "S_STRIP_DETECTED" },
    },
  ],
};

const mockTls13Session: SessionDetailSchema = {
  id: "sess-0100",
  analysis_id: "test-analysis-uuid",
  client_ip: "192.168.1.101",
  client_port: 54322,
  server_ip: "10.0.1.26",
  server_port: 465,
  protocol: "SMTP",
  mode: "IMPLICIT",
  starttls_state: "S4_ENCRYPTED",
  risk_score: 0,
  risk_band: "SECURE",
  ja3: "771,4865-4866-4867,0-23-65281-10-11-35-16,29-23-24,0",
  ja4: "t13d1516h2_8daaf6152771_000000000000",
  sni: "mx2.enterprise.corp",
  first_seen: 1727260500.0,
  duration_sec: 1.12,
  is_anomaly: false,
  c2s_bytes: 4096,
  s2c_bytes: 8192,
  risk_breakdown: {
    score: 0,
    band: "SECURE",
    context_multiplier: 1.15,
    component_scores: {
      protocol_version: 0,
      cipher_hash: 0,
      key_exchange: 0,
      certificate: 0,
      session_hygiene: 0,
    },
    component_weights: {
      protocol_version: 0.3125,
      cipher_hash: 0.3125,
      key_exchange: 0.25,
      certificate: 0.0,
      session_hygiene: 0.125,
    },
    vetoes: [],
    effective_security_bits: 256,
    weight_redistributed: true,
    provenance: [
      {
        component: "protocol_version",
        rule_id: "PROTO-TLS13",
        penalty: 0,
        evidence: "TLS 1.3 negotiated",
        nist_reference: "NIST SP 800-52r2 §3.1",
      },
    ],
  },
  certificates: [],
  findings: [],
};

describe("SessionDetailView Component", () => {
  it("renders STARTTLS FSM timeline with stripping attack node and stream offset", () => {
    render(<SessionDetailView session={mockSessionWithVeto} />);

    // Check FSM title & nodes
    expect(screen.getByText(/STARTTLS Finite State Machine Timeline/i)).toBeInTheDocument();
    expect(screen.getByText("S_STRIP_DETECTED")).toBeInTheDocument();
    expect(screen.getByText(/STRIPPING ATTACK DETECTED/i)).toBeInTheDocument();

    // Verify stream offset display
    expect(screen.getByText(/\+0 bytes/i)).toBeInTheDocument();

    // Click on STRIP DETECTED node to inspect evidence hex
    const stripNode = screen.getByText("S_STRIP_DETECTED");
    fireEvent.click(stripNode);

    expect(screen.getByText(/Stream Offset:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Passive EHLO tamper detected/i).length).toBeGreaterThanOrEqual(1);
  });

  it("renders NIST SP 800-57 risk score breakdown with veto floor and provenance list", () => {
    render(<SessionDetailView session={mockSessionWithVeto} />);

    // Score title and band
    expect(screen.getByText(/NIST SP 800-57 Risk Score Breakdown/i)).toBeInTheDocument();
    expect(screen.getByText(/Categorical Policy Veto Floor Triggered/i)).toBeInTheDocument();
    expect(screen.getByText(/VETO-STRIP-DETECTED/i)).toBeInTheDocument();
    expect(screen.getByText(/Floor: 85/i)).toBeInTheDocument();

    // Provenance line
    expect(screen.getByText(/HYGIENE-STARTTLS-STRIP/i)).toBeInTheDocument();
    expect(screen.getByText(/RFC 3207 §4 \/ NIST SP 800-52r2 §3.3.1/i)).toBeInTheDocument();
  });

  it("displays prominent TLS 1.3 encrypted certificate reality check banner", () => {
    render(<SessionDetailView session={mockTls13Session} />);

    expect(screen.getByText(/TLS 1.3 Active:/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Server certificate is encrypted inside/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/proportionally redistributed/i)).toBeInTheDocument();
  });

  it("handles copy evidence block action cleanly", async () => {
    render(<SessionDetailView session={mockSessionWithVeto} />);

    const copyBtn = screen.getByText(/Copy Evidence Block/i);
    expect(copyBtn).toBeInTheDocument();

    fireEvent.click(copyBtn);
    expect(screen.getByText(/Copied!/i)).toBeInTheDocument();
  });
});
