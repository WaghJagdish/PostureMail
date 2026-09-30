import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SessionTableView } from "../components/views/SessionTableView";
import { SessionDetailSchema } from "../api/client";

const mockSessions: SessionDetailSchema[] = [
  {
    id: "sess-0001",
    analysis_id: "test-analysis-uuid",
    client_ip: "192.168.1.10",
    client_port: 40001,
    server_ip: "10.0.1.25",
    server_port: 25,
    protocol: "SMTP",
    mode: "EXPLICIT",
    starttls_state: "S_STRIP_DETECTED",
    risk_score: 95,
    risk_band: "CRITICAL",
    ja3: "771,49195,0,29,0",
    ja4: "t12d080500_c02f_000000000000",
    sni: "mx1.enterprise.corp",
    first_seen: 1727260000.0,
    duration_sec: 2.1,
    is_anomaly: true,
    c2s_bytes: 1024,
    s2c_bytes: 2048,
  },
  {
    id: "sess-0002",
    analysis_id: "test-analysis-uuid",
    client_ip: "192.168.1.11",
    client_port: 40002,
    server_ip: "10.0.1.26",
    server_port: 465,
    protocol: "SMTP",
    mode: "IMPLICIT",
    starttls_state: "S4_ENCRYPTED",
    risk_score: 0,
    risk_band: "SECURE",
    ja3: "771,4865,0,29,0",
    ja4: "t13d1516h2_8daaf6152771_000000000000",
    sni: "mx2.enterprise.corp",
    first_seen: 1727260020.0,
    duration_sec: 1.5,
    is_anomaly: false,
    c2s_bytes: 2048,
    s2c_bytes: 4096,
  },
  {
    id: "sess-0003",
    analysis_id: "test-analysis-uuid",
    client_ip: "192.168.1.12",
    client_port: 40003,
    server_ip: "10.0.1.25",
    server_port: 143,
    protocol: "IMAP",
    mode: "EXPLICIT",
    starttls_state: "S_PLAINTEXT",
    risk_score: 75,
    risk_band: "HIGH",
    ja3: "771,49195,0,29,0",
    ja4: "t12d080500_c02f_000000000000",
    sni: "imap.enterprise.corp",
    first_seen: 1727260040.0,
    duration_sec: 3.2,
    is_anomaly: false,
    c2s_bytes: 512,
    s2c_bytes: 1024,
  },
];

describe("SessionTableView Component", () => {
  it("renders session rows with colored risk badges and WCAG text", () => {
    render(
      <SessionTableView
        sessions={mockSessions}
        onSelectSession={vi.fn()}
      />
    );

    expect(screen.getByText("sess-0001")).toBeInTheDocument();
    expect(screen.getByText("sess-0002")).toBeInTheDocument();
    expect(screen.getByText("sess-0003")).toBeInTheDocument();

    // Verify WCAG labels (never color alone)
    expect(screen.getByText(/95 • CRITICAL/i)).toBeInTheDocument();
    expect(screen.getByText(/0 • SECURE/i)).toBeInTheDocument();
    expect(screen.getByText(/75 • HIGH/i)).toBeInTheDocument();
  });

  it("filters sessions via preset buttons", () => {
    render(
      <SessionTableView
        sessions={mockSessions}
        onSelectSession={vi.fn()}
      />
    );

    // Click Critical Preset filter
    const criticalBtn = screen.getByText(/Critical Risk/i);
    fireEvent.click(criticalBtn);

    expect(screen.getByText("sess-0001")).toBeInTheDocument();
    expect(screen.queryByText("sess-0002")).not.toBeInTheDocument();
    expect(screen.queryByText("sess-0003")).not.toBeInTheDocument();
  });

  it("filters sessions via search text input", () => {
    render(
      <SessionTableView
        sessions={mockSessions}
        onSelectSession={vi.fn()}
      />
    );

    const searchInput = screen.getByPlaceholderText(/Filter sessions/i);
    fireEvent.change(searchInput, { target: { value: "IMAP" } });

    expect(screen.queryByText("sess-0001")).not.toBeInTheDocument();
    expect(screen.queryByText("sess-0002")).not.toBeInTheDocument();
    expect(screen.getByText("sess-0003")).toBeInTheDocument();
  });

  it("calls onSelectSession when a session row is clicked", () => {
    const handleSelect = vi.fn();
    render(
      <SessionTableView
        sessions={mockSessions}
        onSelectSession={handleSelect}
      />
    );

    const row = screen.getByText("sess-0001");
    fireEvent.click(row);

    expect(handleSelect).toHaveBeenCalledWith(mockSessions[0]);
  });
});
