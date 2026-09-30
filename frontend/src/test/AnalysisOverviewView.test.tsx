import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { AnalysisOverviewView } from "../components/views/AnalysisOverviewView";
import { generateMockAnalysis } from "../api/client";

describe("AnalysisOverviewView Component", () => {
  const mockAnalysis = generateMockAnalysis("test-corpus-1000");

  it("renders corpus summary statistics cards", () => {
    render(
      <AnalysisOverviewView
        analysis={mockAnalysis}
        onFilterSessions={vi.fn()}
      />
    );

    expect(screen.getByText(/Total Sessions/i)).toBeInTheDocument();
    expect(screen.getByText(/Cryptographic Findings/i)).toBeInTheDocument();
    expect(screen.getByText(/Anomalous Flows/i)).toBeInTheDocument();
    expect(screen.getByText(/Risk Distribution \(Click to Filter\)/i)).toBeInTheDocument();
  });

  it("renders STARTTLS health MX table sorted worst upgrade rate first", () => {
    render(
      <AnalysisOverviewView
        analysis={mockAnalysis}
        onFilterSessions={vi.fn()}
      />
    );

    expect(screen.getByText(/STARTTLS Upgrade Health per Destination MX/i)).toBeInTheDocument();
    expect(screen.getByText(/Worst First/i)).toBeInTheDocument();
  });

  it("triggers filter callback when clicking risk distribution band", () => {
    const handleFilter = vi.fn();
    render(
      <AnalysisOverviewView
        analysis={mockAnalysis}
        onFilterSessions={handleFilter}
      />
    );

    const criticalTag = screen.getByTitle(/Filter table to CRITICAL/i);
    expect(criticalTag).toBeInTheDocument();

    fireEvent.click(criticalTag);
    expect(handleFilter).toHaveBeenCalledWith({ risk_band: "CRITICAL" });
  });
});
