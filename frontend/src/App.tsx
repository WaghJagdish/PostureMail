import { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { AppNav, AppPage } from "./components/layout/AppNav";
import { LandingPage } from "./components/views/LandingPage";
import { IngestionPage } from "./components/views/IngestionPage";
import { AnalysisOverviewView } from "./components/views/AnalysisOverviewView";
import { SessionTableView } from "./components/views/SessionTableView";
import { SessionDetailView } from "./components/views/SessionDetailView";
import { CorpusCorrelationsView } from "./components/views/CorpusCorrelationsView";
import { KeyboardShortcutsModal } from "./components/common/KeyboardShortcutsModal";
import {
  fetchAnalysis,
  generateMockAnalysis,
  AnalysisDetailResponse,
  SessionDetailSchema,
} from "./api/client";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, staleTime: 30000 } },
});

const DASHBOARD_PAGES: AppPage[] = ["overview", "sessions", "detail", "correlations"];

function AppShell() {
  const [currentPage, setCurrentPage] = useState<AppPage>("landing");
  const [currentAnalysisId, setCurrentAnalysisId] = useState("analysis-1000-fixtures");
  const [selectedSession, setSelectedSession] = useState<SessionDetailSchema | null>(null);
  const [isMockMode, setIsMockMode] = useState(true);
  const [isShortcutsOpen, setIsShortcutsOpen] = useState(false);
  const [triageTimer, setTriageTimer] = useState(0);
  const [tableFilterSearch, setTableFilterSearch] = useState("");
  const [tableFilterPreset, setTableFilterPreset] = useState("all");

  // Triage timer — only runs while in dashboard
  useEffect(() => {
    if (!DASHBOARD_PAGES.includes(currentPage)) return;
    const timer = setInterval(() => setTriageTimer((prev) => prev + 1), 1000);
    return () => clearInterval(timer);
  }, [currentPage]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === "1") setCurrentPage("ingestion");
      else if (e.key === "2") setCurrentPage("overview");
      else if (e.key === "3") setCurrentPage("sessions");
      else if (e.key === "4") setCurrentPage("detail");
      else if (e.key === "5") setCurrentPage("correlations");
      else if (e.key === "?") setIsShortcutsOpen((p) => !p);
      else if (e.key === "Escape") setIsShortcutsOpen(false);
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  // Fetch analysis data
  const { data: analysisData } = useQuery<AnalysisDetailResponse>({
    queryKey: ["analysis", currentAnalysisId, isMockMode],
    queryFn: async () => {
      if (isMockMode) return generateMockAnalysis(currentAnalysisId);
      return fetchAnalysis(currentAnalysisId);
    },
    initialData: isMockMode ? () => generateMockAnalysis(currentAnalysisId) : undefined,
  });

  // Auto-select first critical session
  useEffect(() => {
    if (analysisData && analysisData.sessions.length > 0 && !selectedSession) {
      const first =
        analysisData.sessions.find((s: SessionDetailSchema) => s.risk_band === "CRITICAL") ||
        analysisData.sessions[0];
      setSelectedSession(first);
    }
  }, [analysisData, selectedSession]);

  const handleAnalysisReady = (id: string) => {
    setIsMockMode(false);
    setCurrentAnalysisId(id);
    setSelectedSession(null);
    setCurrentPage("overview");
  };

  const handleLoadDemo = () => {
    setIsMockMode(true);
    setCurrentAnalysisId("analysis-1000-fixtures");
    setSelectedSession(null);
    setCurrentPage("overview");
  };

  const handleFilterFromChart = (filter: { risk_band?: string; protocol?: string; cipher?: string; search?: string }) => {
    setTableFilterPreset(filter.risk_band === "CRITICAL" ? "critical" : "all");
    if (filter.search) setTableFilterSearch(filter.search);
    else if (filter.risk_band && filter.risk_band !== "CRITICAL") setTableFilterSearch(filter.risk_band);
    setCurrentPage("sessions");
  };



  // Landing page — full-screen, no nav
  if (currentPage === "landing") {
    return (
      <LandingPage
        onEnterConsole={handleLoadDemo}
        onGoToIngestion={() => setCurrentPage("ingestion")}
      />
    );
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "#f5f6fa" }}>
      <AppNav
        currentPage={currentPage}
        onNavigate={setCurrentPage}
        analysisFilename={analysisData?.pcap_filename || currentAnalysisId}
        isMockMode={isMockMode}
        onOpenShortcuts={() => setIsShortcutsOpen(true)}
        triageTimerSeconds={triageTimer}
      />

      <main style={{ flex: 1 }}>
        {/* INGESTION */}
        {currentPage === "ingestion" && (
          <IngestionPage
            onAnalysisReady={handleAnalysisReady}
            onLoadDemo={handleLoadDemo}
          />
        )}

        {/* OVERVIEW DASHBOARD */}
        {currentPage === "overview" && analysisData && (
          <div style={{ padding: "24px 28px" }}>
            <AnalysisOverviewView
              analysis={analysisData}
              onFilterSessions={handleFilterFromChart}
            />
          </div>
        )}

        {/* SESSIONS TABLE */}
        {currentPage === "sessions" && analysisData && (
          <div style={{ padding: "24px 28px" }}>
            <SessionTableView
              sessions={analysisData.sessions}
              selectedSessionId={selectedSession?.id || null}
              onSelectSession={(s) => { setSelectedSession(s); setCurrentPage("detail"); }}
              onOpenVerdict={(sessionId) => {
                const target = analysisData?.sessions.find((s: SessionDetailSchema) => s.id === sessionId);
                if (target) { setSelectedSession(target); setCurrentPage("detail"); }
              }}
              activeFilterPreset={tableFilterPreset}
              externalSearch={tableFilterSearch}
            />
          </div>
        )}

        {/* SESSION DETAIL */}
        {currentPage === "detail" && (
          <div style={{ padding: "24px 28px" }}>
            <SessionDetailView
              session={selectedSession}
              onVerdictSaved={(sessionId, verdict) => console.log(`Verdict: ${sessionId} → ${verdict}`)}
            />
          </div>
        )}

        {/* CORRELATIONS */}
        {currentPage === "correlations" && analysisData && (
          <div style={{ padding: "24px 28px" }}>
            <CorpusCorrelationsView
              analysis={analysisData}
              onFilterSessions={handleFilterFromChart}
            />
          </div>
        )}
      </main>

      <KeyboardShortcutsModal
        isOpen={isShortcutsOpen}
        onClose={() => setIsShortcutsOpen(false)}
      />
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppShell />
    </QueryClientProvider>
  );
}
