import { useState, useEffect } from "react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { Header } from "./components/layout/Header";
import { Tabs, ViewTab } from "./components/layout/Tabs";
import { UploadQueueView } from "./components/views/UploadQueueView";
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
  FindingSchema,
} from "./api/client";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 30000,
    },
  },
});

function AnalystConsole() {
  const [activeTab, setActiveTab] = useState<ViewTab>("overview");
  const [currentAnalysisId, setCurrentAnalysisId] = useState("analysis-1000-fixtures");
  const [selectedSession, setSelectedSession] = useState<SessionDetailSchema | null>(null);
  const [isMockMode, setIsMockMode] = useState(true);
  const [isShortcutsOpen, setIsShortcutsOpen] = useState(false);
  const [triageTimer, setTriageTimer] = useState(0);

  // Table filter overrides from charts
  const [tableFilterSearch, setTableFilterSearch] = useState("");
  const [tableFilterPreset, setTableFilterPreset] = useState("all");

  // Triage timer ticker
  useEffect(() => {
    const timer = setInterval(() => {
      setTriageTimer((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Global Keyboard Shortcuts
  useEffect(() => {
    const handleGlobalKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      if (e.key === "1") setActiveTab("upload");
      else if (e.key === "2") setActiveTab("overview");
      else if (e.key === "3") setActiveTab("sessions");
      else if (e.key === "4") setActiveTab("detail");
      else if (e.key === "5") setActiveTab("correlations");
      else if (e.key === "?") setIsShortcutsOpen((prev) => !prev);
      else if (e.key === "Escape") {
        setIsShortcutsOpen(false);
      }
    };

    window.addEventListener("keydown", handleGlobalKey);
    return () => window.removeEventListener("keydown", handleGlobalKey);
  }, []);

  // Query Analysis Data
  const { data: analysisData } = useQuery<AnalysisDetailResponse>({
    queryKey: ["analysis", currentAnalysisId, isMockMode],
    queryFn: async () => {
      if (isMockMode) {
        return generateMockAnalysis(currentAnalysisId);
      }
      return fetchAnalysis(currentAnalysisId);
    },
    // Only seed with mock data when in mock mode; live mode fetches fresh from backend
    initialData: isMockMode ? () => generateMockAnalysis(currentAnalysisId) : undefined,
  });

  // Automatically select first critical session on initial load for instant inspection
  useEffect(() => {
    if (analysisData && analysisData.sessions.length > 0 && !selectedSession) {
      const firstCritical =
        analysisData.sessions.find((s: SessionDetailSchema) => s.risk_band === "CRITICAL") ||
        analysisData.sessions[0];
      setSelectedSession(firstCritical);
    }
  }, [analysisData, selectedSession]);

  const handleFilterFromChart = (filter: {
    risk_band?: string;
    protocol?: string;
    cipher?: string;
    search?: string;
  }) => {
    if (filter.risk_band === "CRITICAL") {
      setTableFilterPreset("critical");
    } else {
      setTableFilterPreset("all");
    }

    if (filter.search) {
      setTableFilterSearch(filter.search);
    } else if (filter.risk_band && filter.risk_band !== "CRITICAL") {
      setTableFilterSearch(filter.risk_band);
    }

    setActiveTab("sessions");
  };

  const handleSelectSessionFromTable = (s: SessionDetailSchema) => {
    setSelectedSession(s);
    setActiveTab("detail");
  };

  const handleOpenVerdictFromTable = (sessionId: string) => {
    const target = analysisData?.sessions.find((s: SessionDetailSchema) => s.id === sessionId);
    if (target) {
      setSelectedSession(target);
      setActiveTab("detail");
    }
  };

  const criticalCount =
    analysisData?.findings.filter((f: FindingSchema) => f.severity === "CRITICAL").length || 0;

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Header
        currentAnalysisId={analysisData?.pcap_filename || currentAnalysisId}
        onNewUpload={() => setActiveTab("upload")}
        onOpenShortcuts={() => setIsShortcutsOpen(true)}
        isMockMode={isMockMode}
        onToggleMockMode={() => setIsMockMode(!isMockMode)}
        activeTab={activeTab}
        triageTimerSeconds={triageTimer}
      />

      <Tabs
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        selectedSessionId={selectedSession?.id || null}
        totalSessionsCount={analysisData?.total_sessions || 0}
        criticalFindingsCount={criticalCount}
      />

      <main style={{ flex: 1 }}>
        {activeTab === "upload" && (
          <UploadQueueView
            onAnalysisReady={(id) => {
              setCurrentAnalysisId(id);
              setActiveTab("overview");
            }}
            isMockMode={isMockMode}
          />
        )}

        {activeTab === "overview" && analysisData && (
          <AnalysisOverviewView
            analysis={analysisData}
            onFilterSessions={handleFilterFromChart}
          />
        )}

        {activeTab === "sessions" && analysisData && (
          <SessionTableView
            sessions={analysisData.sessions}
            selectedSessionId={selectedSession?.id || null}
            onSelectSession={handleSelectSessionFromTable}
            onOpenVerdict={handleOpenVerdictFromTable}
            activeFilterPreset={tableFilterPreset}
            externalSearch={tableFilterSearch}
          />
        )}

        {activeTab === "detail" && (
          <SessionDetailView
            session={selectedSession}
            onVerdictSaved={(sessionId, verdict) => {
              console.log(`Verdict saved for ${sessionId}: ${verdict}`);
            }}
          />
        )}

        {activeTab === "correlations" && analysisData && (
          <CorpusCorrelationsView
            analysis={analysisData}
            onFilterSessions={handleFilterFromChart}
          />
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
      <AnalystConsole />
    </QueryClientProvider>
  );
}
