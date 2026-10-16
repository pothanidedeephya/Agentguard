/**
 * AgentGuard - Main Application Container
 * Runtime Defence for MCP-Connected AI Tools
 */
import React, { useState } from 'react';
import { SecurityProvider, useSecurity } from './context/SecurityContext';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewPage } from './components/pages/OverviewPage';
import { LiveMonitorPage } from './components/pages/LiveMonitorPage';
import { ToolCallsPage } from './components/pages/ToolCallsPage';
import { ThreatDetectionPage } from './components/pages/ThreatDetectionPage';
import { PolicyEnginePage } from './components/pages/PolicyEnginePage';
import { MCPServersPage } from './components/pages/MCPServersPage';
import { ResponseInspectorPage } from './components/pages/ResponseInspectorPage';
import { ApprovalQueuePage } from './components/pages/ApprovalQueuePage';
import { AuditLogsPage } from './components/pages/AuditLogsPage';
import { AnalyticsPage } from './components/pages/AnalyticsPage';
import { SettingsPage } from './components/pages/SettingsPage';
import { ScenarioRunModal } from './components/modals/ScenarioRunModal';
import { ToolCallDetailModal } from './components/modals/ToolCallDetailModal';
import { ThreatDetailModal } from './components/modals/ThreatDetailModal';

const DashboardContent: React.FC = () => {
  const {
    currentPage,
    selectedToolCall,
    setSelectedToolCall,
    selectedThreat,
    setSelectedThreat,
    lastScenarioRun,
  } = useSecurity();

  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isScenarioModalOpen, setIsScenarioModalOpen] = useState(false);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#070b14] text-slate-100 antialiased font-sans select-none">
      {/* Persistent Left Sidebar */}
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />

      {/* Main Workspace Column */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navigation Bar */}
        <Header
          onOpenMobileSidebar={() => setMobileOpen(true)}
          onOpenScenarioModal={() => setIsScenarioModalOpen(true)}
        />

        {/* Scrollable Main Content Area */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8 space-y-6">
          {/* Active Toast for recent scenario run */}
          {lastScenarioRun && (
            <div className="p-3 rounded-xl border border-cyan-500/40 bg-cyan-950/30 text-xs text-cyan-200 flex items-center justify-between gap-3 shadow-md animate-in fade-in slide-in-from-top-2 duration-200">
              <span className="font-mono">
                Scenario Executed: <strong>{lastScenarioRun.scenarioName}</strong> &rarr; Enforcement: <strong className="text-white">[{lastScenarioRun.decision}]</strong> at {lastScenarioRun.time}
              </span>
              <button
                onClick={() => setIsScenarioModalOpen(true)}
                className="underline hover:text-white text-[11px] shrink-0"
              >
                Run Another
              </button>
            </div>
          )}

          {/* Page Routing */}
          {currentPage === 'overview' && <OverviewPage />}
          {currentPage === 'live-monitor' && <LiveMonitorPage />}
          {currentPage === 'tool-calls' && <ToolCallsPage />}
          {currentPage === 'threats' && <ThreatDetectionPage />}
          {currentPage === 'policies' && <PolicyEnginePage />}
          {currentPage === 'mcp-servers' && <MCPServersPage />}
          {currentPage === 'response-inspector' && <ResponseInspectorPage />}
          {currentPage === 'approvals' && <ApprovalQueuePage />}
          {currentPage === 'audit-logs' && <AuditLogsPage />}
          {currentPage === 'analytics' && <AnalyticsPage />}
          {currentPage === 'settings' && <SettingsPage />}
        </main>
      </div>

      {/* Global Modals */}
      <ScenarioRunModal
        isOpen={isScenarioModalOpen}
        onClose={() => setIsScenarioModalOpen(false)}
      />

      <ToolCallDetailModal
        toolCall={selectedToolCall}
        onClose={() => setSelectedToolCall(null)}
      />

      <ThreatDetailModal
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
      />
    </div>
  );
};

export default function App() {
  return (
    <SecurityProvider>
      <DashboardContent />
    </SecurityProvider>
  );
}
