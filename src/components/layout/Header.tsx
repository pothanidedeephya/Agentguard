import React, { useState } from 'react';
import {
  Menu,
  Search,
  Bell,
  Play,
  RotateCcw,
  Wifi,
  WifiOff,
  User,
  ShieldAlert,
  Sliders,
  CheckCircle2,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { NavigationPage } from '../../types/agentguard';

interface HeaderProps {
  onOpenMobileSidebar: () => void;
  onOpenScenarioModal: () => void;
}

const PAGE_METADATA: Record<NavigationPage, { title: string; category: string }> = {
  overview: { title: 'Security Overview', category: 'Operations' },
  'tool-calls': { title: 'Tool Requests Monitor', category: 'Interception' },
  threats: { title: 'Threat Detection', category: 'Defence' },
  analytics: { title: 'Risk Analysis & Forensics', category: 'Intelligence' },
  approvals: { title: 'Approval Queue (HITL)', category: 'Authorisation' },
  'audit-logs': { title: 'Audit Trail', category: 'Compliance' },
  policies: { title: 'Security Policies', category: 'Governance' },
  'mcp-servers': { title: 'MCP Connections', category: 'Infrastructure' },
  'live-monitor': { title: 'System Health & Stream', category: 'Telemetry' },
  'response-inspector': { title: 'Data Loss Prevention (DLP)', category: 'Data Safety' },
  settings: { title: 'Gateway & Engine Settings', category: 'Configuration' },
};

export const Header: React.FC<HeaderProps> = ({
  onOpenMobileSidebar,
  onOpenScenarioModal,
}) => {
  const {
    currentPage,
    setCurrentPage,
    operatingState,
    isBackendConnected,
    isDemoMode,
    setIsDemoMode,
    checkBackendConnection,
    isCheckingConnection,
    dbState,
    dbHost,
    threats,
    setSelectedThreat,
  } = useSecurity();

  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const activeThreats = threats.filter((t) => t.status === 'ACTIVE');
  const currentMeta = PAGE_METADATA[currentPage] || { title: 'Dashboard', category: 'AgentGuard' };

  // Only display Connected if backend health check is positive and database is connected
  const isHealthyConnected = operatingState === 'LIVE' && isBackendConnected && dbState === 'CONNECTED';

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    const q = searchQuery.toLowerCase();
    if (q.includes('threat') || q.includes('alert')) setCurrentPage('threats');
    else if (q.includes('tool') || q.includes('call') || q.includes('request')) setCurrentPage('tool-calls');
    else if (q.includes('policy') || q.includes('rule')) setCurrentPage('policies');
    else if (q.includes('mcp') || q.includes('server') || q.includes('connect')) setCurrentPage('mcp-servers');
    else if (q.includes('inspect') || q.includes('dlp')) setCurrentPage('response-inspector');
    else if (q.includes('approve') || q.includes('queue')) setCurrentPage('approvals');
    else if (q.includes('audit') || q.includes('log')) setCurrentPage('audit-logs');
    else if (q.includes('risk') || q.includes('analytic')) setCurrentPage('analytics');
    else if (q.includes('health') || q.includes('live')) setCurrentPage('live-monitor');
    else if (q.includes('setting')) setCurrentPage('settings');
    else setCurrentPage('tool-calls');
  };

  return (
    <header className="h-14 px-4 md:px-6 bg-[#080d17] border-b border-slate-800/90 flex items-center justify-between gap-4 sticky top-0 z-30 select-none">
      {/* Left: Mobile Nav Toggle & Breadcrumbs */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onOpenMobileSidebar}
          className="md:hidden p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
          aria-label="Open navigation menu"
        >
          <Menu size={18} />
        </button>

        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400">
            <span>AgentGuard</span>
            <span>/</span>
            <span>{currentMeta.category}</span>
          </div>
          <h1 className="text-xs md:text-sm font-semibold text-slate-100 tracking-tight truncate">
            {currentMeta.title}
          </h1>
        </div>
      </div>

      {/* Center: Search Filter */}
      <form
        onSubmit={handleSearchSubmit}
        className="hidden md:flex items-center relative w-64 lg:w-80"
      >
        <Search
          size={13}
          className="absolute left-3 text-slate-400 pointer-events-none"
        />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search requests, threats, policies... (Enter)"
          className="w-full pl-8 pr-12 py-1 bg-[#0b121e] border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500/70 font-mono transition-all"
        />
        <span className="absolute right-2 px-1 py-0.5 rounded bg-slate-800/80 text-[10px] font-mono text-slate-400 pointer-events-none border border-slate-700/60">
          ⌘K
        </span>
      </form>

      {/* Right Controls */}
      <div className="flex items-center gap-2 md:gap-3 shrink-0">
        {/* Environment Indicator: Real Verification Only */}
        <div className="flex items-center">
          {isHealthyConnected ? (
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0b1716] border border-emerald-500/30 text-emerald-300 text-xs font-mono"
              title={`PostgreSQL database connection verified at ${dbHost || 'Supabase'}`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span className="font-semibold text-[11px]">Connected</span>
              <span className="hidden sm:inline text-slate-400 text-[10px]">·</span>
              <span className="hidden sm:inline text-[10px] text-emerald-200">Supabase</span>
            </div>
          ) : isDemoMode ? (
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0c1626] border border-cyan-500/30 text-cyan-300 text-xs font-mono"
              title="Running in Local / Demo Mode with synthetic simulation data."
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              <span className="font-semibold text-[11px]">Local / Demo</span>
            </div>
          ) : (
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1c1212] border border-rose-500/30 text-rose-300 text-xs font-mono"
              title="Backend daemon or database unreachable. Click refresh to test connection."
            >
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
              <span className="font-semibold text-[11px]">Disconnected</span>
              <button
                onClick={() => checkBackendConnection()}
                disabled={isCheckingConnection}
                className="ml-1 p-0.5 hover:text-white transition-colors"
                title="Retry connection check"
              >
                <RotateCcw
                  size={11}
                  className={isCheckingConnection ? 'animate-spin' : ''}
                />
              </button>
            </div>
          )}
        </div>

        {/* Attack Scenario Runner */}
        <button
          onClick={onOpenScenarioModal}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-medium transition-colors"
          title="Run deterministic MCP threat scenario"
        >
          <Play size={11} className="text-cyan-400" />
          <span className="hidden sm:inline text-[11px]">Run Scenario</span>
        </button>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowProfile(false);
            }}
            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors relative"
            aria-label="Security notifications"
          >
            <Bell size={16} />
            {activeThreats.length > 0 && (
              <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-rose-500" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 md:w-96 rounded-lg border border-slate-800 bg-[#0d1424] shadow-xl z-50 overflow-hidden text-xs">
              <div className="px-3.5 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                <span className="font-semibold text-slate-200 flex items-center gap-2">
                  <ShieldAlert size={14} className="text-rose-400" />
                  Active Security Alerts ({activeThreats.length})
                </span>
                <button
                  onClick={() => {
                    setShowNotifications(false);
                    setCurrentPage('threats');
                  }}
                  className="text-cyan-400 hover:underline text-[11px]"
                >
                  View all
                </button>
              </div>
              <div className="max-h-72 overflow-y-auto divide-y divide-slate-800/80">
                {activeThreats.length === 0 ? (
                  <div className="p-4 text-center text-slate-400 text-xs">
                    No active threat alerts detected.
                  </div>
                ) : (
                  activeThreats.map((t) => (
                    <div
                      key={t.id}
                      onClick={() => {
                        setSelectedThreat(t);
                        setShowNotifications(false);
                        setCurrentPage('threats');
                      }}
                      className="p-3 hover:bg-slate-800/50 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center justify-between font-mono text-[10px] text-slate-400">
                        <span className="text-rose-400 font-semibold">{t.category}</span>
                        <span>{new Date(t.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="font-medium text-slate-200 mt-1 line-clamp-1">
                        {t.title}
                      </p>
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1 font-mono">
                        Source: {t.sourceTool} ({t.agentName})
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Analyst Identity & Clearance */}
        <div className="relative">
          <button
            onClick={() => {
              setShowProfile(!showProfile);
              setShowNotifications(false);
            }}
            className="flex items-center gap-2 p-1 rounded hover:bg-slate-800 transition-colors"
            aria-label="Security profile menu"
          >
            <div className="w-6 h-6 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 text-xs">
              <User size={13} />
            </div>
          </button>

          {showProfile && (
            <div className="absolute right-0 mt-2 w-64 rounded-lg border border-slate-800 bg-[#0d1424] shadow-xl z-50 overflow-hidden text-xs">
              <div className="p-3.5 border-b border-slate-800 bg-slate-900/60">
                <p className="font-semibold text-slate-100">SOC Security Engineer</p>
                <p className="text-[11px] font-mono text-cyan-400 mt-0.5">
                  analyst-l2@agentguard.internal
                </p>
                <div className="mt-1.5 flex items-center gap-1.5 text-[10px] text-slate-400 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span>Enforcement Role: Admin</span>
                </div>
              </div>
              <div className="p-1.5 space-y-0.5">
                <button
                  onClick={() => {
                    setCurrentPage('settings');
                    setShowProfile(false);
                  }}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-slate-300 hover:bg-slate-800 text-left transition-colors"
                >
                  <Sliders size={13} className="text-slate-400" />
                  <span>Gateway Settings</span>
                </button>
                <button
                  onClick={() => {
                    setIsDemoMode(!isDemoMode);
                    setShowProfile(false);
                  }}
                  className="w-full flex items-center justify-between px-2.5 py-1.5 rounded text-slate-300 hover:bg-slate-800 text-left transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <RotateCcw size={13} className="text-slate-400" />
                    <span>Mode: {isDemoMode ? 'Demo' : 'Production'}</span>
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400">Toggle</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
