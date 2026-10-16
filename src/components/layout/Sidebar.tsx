import React from 'react';
import { Shield, ChevronLeft, ChevronRight } from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { NavigationPage } from '../../types/agentguard';

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (c: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (o: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  setCollapsed,
  mobileOpen,
  setMobileOpen,
}) => {
  const {
    currentPage,
    setCurrentPage,
    approvals,
    threats,
    operatingState,
    dbHost,
    dbState,
    isBackendConnected,
    isDemoMode,
  } = useSecurity();

  const pendingApprovalsCount = approvals.filter((a) => a.status === 'PENDING').length;
  const activeThreatsCount = threats.filter((t) => t.status === 'ACTIVE').length;

  const navItems: {
    id: NavigationPage;
    label: string;
    shortCode: string;
    badge?: number;
    badgeType?: 'danger' | 'warning' | 'info';
  }[] = [
    { id: 'overview', label: 'Overview', shortCode: 'OV' },
    { id: 'tool-calls', label: 'Tool Requests', shortCode: 'TR' },
    {
      id: 'threats',
      label: 'Threat Detection',
      shortCode: 'TD',
      badge: activeThreatsCount,
      badgeType: 'danger',
    },
    { id: 'analytics', label: 'Risk Analysis', shortCode: 'RA' },
    {
      id: 'approvals',
      label: 'Approval Queue',
      shortCode: 'AQ',
      badge: pendingApprovalsCount,
      badgeType: 'warning',
    },
    { id: 'audit-logs', label: 'Audit Logs', shortCode: 'AL' },
    { id: 'policies', label: 'Security Policies', shortCode: 'SP' },
    { id: 'mcp-servers', label: 'MCP Connections', shortCode: 'MC' },
    { id: 'live-monitor', label: 'System Health', shortCode: 'SH' },
    { id: 'response-inspector', label: 'Data Safety / DLP', shortCode: 'DS' },
    { id: 'settings', label: 'Settings', shortCode: 'ST' },
  ];

  const handleNavClick = (id: NavigationPage) => {
    setCurrentPage(id);
    setMobileOpen(false);
  };

  const isLiveConnected = operatingState === 'LIVE' && isBackendConnected && dbState === 'CONNECTED';

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/80 md:hidden backdrop-blur-xs"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed md:static inset-y-0 left-0 z-40 flex flex-col bg-[#080d17] border-r border-slate-800/90 transition-all duration-150 select-none ${
          collapsed ? 'w-16' : 'w-60'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}
      >
        {/* Brand Header: Crisp Wordmark */}
        <div className="h-14 flex items-center justify-between px-3.5 border-b border-slate-800/90 bg-[#060a12]">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className="w-7 h-7 rounded-md bg-slate-900 border border-slate-700/80 flex items-center justify-center shrink-0">
              <Shield size={15} className="text-cyan-400" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <span className="text-xs font-bold tracking-wider text-slate-100 font-mono block uppercase truncate">
                  AgentGuard
                </span>
                <span className="text-[10px] text-slate-400 font-mono block truncate">
                  MCP Runtime Defence
                </span>
              </div>
            )}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden md:flex p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </button>
        </div>

        {/* Section Title */}
        {!collapsed && (
          <div className="px-3.5 pt-3 pb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-400">
            SOC NAVIGATION
          </div>
        )}

        {/* Navigation List */}
        <nav className="flex-1 py-1 px-2 space-y-0.5 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = currentPage === item.id;

            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs transition-colors text-left relative border-l-2 ${
                  isActive
                    ? 'bg-[#121c2e] text-cyan-300 font-semibold border-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
                title={item.label}
              >
                {!collapsed ? (
                  <span className="truncate tracking-tight text-[12px]">{item.label}</span>
                ) : (
                  <span className="font-mono text-[11px] font-bold text-center w-full">{item.shortCode}</span>
                )}
                {!collapsed && item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`font-mono text-[10px] px-1.5 py-0.2 rounded border tabular-nums shrink-0 ml-2 ${
                      item.badgeType === 'danger'
                        ? 'bg-rose-950/60 text-rose-300 border-rose-500/40'
                        : item.badgeType === 'warning'
                        ? 'bg-amber-950/60 text-amber-300 border-amber-500/40'
                        : 'bg-slate-800 text-slate-300 border-slate-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
                {collapsed && item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`absolute top-2 right-2 w-1.5 h-1.5 rounded-full ${
                      item.badgeType === 'danger' ? 'bg-rose-400' : 'bg-amber-400'
                    }`}
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom Technical Status Block */}
        <div className="p-2.5 border-t border-slate-800/90 bg-[#060a12] text-xs">
          {!collapsed ? (
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Telemetry Feed
                </span>
                <span
                  className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                    isLiveConnected
                      ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                      : isDemoMode
                      ? 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300'
                      : 'border-amber-500/40 bg-amber-950/40 text-amber-300'
                  }`}
                >
                  {isLiveConnected ? 'CONNECTED' : isDemoMode ? 'DEMO' : 'OFFLINE'}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 font-mono truncate">
                {isLiveConnected
                  ? `PostgreSQL (${dbHost || 'Supabase'})`
                  : isDemoMode
                  ? 'Local Demo Mode (Synthetic)'
                  : 'Database Disconnected'}
              </div>
            </div>
          ) : (
            <div
              className="flex justify-center"
              title={isLiveConnected ? 'Connected (PostgreSQL)' : isDemoMode ? 'Demo Mode' : 'Disconnected'}
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  isLiveConnected
                    ? 'bg-emerald-400'
                    : isDemoMode
                    ? 'bg-cyan-400'
                    : 'bg-amber-400'
                }`}
              />
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
