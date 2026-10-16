import React, { useState } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import {
  Settings,
  Server,
  Wifi,
  WifiOff,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Lock,
  Eye,
  Sliders,
  Play,
  Database,
  ExternalLink,
  Code,
  FileCheck,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const {
    backendUrl,
    updateBackendUrl,
    checkBackendConnection,
    isBackendConnected,
    isCheckingConnection,
    isDemoMode,
    setIsDemoMode,
    operatingState,
    dbState,
    dbHost,
    dbError,
    triggerMigrations,
  } = useSecurity();

  const [urlInput, setUrlInput] = useState(backendUrl || '');
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [isMigrating, setIsMigrating] = useState(false);
  const [migrationStatus, setMigrationStatus] = useState<string | null>(null);

  // Configuration States
  const [sensitivity, setSensitivity] = useState<'STRICT' | 'BALANCED' | 'PERMISSIVE'>('STRICT');
  const [logLevel, setLogLevel] = useState('INFO');
  const [quarantineThreshold, setQuarantineThreshold] = useState(75);
  const [blockThreshold, setBlockThreshold] = useState(90);

  // DLP toggles
  const [dlpOpenAi, setDlpOpenAi] = useState(true);
  const [dlpAws, setDlpAws] = useState(true);
  const [dlpSsn, setDlpSsn] = useState(true);
  const [dlpEmail, setDlpEmail] = useState(true);
  const [dlpPromptInjection, setDlpPromptInjection] = useState(true);

  // Audit retention
  const [retentionDays, setRetentionDays] = useState(90);

  const handleSaveConnection = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveStatus('Connecting to AgentGuard backend...');
    const connected = await updateBackendUrl(urlInput);
    if (connected) {
      setSaveStatus('Connected successfully to live AgentGuard daemon.');
    } else {
      setSaveStatus('Could not reach backend daemon.');
    }
    setTimeout(() => setSaveStatus(null), 3500);
  };

  const handleRunMigrations = async () => {
    setIsMigrating(true);
    setMigrationStatus('Running schema migrations on PostgreSQL...');
    try {
      const res = await triggerMigrations();
      if (res.success) {
        setMigrationStatus(`Migrations applied successfully: ${res.message}`);
      } else {
        setMigrationStatus(`Migration notice: ${res.message}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Migration request failed';
      setMigrationStatus(`Error: ${msg}`);
    } finally {
      setIsMigrating(false);
      setTimeout(() => setMigrationStatus(null), 5000);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#090e18] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Settings size={16} className="text-cyan-400" />
            AgentGuard Gateway & Runtime Configuration
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure backend connection endpoints, PostgreSQL database, detection thresholds, and DLP rules
          </p>
        </div>

        <div className="flex items-center gap-2">
          {operatingState === 'LIVE' ? (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs font-mono">
              <Wifi size={12} className="text-emerald-400" />
              <span>LIVE (POSTGRESQL)</span>
            </span>
          ) : operatingState === 'DEMO' ? (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/40 border border-cyan-500/40 text-cyan-300 text-xs font-mono">
              <RotateCcw size={12} className="text-cyan-400" />
              <span>DEMO MODE (SYNTHETIC)</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/40 border border-amber-500/40 text-amber-300 text-xs font-mono">
              <WifiOff size={12} className="text-amber-400" />
              <span>DISCONNECTED</span>
            </span>
          )}
        </div>
      </div>

      {/* Section 1: PostgreSQL & Supabase Database Configuration */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#090e18] space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Database size={16} className="text-cyan-400" />
            <h3>PostgreSQL / Supabase Database Persistence</h3>
          </div>
          <span
            className={`text-xs font-mono px-2 py-0.5 rounded border ${
              dbState === 'CONNECTED'
                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300 font-bold'
                : dbState === 'NOT_CONFIGURED'
                ? 'border-slate-700 bg-slate-800 text-slate-300'
                : 'border-amber-500/40 bg-amber-950/40 text-amber-300'
            }`}
          >
            {dbState === 'CONNECTED' ? `CONNECTED (${dbHost || 'remote'})` : dbState}
          </span>
        </div>

        <div className="space-y-3 text-xs">
          <p className="text-slate-300 leading-relaxed">
            AgentGuard stores real intercepted tool calls, threat detections, policy matrices, and immutable audit logs in a persistent PostgreSQL database.
          </p>

          {dbState === 'CONNECTED' ? (
            <div className="p-3 rounded-lg border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 flex items-start gap-2.5">
              <CheckCircle2 size={16} className="text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-semibold block">PostgreSQL Database Connected & Verified</span>
                <p className="text-[11px] text-slate-300">
                  Host: <code className="text-emerald-300 font-mono">{dbHost}</code>. Tool calls, threat events, and audit logs are persisting to database tables.
                </p>
              </div>
            </div>
          ) : (
            <div className="p-3.5 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-300 space-y-2">
              <div className="flex items-start gap-2">
                <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold block">Database Connection Required for LIVE Mode</span>
                  <p className="text-[11px] text-slate-300 mt-0.5">
                    {dbError || 'DATABASE_URL is not set or Supabase instance is unreachable. Set DATABASE_URL in your server environment to enable live persistent records.'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Migration & Setup Controls */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-[#070c14] space-y-2.5 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                <FileCheck size={14} className="text-cyan-400" />
                Schema Migrations: <code>migrations/001_init_schema.sql</code>
              </span>
              <button
                onClick={handleRunMigrations}
                disabled={isMigrating || dbState !== 'CONNECTED'}
                className="px-3 py-1.5 rounded-lg bg-cyan-600/30 hover:bg-cyan-600/50 disabled:opacity-40 text-cyan-200 border border-cyan-500/40 text-xs font-semibold transition-colors flex items-center gap-1.5"
              >
                <RotateCcw size={12} className={isMigrating ? 'animate-spin' : ''} />
                <span>{isMigrating ? 'Applying...' : 'Apply Schema Migrations'}</span>
              </button>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Applies table DDL for <code>tool_calls</code>, <code>threats</code>, <code>security_policies</code>, <code>audit_logs</code>, and <code>mcp_servers</code>.
            </p>
            {migrationStatus && (
              <div className="p-2 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                {migrationStatus}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Section 2: Backend Daemon Connection & Operating Modes */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#090e18] space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 border-b border-slate-800 pb-3">
          <Server size={16} className="text-cyan-400" />
          <h3>AgentGuard Gateway Daemon Connection</h3>
        </div>

        <form onSubmit={handleSaveConnection} className="space-y-3">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Gateway API Base URL:
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Leave empty for same origin (/api)"
                className="flex-1 px-3 py-2 bg-[#070c14] border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 placeholder-slate-500 focus:outline-hidden focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={isCheckingConnection}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors flex items-center gap-1.5 shrink-0"
              >
                <RotateCcw size={13} className={isCheckingConnection ? 'animate-spin' : ''} />
                <span>Test & Save</span>
              </button>
            </div>
          </div>

          {saveStatus && (
            <div
              className={`p-3 rounded-lg text-xs font-mono flex items-center gap-2 border ${
                isBackendConnected
                  ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/40'
                  : 'bg-amber-950/40 text-amber-300 border-amber-500/40'
              }`}
            >
              {isBackendConnected ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
              <span>{saveStatus}</span>
            </div>
          )}
        </form>

        {/* Demo Mode Toggle */}
        <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-200 block">
              Explicit Demo Mode Switch
            </span>
            <span className="text-[11px] text-slate-400">
              Switch to synthetic sample telemetry without contaminating production PostgreSQL tables
            </span>
          </div>

          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={isDemoMode}
              onChange={(e) => setIsDemoMode(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500" />
          </label>
        </div>
      </div>

      {/* Section 3: Detection Sensitivity & Risk Thresholds */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#090e18] space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 border-b border-slate-800 pb-3">
          <Sliders size={16} className="text-cyan-400" />
          <h3>Threat Detection Sensitivity & Thresholds</h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Detection Profile:
            </label>
            <select
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value as any)}
              className="w-full px-3 py-2 bg-[#070c14] border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-hidden focus:border-cyan-500"
            >
              <option value="STRICT">STRICT (Zero-tolerance on relative paths and shell commands)</option>
              <option value="BALANCED">BALANCED (Standard SOC baseline)</option>
              <option value="PERMISSIVE">PERMISSIVE (Dev and local testing only)</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Gateway Logging Level:
            </label>
            <select
              value={logLevel}
              onChange={(e) => setLogLevel(e.target.value)}
              className="w-full px-3 py-2 bg-[#070c14] border border-slate-800 rounded-lg text-xs text-slate-100 font-mono focus:outline-hidden focus:border-cyan-500"
            >
              <option value="DEBUG">DEBUG (Full payload capture)</option>
              <option value="INFO">INFO (Production default)</option>
              <option value="WARN">WARN (Violations only)</option>
            </select>
          </div>
        </div>

        {/* Quarantine & Block Sliders */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 pt-2">
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300">Quarantine Threshold (HITL Approval):</span>
              <span className="font-mono text-amber-400 font-bold">&ge; {quarantineThreshold}</span>
            </div>
            <input
              type="range"
              min={50}
              max={89}
              value={quarantineThreshold}
              onChange={(e) => setQuarantineThreshold(Number(e.target.value))}
              className="w-full accent-amber-500 cursor-pointer"
            />
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300">Auto-Block Threshold:</span>
              <span className="font-mono text-rose-400 font-bold">&ge; {blockThreshold}</span>
            </div>
            <input
              type="range"
              min={70}
              max={100}
              value={blockThreshold}
              onChange={(e) => setBlockThreshold(Number(e.target.value))}
              className="w-full accent-rose-500 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* Section 4: DLP & Response Sanitization Rules */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#090e18] space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 border-b border-slate-800 pb-3">
          <Shield size={16} className="text-cyan-400" />
          <h3>Data Loss Prevention (DLP) Pattern Interceptors</h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-[#070c14] cursor-pointer">
            <div>
              <span className="text-slate-200 font-medium block">OpenAI & Anthropic Tokens</span>
              <span className="text-[11px] text-slate-400">Match <code>sk-proj-*</code> and developer tokens</span>
            </div>
            <input
              type="checkbox"
              checked={dlpOpenAi}
              onChange={(e) => setDlpOpenAi(e.target.checked)}
              className="w-4 h-4 accent-cyan-500"
            />
          </label>

          <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-[#070c14] cursor-pointer">
            <div>
              <span className="text-slate-200 font-medium block">AWS Access Key IDs</span>
              <span className="text-[11px] text-slate-400">Match <code>AKIA[0-9A-Z]&#123;16&#125;</code></span>
            </div>
            <input
              type="checkbox"
              checked={dlpAws}
              onChange={(e) => setDlpAws(e.target.checked)}
              className="w-4 h-4 accent-cyan-500"
            />
          </label>

          <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-[#070c14] cursor-pointer">
            <div>
              <span className="text-slate-200 font-medium block">US Social Security Numbers (SSN)</span>
              <span className="text-[11px] text-slate-400">Match <code>\d&#123;3&#125;-\d&#123;2&#125;-\d&#123;4&#125;</code></span>
            </div>
            <input
              type="checkbox"
              checked={dlpSsn}
              onChange={(e) => setDlpSsn(e.target.checked)}
              className="w-4 h-4 accent-cyan-500"
            />
          </label>

          <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-[#070c14] cursor-pointer">
            <div>
              <span className="text-slate-200 font-medium block">Indirect Prompt Injection Heuristics</span>
              <span className="text-[11px] text-slate-400">Jailbreak instructions in scraped data</span>
            </div>
            <input
              type="checkbox"
              checked={dlpPromptInjection}
              onChange={(e) => setDlpPromptInjection(e.target.checked)}
              className="w-4 h-4 accent-cyan-500"
            />
          </label>
        </div>
      </div>

      {/* Section 5: Audit Retention */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#090e18] space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 border-b border-slate-800 pb-3">
          <Database size={16} className="text-cyan-400" />
          <h3>Compliance & Audit Retention Policy</h3>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
          <div>
            <span className="text-slate-200 font-medium block">Audit Log Retention Window</span>
            <span className="text-[11px] text-slate-400">
              Duration security audit logs are retained before automated archival to immutable storage
            </span>
          </div>

          <div className="flex items-center gap-2 font-mono">
            {[30, 90, 180, 365].map((days) => (
              <button
                key={days}
                onClick={() => setRetentionDays(days)}
                className={`px-3 py-1.5 rounded-lg border text-xs transition-colors ${
                  retentionDays === days
                    ? 'border-cyan-500 bg-cyan-950/40 text-cyan-300 font-bold'
                    : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200'
                }`}
              >
                {days} Days
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
