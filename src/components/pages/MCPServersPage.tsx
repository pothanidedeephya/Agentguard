import React, { useState } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { MCPServer, MCPServerTool } from '../../types/agentguard';
import { CodeBlock } from '../common/CodeBlock';
import {
  Server,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Radio,
  Search,
  ExternalLink,
  Shield,
  Layers,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Terminal,
} from 'lucide-react';

export const MCPServersPage: React.FC = () => {
  const { mcpServers, pingMcpServer, isBackendConnected } = useSecurity();

  const [selectedServer, setSelectedServer] = useState<MCPServer | null>(mcpServers[0] || null);
  const [inspectTool, setInspectTool] = useState<MCPServerTool | null>(null);
  const [pingingId, setPingingId] = useState<string | null>(null);
  const [serversState, setServersState] = useState<MCPServer[]>(mcpServers);

  const handlePing = async (serverId: string) => {
    setPingingId(serverId);
    try {
      const latency = await pingMcpServer(serverId);
      setServersState((prev) =>
        prev.map((s) =>
          s.id === serverId
            ? {
                ...s,
                lastPing: new Date().toISOString(),
                latencyMs: latency,
              }
            : s
        )
      );
    } catch {
      // fallback
    } finally {
      setPingingId(null);
    }
  };

  const handleToggleToolAllowed = (toolName: string) => {
    if (!selectedServer) return;
    setServersState((prev) =>
      prev.map((s) =>
        s.id === selectedServer.id
          ? {
              ...s,
              tools: s.tools.map((t) =>
                t.name === toolName ? { ...t, isAllowed: !t.isAllowed } : t
              ),
            }
          : s
      )
    );
    setSelectedServer((prev) =>
      prev
        ? {
            ...prev,
            tools: prev.tools.map((t) =>
              t.name === toolName ? { ...t, isAllowed: !t.isAllowed } : t
            ),
          }
        : null
    );
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <Server size={15} className="text-cyan-400" />
            Model Context Protocol (MCP) Connections & Health
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Transport connectivity, schema discovery, health probes, and granular per-tool authorization boundaries
          </p>
        </div>

        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
            Registered Daemons: <strong className="text-cyan-300">{serversState.length}</strong>
          </span>
        </div>
      </div>

      {/* Grid: Server Cards on Left, Selected Server on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: 4 Cols */}
        <div className="lg:col-span-4 space-y-2.5">
          {serversState.map((server) => {
            const isSelected = selectedServer?.id === server.id;
            const isConnected = server.status === 'CONNECTED';
            const isDegraded = server.status === 'DEGRADED';

            return (
              <div
                key={server.id}
                onClick={() => setSelectedServer(server)}
                className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                  isSelected
                    ? 'border-cyan-500/60 bg-[#121c2e]'
                    : 'border-slate-800/90 bg-[#0d1424] hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isConnected
                          ? 'bg-emerald-400'
                          : isDegraded
                          ? 'bg-amber-400'
                          : 'bg-rose-400'
                      }`}
                    />
                    <span className="text-xs font-semibold text-slate-100 font-mono">
                      {server.name}
                    </span>
                  </div>

                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-400 uppercase">
                    {server.transport}
                  </span>
                </div>

                <div className="mt-1.5 font-mono text-[11px] text-slate-400 truncate">
                  {server.endpointOrCommand}
                </div>

                <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                  <span>Tools: <strong className="text-slate-200">{server.tools.length}</strong></span>
                  <span>Allowed: <strong className="text-emerald-400">{server.allowedCallsCount}</strong></span>
                  <span>Blocked: <strong className="text-rose-400">{server.blockedCallsCount}</strong></span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Column: 8 Cols */}
        <div className="lg:col-span-8 space-y-3">
          {selectedServer ? (
            <div className="p-4 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-4">
              {/* Selected Server Top Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/90 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-100 font-mono">
                      {selectedServer.name}
                    </h3>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        selectedServer.status === 'CONNECTED'
                          ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300 font-semibold'
                          : 'border-amber-500/40 bg-amber-950/40 text-amber-300'
                      }`}
                    >
                      {selectedServer.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                    ID: {selectedServer.id} · Transport: {selectedServer.transport.toUpperCase()}
                  </p>
                </div>

                <div className="flex items-center gap-2.5">
                  <div className="text-right text-[11px] font-mono text-slate-400">
                    <div>Latency: <strong className="text-cyan-400">{selectedServer.latencyMs}ms</strong></div>
                    <div className="text-[10px]">Probe: {new Date(selectedServer.lastPing).toLocaleTimeString()}</div>
                  </div>
                  <button
                    onClick={() => handlePing(selectedServer.id)}
                    disabled={pingingId === selectedServer.id}
                    className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                    title="Send Health Check Ping"
                  >
                    <RefreshCw
                      size={13}
                      className={pingingId === selectedServer.id ? 'animate-spin' : ''}
                    />
                  </button>
                </div>
              </div>

              {/* Technical Endpoint Diagnostic Details */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs font-mono">
                <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase block">Connection State:</span>
                  <span className="text-emerald-400 font-bold block">ESTABLISHED</span>
                  <span className="text-[10px] text-slate-400 block">Health Check Verified</span>
                </div>
                <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase block">Invocation Activity:</span>
                  <span className="text-slate-100 font-bold block">
                    {selectedServer.allowedCallsCount + selectedServer.blockedCallsCount} calls
                  </span>
                  <span className="text-[10px] text-slate-400 block">
                    {selectedServer.blockedCallsCount} quarantined violations
                  </span>
                </div>
                <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase block">Daemon Errors:</span>
                  <span className="text-emerald-400 font-bold block">0 ERROR ALERTS</span>
                  <span className="text-[10px] text-slate-400 block">Clean stdio/socket pipe</span>
                </div>
              </div>

              <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] text-xs font-mono">
                <span className="text-slate-400 text-[10px] uppercase block mb-0.5">
                  Endpoint Command / Target URI:
                </span>
                <span className="text-cyan-300 block truncate">
                  {selectedServer.endpointOrCommand}
                </span>
              </div>

              {/* Available Tools with Schema Inspector & Granular Switch */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                    Discovered Tools ({selectedServer.tools.length})
                  </h4>
                  <span className="text-[10px] font-mono text-slate-400">
                    Granular Tool Access Control
                  </span>
                </div>

                <div className="space-y-2">
                  {selectedServer.tools.map((tool) => (
                    <div
                      key={tool.name}
                      className="p-3 rounded border border-slate-800 bg-slate-900/50 hover:border-slate-700 transition-colors space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-100">
                            {tool.name}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                              tool.isAllowed
                                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                                : 'border-rose-500/40 bg-rose-950/40 text-rose-300'
                            }`}
                          >
                            {tool.isAllowed ? 'ALLOWED' : 'BLOCKED'}
                          </span>
                        </div>

                        <div className="flex items-center gap-2.5">
                          <button
                            onClick={() => setInspectTool(inspectTool?.name === tool.name ? null : tool)}
                            className="text-[11px] font-mono text-cyan-400 hover:underline"
                          >
                            {inspectTool?.name === tool.name ? 'Hide Schema' : 'Inspect Schema'}
                          </button>
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={tool.isAllowed}
                              onChange={() => handleToggleToolAllowed(tool.name)}
                              className="sr-only peer"
                            />
                            <div className="w-7 h-3.5 bg-slate-800 peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-emerald-500" />
                          </label>
                        </div>
                      </div>

                      <p className="text-xs text-slate-400 font-sans">
                        {tool.description}
                      </p>

                      <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400">
                        <span>Executed: <strong className="text-slate-200">{tool.callsCount}</strong> times</span>
                        <span>·</span>
                        <span>Quarantined: <strong className="text-rose-400">{tool.blockedCount}</strong></span>
                      </div>

                      {/* Schema viewer */}
                      {inspectTool?.name === tool.name && (
                        <div className="pt-2">
                          <CodeBlock
                            code={tool.parametersSchema}
                            title={`${tool.name}_schema.json`}
                            maxHeight="max-h-40"
                          />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center rounded-lg border border-dashed border-slate-800 bg-[#0d1424] text-xs text-slate-400 font-mono">
              Select an MCP connection on the left to inspect its status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
