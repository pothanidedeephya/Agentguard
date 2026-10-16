import React, { useState, useMemo } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  BarChart3,
  Calendar,
  ShieldCheck,
  ShieldAlert,
  Server,
  Activity,
  Layers,
  Info,
  Terminal,
} from 'lucide-react';

export const AnalyticsPage: React.FC = () => {
  const { isBackendConnected, metrics, mcpServers, toolCalls, threats, operatingState, dbState, dbHost } = useSecurity();

  const [timeRange, setTimeRange] = useState<'15m' | '1h' | '24h' | '7d'>('24h');

  // Compute actual dynamic analytics from current toolCalls and threats
  const dynamicThreatsData = useMemo(() => {
    const counts: Record<string, number> = {};
    const palette = ['#f43f5e', '#fb923c', '#c084fc', '#38bdf8', '#facc15'];

    threats.forEach((t) => {
      const key = t.category.replace(/_/g, ' ');
      counts[key] = (counts[key] || 0) + 1;
    });

    const items = Object.entries(counts).map(([name, count], i) => ({
      name,
      count,
      color: palette[i % palette.length],
    }));

    if (items.length === 0) {
      return [{ name: 'Zero Threats', count: 0, color: '#10b981' }];
    }
    return items;
  }, [threats]);

  // Risk Score Histogram calculated from toolCalls
  const riskHistogram = useMemo(() => {
    const buckets = [
      { range: '0 - 19 (Safe)', count: 0 },
      { range: '20 - 39 (Low)', count: 0 },
      { range: '40 - 59 (Med)', count: 0 },
      { range: '60 - 79 (High)', count: 0 },
      { range: '80 - 100 (Crit)', count: 0 },
    ];

    toolCalls.forEach((c) => {
      if (c.riskScore < 20) buckets[0].count++;
      else if (c.riskScore < 40) buckets[1].count++;
      else if (c.riskScore < 60) buckets[2].count++;
      else if (c.riskScore < 80) buckets[3].count++;
      else buckets[4].count++;
    });

    return buckets;
  }, [toolCalls]);

  // Top Invoked vs Quarantined Tools
  const topToolsData = useMemo(() => {
    const invokedMap: Record<string, number> = {};
    const blockedMap: Record<string, number> = {};

    toolCalls.forEach((c) => {
      invokedMap[c.toolName] = (invokedMap[c.toolName] || 0) + 1;
      if (c.decision === 'BLOCK' || c.status === 'BLOCKED') {
        blockedMap[c.toolName] = (blockedMap[c.toolName] || 0) + 1;
      }
    });

    const topInvoked = Object.entries(invokedMap)
      .map(([tool, calls]) => ({ tool, calls }))
      .sort((a, b) => b.calls - a.calls)
      .slice(0, 5);

    const topBlocked = Object.entries(blockedMap)
      .map(([tool, blocks]) => ({ tool, blocks }))
      .sort((a, b) => b.blocks - a.blocks)
      .slice(0, 5);

    return { topInvoked, topBlocked };
  }, [toolCalls]);

  // Time Series Volume
  const timeSeriesData = {
    '15m': [
      { time: '22:35', total: 18, allowed: 16, blocked: 2 },
      { time: '22:40', total: 24, allowed: 21, blocked: 2 },
      { time: '22:45', total: 32, allowed: 29, blocked: 3 },
      { time: '22:50', total: 28, allowed: 25, blocked: 2 },
    ],
    '1h': [
      { time: '22:00', total: 85, allowed: 78, blocked: 5 },
      { time: '22:15', total: 110, allowed: 98, blocked: 9 },
      { time: '22:30', total: 145, allowed: 132, blocked: 10 },
      { time: '22:45', total: 160, allowed: 144, blocked: 12 },
    ],
    '24h': [
      { time: '04:00', total: 120, allowed: 115, blocked: 4 },
      { time: '08:00', total: 340, allowed: 310, blocked: 22 },
      { time: '12:00', total: 620, allowed: 580, blocked: 32 },
      { time: '16:00', total: 840, allowed: 790, blocked: 41 },
      { time: '20:00', total: 510, allowed: 480, blocked: 25 },
      { time: '24:00', total: 411, allowed: 383, blocked: 22 },
    ],
    '7d': [
      { time: 'Mon', total: 2400, allowed: 2280, blocked: 95 },
      { time: 'Tue', total: 3100, allowed: 2920, blocked: 140 },
      { time: 'Wed', total: 2950, allowed: 2790, blocked: 125 },
      { time: 'Thu', total: 3400, allowed: 3210, blocked: 155 },
      { time: 'Fri', total: 3800, allowed: 3580, blocked: 180 },
      { time: 'Sat', total: 1200, allowed: 1140, blocked: 48 },
      { time: 'Sun', total: 1400, allowed: 1330, blocked: 58 },
    ],
  }[timeRange];

  const isLive = operatingState === 'LIVE' && isBackendConnected && dbState === 'CONNECTED';

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <BarChart3 size={15} className="text-cyan-400" />
            Risk Analysis & Threat Intelligence
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Statistical behavioral distributions, policy enforcement trends, and tool risk metrics
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span
            className={`px-2 py-0.5 rounded border ${
              isLive
                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                : 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300'
            }`}
          >
            {isLive ? `PostgreSQL Live Analytics` : 'Demo Telemetry'}
          </span>

          <div className="flex items-center p-0.5 bg-slate-900 border border-slate-800 rounded">
            {(['15m', '1h', '24h', '7d'] as const).map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  timeRange === r
                    ? 'bg-slate-800 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Row 1: Volume & Threat Vectors */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Volume (7 cols) */}
        <div className="lg:col-span-7 p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/90 pb-2">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                Interception Volume Trend ({timeRange})
              </h3>
              <p className="text-[11px] text-slate-400">Total evaluations vs blocked tool calls</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded bg-cyan-400" /> Total
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded bg-rose-500" /> Blocked
              </span>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#080d17',
                    border: '1px solid #1e293b',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                />
                <Area type="monotone" dataKey="total" stroke="#0ea5e9" strokeWidth={1.5} fill="#0ea5e9" fillOpacity={0.15} />
                <Area type="monotone" dataKey="blocked" stroke="#f43f5e" strokeWidth={1.5} fill="#f43f5e" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Threat Breakdown (5 cols) */}
        <div className="lg:col-span-5 p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-3 flex flex-col justify-between">
          <div className="border-b border-slate-800/90 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
              Threat Vector Categories
            </h3>
            <p className="text-[11px] text-slate-400">Interception classification distribution</p>
          </div>

          <div className="h-36 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={dynamicThreatsData}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={42}
                  outerRadius={64}
                  paddingAngle={3}
                >
                  {dynamicThreatsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#080d17',
                    border: '1px solid #1e293b',
                    borderRadius: '6px',
                    fontSize: '11px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="space-y-1 font-mono text-[11px] border-t border-slate-800/80 pt-2">
            {dynamicThreatsData.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-slate-300">
                <span className="flex items-center gap-1.5 truncate">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                  <span className="truncate">{item.name}</span>
                </span>
                <span className="text-slate-400 font-semibold">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 2: Tool Activity & Risk Score Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Most Invoked Tools */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-3">
          <div className="border-b border-slate-800/90 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
              Top Invoked Tools
            </h3>
            <p className="text-[11px] text-slate-400">Highest volume legitimate interactions</p>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topToolsData.topInvoked} layout="vertical">
                <XAxis type="number" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis dataKey="tool" type="category" stroke="#94a3b8" fontSize={10} width={130} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#080d17',
                    border: '1px solid #1e293b',
                    borderRadius: '6px',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="calls" fill="#0ea5e9" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Histogram */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-3">
          <div className="border-b border-slate-800/90 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
              Risk Score Distribution
            </h3>
            <p className="text-[11px] text-slate-400">Frequency of evaluated tool requests by computed score</p>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskHistogram}>
                <XAxis dataKey="range" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#080d17',
                    border: '1px solid #1e293b',
                    borderRadius: '6px',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
