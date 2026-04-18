import React from 'react';
import { BarChart3 } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import InsightTooltip from './InsightTooltip';

const PRIORITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#10b981',
};

const TopThreatsChart = ({ cves = [] }) => {
  const data = cves
    .slice(0, 6)
    .map((cve) => ({
      id: cve.id,
      riskScore: Number(Number(cve.risk_score ?? 0).toFixed(1)),
      priority: (cve.priority || 'LOW').toUpperCase(),
      fill: PRIORITY_COLORS[(cve.priority || 'LOW').toUpperCase()] || '#38bdf8',
    }));

  return (
    // 1. Added explicit overflow-visible and z-50 to the main wrapper
    <div className="relative z-50 overflow-visible rounded-2xl border border-slate-800/80 bg-[#0f172a]/40 p-6 shadow-[0_8px_30px_rgb(0,0,0,0.4)] backdrop-blur-xl">
      
      <div className="absolute inset-x-0 top-0 h-1 rounded-t-2xl bg-gradient-to-r from-transparent via-red-500/30 to-transparent"></div>

      <div className="mb-5 flex items-center justify-between gap-4">
        <div>
          <h3 className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-[0.2em] text-slate-400">
            <BarChart3 size={14} className="text-red-400" />
            Top Threat Queue
          </h3>
          <p className="mt-2 max-w-xl text-sm text-slate-400">
            Highest-priority CVEs currently surfaced by the scoring engine.
          </p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-2 text-right">
          <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-slate-500">Visible</p>
          <p className="text-2xl font-black tracking-tight text-slate-200">{data.length}</p>
        </div>
      </div>

      <div className="h-[320px]">
        <ResponsiveContainer width="100%" height="100%" className="overflow-visible">
          {/* 2. Increased right margin to 120 to act as a buffer zone for the tooltip */}
          <BarChart data={data} layout="vertical" margin={{ top: 8, right: 120, left: 12, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={true} vertical={false} />
            <XAxis
              type="number"
              domain={[0, 100]}
              tick={{ fill: '#64748b', fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              dataKey="id"
              type="category"
              width={92}
              tick={{ fill: '#cbd5e1', fontSize: 11, fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
            />
            
            {/* 3. Forced ultra-high z-index on the tooltip wrapper */}
            <Tooltip
              cursor={{ fill: 'rgba(15, 23, 42, 0.55)' }}
              allowEscapeViewBox={{ x: true, y: true }}
              wrapperStyle={{ zIndex: 9999, outline: 'none' }}
              content={(
                <InsightTooltip
                  title="Threat Details"
                  labelFormatter={(label, payload) => {
                    const priority = payload?.[0]?.payload?.priority;
                    return priority ? `${label} • ${priority}` : label;
                  }}
                  valueFormatter={(value, _name, entry) => ({
                    value: `${value}/100`,
                    note: 'Contextual risk score after CVSS, exploitability, asset criticality, threat intel, and patch weighting.',
                  })}
                />
              )}
            />
            
            <Bar dataKey="riskScore" radius={[0, 10, 10, 0]} barSize={24}>
              {data.map((entry) => (
                <Cell key={entry.id} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default TopThreatsChart;