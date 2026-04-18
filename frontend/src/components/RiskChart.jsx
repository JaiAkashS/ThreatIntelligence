import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const RiskChart = ({ stats = {} }) => {
  const data = [
    { name: 'Critical', value: stats.critical ?? 0, color: '#ef4444' },
    { name: 'High', value: stats.high ?? 0, color: '#f97316' }, 
    { name: 'Medium', value: stats.medium ?? 0, color: '#eab308' },
    { name: 'Low', value: stats.low ?? 0, color: '#10b981' }, 
  ].filter(d => d.value > 0);

  const totalThreats = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="bg-[#0f172a]/40 backdrop-blur-xl p-6 rounded-2xl border border-slate-800/80 shadow-[0_8px_30px_rgb(0,0,0,0.4)] h-full flex flex-col relative overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent"></div>

      <h3 className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2 mb-2">
        <span className="w-2 h-2 rounded-sm bg-cyan-500/50 inline-block"></span>
        Risk Distribution
      </h3>

      <div className="relative flex-1 min-h-[220px]">
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center">
          <div className="flex -translate-y-4 flex-col items-center text-center">
            <span className="text-4xl font-black leading-none text-slate-200 tracking-tighter drop-shadow-md">
              {totalThreats}
            </span>
            <span className="mt-2 text-[9px] font-mono font-semibold text-slate-500 uppercase tracking-[0.2em]">
              Threats
            </span>
          </div>
        </div>

        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="46%"
              innerRadius={65}
              outerRadius={90}
              paddingAngle={5}
              dataKey="value"
              cornerRadius={8}
              stroke="none"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} className="drop-shadow-lg" />
              ))}
            </Pie>

            <Tooltip
              cursor={false}
              contentStyle={{
                backgroundColor: 'rgba(2, 6, 23, 0.85)',
                backdropFilter: 'blur(12px)',
                border: '1px solid #1e293b',
                borderRadius: '16px',
                boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
                padding: '12px 20px',
              }}
              itemStyle={{ color: '#e2e8f0', fontWeight: 'bold', fontFamily: 'monospace', fontSize: '14px' }}
            />

            <Legend
              verticalAlign="bottom"
              align="center"
              height={30}
              iconType="circle"
              wrapperStyle={{ 
                fontSize: '10px', 
                color: '#94a3b8', 
                fontFamily: 'monospace', 
                textTransform: 'uppercase', 
                letterSpacing: '0.1em' 
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default RiskChart;