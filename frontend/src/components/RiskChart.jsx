import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const RiskChart = ({ stats = {} }) => {
  const data = [
    { name: 'Critical', value: stats.critical ?? 0, color: '#ef4444' }, // red-500
    { name: 'High', value: stats.high ?? 0, color: '#f97316' },     // orange-500
    { name: 'Medium', value: stats.medium ?? 0, color: '#eab308' },   // yellow-500
    { name: 'Low', value: stats.low ?? 0, color: '#22c55e' },      // green-500
  ].filter(d => d.value > 0);

  const totalThreats = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm h-full min-h-[340px]">
      <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider">
        Risk Distribution
      </h3>

      <div className="relative mt-4 h-[260px]">
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center">
          <div className="flex -translate-y-4 flex-col items-center text-center">
            <span className="text-4xl font-extrabold leading-none text-slate-900">
              {totalThreats}
            </span>
            <span className="mt-2 text-sm font-medium text-slate-500">
              Total Threats
            </span>
          </div>
        </div>

        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="46%"
              innerRadius={72}
              outerRadius={98}
              paddingAngle={4}
              dataKey="value"
              cornerRadius={6}
              stroke="none"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>

            <Tooltip
              contentStyle={{
                borderRadius: '12px',
                border: 'none',
                boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)',
                padding: '8px 12px',
              }}
              itemStyle={{ color: '#0f172a', fontWeight: 'bold' }}
            />

            <Legend
              verticalAlign="bottom"
              align="center"
              height={44}
              iconType="circle"
              wrapperStyle={{ fontSize: '13px', color: '#475569', fontWeight: '500' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default RiskChart;
