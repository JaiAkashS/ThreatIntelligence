import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const RiskChart = ({ stats }) => {
  const data = [
    { name: 'Critical', value: stats.critical, color: '#ef4444' }, // red-500
    { name: 'High', value: stats.high, color: '#f97316' },     // orange-500
    { name: 'Medium', value: stats.medium, color: '#eab308' },   // yellow-500
    { name: 'Low', value: stats.low, color: '#22c55e' },      // green-500
  ].filter(d => d.value > 0);

  return (
    <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-center items-center h-full min-h-[250px]">
      <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider w-full text-left mb-4">Risk Distribution</h3>
      <div className="w-full flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie 
              data={data} 
              cx="50%" 
              cy="50%" 
              innerRadius={60} 
              outerRadius={80} 
              paddingAngle={5} 
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip 
              contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} 
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default RiskChart;