import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend, Label } from 'recharts';

const RiskChart = ({ stats }) => {
  const data = [
    { name: 'Critical', value: stats.critical, color: '#ef4444' }, // red-500
    { name: 'High', value: stats.high, color: '#f97316' },     // orange-500
    { name: 'Medium', value: stats.medium, color: '#eab308' },   // yellow-500
    { name: 'Low', value: stats.low, color: '#22c55e' },      // green-500
  ].filter(d => d.value > 0);

  // Calculate the total for the center label
  const totalThreats = data.reduce((sum, item) => sum + item.value, 0);

  // Custom component to render text perfectly in the center of the Donut
  const CenterLabel = ({ viewBox }) => {
    const { cx, cy } = viewBox;
    return (
      <text x={cx} y={cy} textAnchor="middle" dominantBaseline="central">
        <tspan x={cx} y={cy - 5} fontSize="32" fontWeight="800" fill="#0f172a">
          {totalThreats}
        </tspan>
        <tspan x={cx} y={cy + 20} fontSize="13" fontWeight="500" fill="#64748b">
          Total Threats
        </tspan>
      </text>
    );
  };

  return (
    <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-center items-center h-full min-h-[300px]">
      <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider w-full text-left mb-2">Risk Distribution</h3>
      
      <div className="w-full flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie 
              data={data} 
              cx="50%" 
              cy="50%" 
              innerRadius={75}   // Widened the hole
              outerRadius={100}  // Perfected the ring thickness
              paddingAngle={4}   // Small gap between slices
              dataKey="value"
              cornerRadius={6}   // MAGIC TRICK: Rounds the slice edges!
              stroke="none"      // Removes the default ugly border
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
              <Label content={<CenterLabel />} position="center" />
            </Pie>
            
            <Tooltip 
              contentStyle={{ 
                borderRadius: '12px', 
                border: 'none', 
                boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)',
                padding: '8px 12px'
              }}
              itemStyle={{ color: '#0f172a', fontWeight: 'bold' }}
            />
            
            <Legend 
              verticalAlign="bottom" 
              height={36} 
              iconType="circle" // Swaps default squares for clean circles
              wrapperStyle={{ fontSize: '13px', color: '#475569', fontWeight: '500' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default RiskChart;