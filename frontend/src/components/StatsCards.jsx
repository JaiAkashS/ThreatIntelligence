import React from 'react';
import { ShieldAlert, AlertTriangle, Shield, ShieldCheck } from 'lucide-react';

const StatsCards = ({ stats, activeFilter, onFilterChange }) => {
  const cards = [
    { type: 'CRITICAL', count: stats.critical, icon: <ShieldAlert size={24} />, bg: "bg-red-50", text: "text-red-700", border: "border-red-200" },
    { type: 'HIGH', count: stats.high, icon: <AlertTriangle size={24} />, bg: "bg-orange-50", text: "text-orange-700", border: "border-orange-200" },
    { type: 'MEDIUM', count: stats.medium, icon: <Shield size={24} />, bg: "bg-yellow-50", text: "text-yellow-700", border: "border-yellow-200" },
    { type: 'LOW', count: stats.low, icon: <ShieldCheck size={24} />, bg: "bg-green-50", text: "text-green-700", border: "border-green-200" },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => {
        const isActive = activeFilter === card.type;
        return (
          <div 
            key={card.type}
            onClick={() => onFilterChange(isActive ? null : card.type)}
            className={`p-5 rounded-xl border cursor-pointer transition-all duration-200 ${card.bg} ${card.border} flex justify-between items-start ${isActive ? 'ring-2 ring-offset-2 ring-indigo-500 scale-[1.02] shadow-md' : 'hover:shadow-sm'}`}
          >
            <div>
              <p className={`text-sm font-bold uppercase tracking-wider ${card.text} opacity-80`}>{card.type}</p>
              <p className={`text-3xl font-extrabold mt-1 ${card.text}`}>{card.count}</p>
            </div>
            <div className={`p-2 rounded-full bg-white/60 ${card.text}`}>
              {card.icon}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default StatsCards;