import React from 'react';
import { Skull, AlertOctagon, ShieldAlert, ShieldCheck } from 'lucide-react';

const StatsCards = ({ stats, activeFilter, onFilterChange }) => {
  const cards = [
    { type: 'CRITICAL', count: stats.critical, icon: <Skull size={28} />, border: "border-red-500/30", bg: "bg-gradient-to-br from-red-950/40 to-slate-900/80", text: "text-red-500", glow: "shadow-[0_0_30px_rgba(239,68,68,0.2)]", activeBorder: "border-red-500" },
    { type: 'HIGH', count: stats.high, icon: <AlertOctagon size={28} />, border: "border-orange-500/30", bg: "bg-gradient-to-br from-orange-950/40 to-slate-900/80", text: "text-orange-500", glow: "shadow-[0_0_30px_rgba(249,115,22,0.2)]", activeBorder: "border-orange-500" },
    { type: 'MEDIUM', count: stats.medium, icon: <ShieldAlert size={28} />, border: "border-yellow-500/30", bg: "bg-gradient-to-br from-yellow-950/40 to-slate-900/80", text: "text-yellow-500", glow: "shadow-[0_0_30px_rgba(234,179,8,0.2)]", activeBorder: "border-yellow-500" },
    { type: 'LOW', count: stats.low, icon: <ShieldCheck size={28} />, border: "border-emerald-500/30", bg: "bg-gradient-to-br from-emerald-950/40 to-slate-900/80", text: "text-emerald-500", glow: "shadow-[0_0_30px_rgba(16,185,129,0.2)]", activeBorder: "border-emerald-500" },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
      {cards.map((card) => {
        const isActive = activeFilter === card.type;
        return (
          <div 
            key={card.type}
            onClick={() => onFilterChange(isActive ? null : card.type)}
            className={`relative p-6 rounded-2xl cursor-pointer transition-all duration-300 backdrop-blur-xl ${card.bg} border-y border-x ${isActive ? card.activeBorder : card.border} flex justify-between items-center group overflow-hidden ${isActive ? `scale-[1.02] ${card.glow} -translate-y-1` : 'hover:-translate-y-1 hover:shadow-2xl'}`}
          >
            {/* Background Accent Gradient */}
            <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-transparent to-${card.text.split('-')[1]}-500/10 blur-3xl rounded-full -mr-10 -mt-10 pointer-events-none`}></div>
            
            <div className="relative z-10">
              <p className={`text-[10px] font-mono font-bold uppercase tracking-[0.2em] ${card.text} opacity-70 mb-2`}>{card.type}</p>
              <p className="text-5xl font-black text-slate-200 tracking-tighter">{card.count}</p>
            </div>
            <div className={`relative z-10 p-4 rounded-2xl bg-slate-950/50 ${card.text} border border-slate-800/50 group-hover:scale-110 transition-transform duration-300`}>
              {card.icon}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default StatsCards;