import React, { useState } from 'react';
import { Crosshair, Zap, Cpu, CheckCircle2, ChevronRight, Binary } from 'lucide-react';

const CVETable = ({ cves }) => {
  const [expandedId, setExpandedId] = useState(null);

  const toggleRow = (id) => setExpandedId(expandedId === id ? null : id);

  const getStyleForPriority = (priority) => {
    const p = (priority || 'LOW').toUpperCase();
    if (p === 'CRITICAL') return { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/40', glow: 'shadow-[0_0_15px_rgba(239,68,68,0.3)]' };
    if (p === 'HIGH') return { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/40', glow: 'shadow-[0_0_15px_rgba(249,115,22,0.3)]' };
    if (p === 'MEDIUM') return { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/40', glow: 'shadow-[0_0_15px_rgba(234,179,8,0.3)]' };
    return { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/40', glow: 'shadow-[0_0_15px_rgba(16,185,129,0.3)]' };
  };

  return (
    <div className="bg-[#0f172a]/40 backdrop-blur-xl rounded-2xl shadow-[0_8px_30px_rgb(0,0,0,0.4)] border border-slate-800/80 overflow-hidden relative">
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-slate-600/30 to-transparent"></div>
      
      <div className="px-8 py-5 border-b border-slate-800/80 flex justify-between items-center bg-[#020617]/50">
        <h3 className="text-xs font-mono font-bold text-slate-300 tracking-[0.2em] uppercase flex items-center gap-3">
          <Binary size={16} className="text-slate-500" />
          Threat Matrix Log
        </h3>
        <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-4 py-1.5 rounded-full uppercase tracking-widest">
          {cves.length} Signatures Matched
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead className="bg-[#020617]/80">
            <tr>
              <th className="p-5 w-12 border-b border-slate-800/80"></th>
              <th className="p-5 font-mono font-semibold text-slate-500 text-[10px] uppercase tracking-[0.2em] border-b border-slate-800/80 w-1/4">Vector / ID</th>
              <th className="p-5 font-mono font-semibold text-slate-500 text-[10px] uppercase tracking-[0.2em] text-center border-b border-slate-800/80 w-32">Severity Index</th>
              <th className="p-5 font-mono font-semibold text-slate-500 text-[10px] uppercase tracking-[0.2em] border-b border-slate-800/80">Automated Directives</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {cves.length > 0 ? (
              cves.map((cve) => {
                const style = getStyleForPriority(cve.priority);
                const isExpanded = expandedId === cve.id;

                return (
                  <React.Fragment key={cve.id}>
                    <tr 
                      onClick={() => toggleRow(cve.id)}
                      className={`hover:bg-slate-800/30 transition-all duration-300 cursor-pointer group align-top ${isExpanded ? 'bg-slate-800/20' : ''}`}
                    >
                      <td className="p-5 text-slate-600 group-hover:text-cyan-400 transition-colors align-middle">
                        <ChevronRight size={20} className={`transform transition-transform duration-300 ${isExpanded ? 'rotate-90 text-cyan-400' : ''}`} />
                      </td>
                      <td className="p-5">
                        <div className="flex flex-col gap-2.5">
                          <span className="font-mono font-bold text-slate-200 text-sm tracking-wide">{cve.id}</span>
                          
                          {/* Description mapped from backend payload */}
                          {cve.description && (
                            <p className="text-[11px] text-slate-400 leading-relaxed italic max-w-sm line-clamp-2 group-hover:text-slate-300 transition-colors">
                              {cve.description}
                            </p>
                          )}

                          {cve.dominant_factor && (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[9px] font-mono font-bold bg-[#020617] text-slate-400 border border-slate-700/80 tracking-widest uppercase w-fit group-hover:border-slate-600">
                              <Zap size={10} className="text-amber-400" /> {cve.dominant_factor.replace(/_/g, ' ')}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-5 text-center">
                        <div className="flex flex-col items-center gap-2">
                          <span className={`text-2xl font-black font-sans tracking-tighter ${style.color}`}>
                            {cve.risk_score?.toFixed(1) || 'N/A'}
                          </span>
                          <span className={`px-3 py-1 rounded-full text-[9px] font-mono font-bold uppercase tracking-widest border ${style.bg} ${style.border} ${style.color} ${style.glow}`}>
                            {cve.priority || 'UNKNOWN'}
                          </span>
                        </div>
                      </td>
                      <td className="p-5">
                        <div className="flex flex-col gap-4">
                          {/* AI Summary */}
                          <div className="flex items-start gap-3 bg-[#020617]/40 p-3 rounded-xl border border-slate-800/40">
                            <Cpu size={16} className="text-cyan-500 mt-0.5 shrink-0" />
                            <span className="text-sm text-slate-300 font-medium leading-relaxed">
                              {cve.explanation?.summary || "Analyzing vulnerability signature..."}
                            </span>
                          </div>

                          {/* Recommended Actions */}
                          {cve.explanation?.recommended_actions?.length > 0 && (
                            <div className="ml-7 pl-3 border-l-2 border-slate-700/50">
                              <ul className="space-y-2">
                                {cve.explanation.recommended_actions.map((action, i) => (
                                  <li key={i} className="text-[13px] text-slate-400 flex items-start gap-2.5 font-mono">
                                    <CheckCircle2 size={14} className="text-emerald-500 mt-0.5 shrink-0" />
                                    {action}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                    
                    {/* Telemetry Drawer */}
                    {isExpanded && cve.factor_breakdown && (
                      <tr className="bg-[#020617] border-b border-slate-800/80">
                        <td colSpan="4" className="p-0">
                          <div className="px-16 py-8">
                            <div className="bg-[#0f172a]/60 border border-slate-800/80 p-6 rounded-2xl relative overflow-hidden">
                              <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 blur-[100px] rounded-full"></div>
                              <h4 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-[0.2em] mb-6 flex items-center gap-2">
                                <Crosshair size={14} className="text-slate-400" /> Granular Factor Analysis
                              </h4>
                              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 relative z-10">
                                {Object.entries(cve.factor_breakdown).map(([key, data]) => (
                                  <div key={key} className="bg-[#020617]/80 p-4 rounded-xl border border-slate-800/50 hover:border-slate-700/80 transition-colors">
                                    <p className="text-[9px] text-slate-500 font-mono uppercase tracking-[0.2em] truncate mb-2">
                                      {key.replace(/_/g, ' ')}
                                    </p>
                                    <p className="text-lg font-bold text-slate-200 font-mono">
                                      {typeof data.raw_value === 'number' 
                                        ? data.raw_value.toFixed(1) 
                                        : data.raw_value}
                                    </p>
                                    <p className="text-[9px] text-cyan-500/70 font-mono mt-1">
                                      +{data.contribution.toFixed(1)} pts
                                    </p>
                                  </div>
                                ))}
                              </div>
                              {cve.explanation?.dominant_factor_note && (
                                <p className="mt-6 text-[11px] font-mono text-slate-500 italic border-t border-slate-800/50 pt-4">
                                  {cve.explanation.dominant_factor_note}
                                </p>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            ) : (
              <tr>
                <td colSpan="4" className="p-20 text-center">
                  <p className="text-slate-500 font-mono text-[11px] tracking-[0.2em] uppercase">No Threats Identified</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default CVETable;