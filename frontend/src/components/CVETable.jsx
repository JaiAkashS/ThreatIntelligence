import React, { useState } from 'react';
import { ShieldCheck, Zap, Activity, CheckCircle2, ChevronDown, ChevronUp, Network } from 'lucide-react';

const CVETable = ({ cves }) => {
  const [expandedId, setExpandedId] = useState(null);

  const toggleRow = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getStyleForPriority = (priority) => {
    const p = (priority || 'LOW').toUpperCase();
    if (p === 'CRITICAL') return { color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200' };
    if (p === 'HIGH') return { color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200' };
    if (p === 'MEDIUM') return { color: 'text-yellow-700', bg: 'bg-yellow-50', border: 'border-yellow-200' };
    return { color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-200' };
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50/50">
        <h3 className="font-bold text-slate-800">AI Threat Analysis Log</h3>
        <span className="text-xs font-semibold text-slate-500 bg-slate-200 px-3 py-1 rounded-full">
          Showing {cves.length} records
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead className="bg-white border-b border-slate-200">
            <tr>
              <th className="p-4 w-8"></th>
              <th className="p-4 font-semibold text-slate-500 text-xs uppercase tracking-wider w-1/4">Threat Context</th>
              <th className="p-4 font-semibold text-slate-500 text-xs uppercase tracking-wider text-center w-32">Risk Score</th>
              <th className="p-4 font-semibold text-slate-500 text-xs uppercase tracking-wider">AI Insight & Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {cves.length > 0 ? (
              cves.map((cve) => {
                const style = getStyleForPriority(cve.priority);
                const isExpanded = expandedId === cve.id;

                return (
                  <React.Fragment key={cve.id}>
                    <tr 
                      onClick={() => toggleRow(cve.id)}
                      className={`hover:bg-slate-50 transition-colors cursor-pointer group align-top ${isExpanded ? 'bg-slate-50' : ''}`}
                    >
                      <td className="p-4 text-slate-400">
                        {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                      </td>
                      <td className="p-4">
                        <div className="flex flex-col gap-2">
                          <span className="font-bold text-indigo-700 text-base">{cve.id}</span>
                          {cve.dominant_factor && (
                            <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-200 tracking-wide uppercase w-fit">
                              <Zap size={12} className="text-amber-500" /> {cve.dominant_factor}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-4 text-center">
                        <div className="flex flex-col items-center gap-1">
                          <span className={`text-2xl font-black ${style.color}`}>
                            {cve.risk_score?.toFixed(1) || 'N/A'}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${style.bg} ${style.border} ${style.color}`}>
                            {cve.priority || 'UNKNOWN'}
                          </span>
                        </div>
                      </td>
                      <td className="p-4">
                        <div className="flex flex-col gap-3">
                          <div className="flex items-start gap-2">
                            <Activity size={16} className="text-indigo-500 mt-0.5 shrink-0" />
                            <span className="text-sm text-slate-700 font-medium">
                              {cve.explainations?.summary || "No AI summary provided."}
                            </span>
                          </div>
                          {cve.recommended_actions && cve.recommended_actions.length > 0 && (
                            <div className="bg-indigo-50/50 p-3 rounded-lg border border-indigo-100/50 ml-6">
                              <p className="text-[10px] font-bold text-indigo-400 uppercase tracking-wider mb-2">Recommended Actions</p>
                              <ul className="space-y-1.5">
                                {cve.recommended_actions.map((action, i) => (
                                  <li key={i} className="text-sm text-slate-600 flex items-start gap-2">
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
                    
                    {/* Expandable Row Content: Factor Breakdown */}
                    {isExpanded && cve.factor_breakdown && (
                      <tr className="bg-slate-50 border-b border-slate-200">
                        <td colSpan="4" className="p-0">
                          <div className="px-14 py-4 pb-6">
                            <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-inner">
                              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <Network size={14} /> Risk Factor Breakdown
                              </h4>
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                {Object.entries(cve.factor_breakdown).map(([key, value]) => (
                                  <div key={key} className="bg-slate-50 p-3 rounded border border-slate-100">
                                    <p className="text-[10px] text-slate-400 uppercase font-bold truncate">
                                      {key.replace(/_/g, ' ')}
                                    </p>
                                    <p className="text-lg font-bold text-slate-700 mt-1">{value}</p>
                                  </div>
                                ))}
                              </div>
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
                <td colSpan="4" className="p-12 text-center">
                  <ShieldCheck size={48} className="mx-auto text-slate-300 mb-3" />
                  <p className="text-slate-500 font-medium">No vulnerabilities found matching your criteria.</p>
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