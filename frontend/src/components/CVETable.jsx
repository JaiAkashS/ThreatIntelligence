import React from 'react';
import { Activity, ShieldCheck } from 'lucide-react';

const CVETable = ({ cves }) => {
  const getSeverityData = (score) => {
    if (score >= 9.0) return { label: 'CRITICAL', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200' };
    if (score >= 7.0) return { label: 'HIGH', color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200' };
    if (score >= 4.0) return { label: 'MEDIUM', color: 'text-yellow-700', bg: 'bg-yellow-50', border: 'border-yellow-200' };
    return { label: 'LOW', color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-200' };
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50/50">
        <h3 className="font-bold text-slate-800">Threat Intelligence Log</h3>
        <span className="text-xs font-semibold text-slate-500 bg-slate-200 px-3 py-1 rounded-full">
          Showing {cves.length} records
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead className="bg-white border-b border-slate-200">
            <tr>
              <th className="p-4 font-semibold text-slate-500 text-xs uppercase tracking-wider">Vulnerability</th>
              <th className="p-4 font-semibold text-slate-500 text-xs uppercase tracking-wider text-center">CVSS Score</th>
              <th className="p-4 font-semibold text-slate-500 text-xs uppercase tracking-wider">AI Recommendation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {cves.length > 0 ? (
              cves.map((cve, index) => {
                const style = getSeverityData(cve.score);
                return (
                  <tr key={cve.id || index} className="hover:bg-slate-50 transition-colors group">
                    <td className="p-4">
                      <div className="flex flex-col">
                        <span className="font-bold text-indigo-700">{cve.id}</span>
                        <span className="text-slate-500 text-sm mt-1 max-w-sm truncate group-hover:whitespace-normal group-hover:break-words transition-all">{cve.description}</span>
                      </div>
                    </td>
                    <td className="p-4 text-center">
                      <div className="flex flex-col items-center gap-1">
                        <span className={`text-lg font-bold ${style.color}`}>{cve.score?.toFixed(1) || 'N/A'}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${style.bg} ${style.border} ${style.color}`}>
                          {style.label}
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex items-start gap-2 bg-indigo-50/50 p-3 rounded-lg border border-indigo-100/50">
                        <Activity size={16} className="text-indigo-500 mt-0.5 shrink-0" />
                        <span className="text-sm text-slate-700 font-medium">
                          {cve.explanation || "Awaiting AI analysis..."}
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan="3" className="p-12 text-center">
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