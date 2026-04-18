import React from "react";
import {
  Radar,
  RadarChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { Activity } from "lucide-react";
import InsightTooltip from "./InsightTooltip";

const FactorInsightsChart = ({ data = [] }) => {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-800/80 bg-[#0f172a]/40 p-6 shadow-[0_8px_30px_rgb(0,0,0,0.4)] backdrop-blur-xl">
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent"></div>
      <div className="pointer-events-none absolute -left-16 top-32 h-56 w-56 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute bottom-0 right-0 h-64 w-64 rounded-full bg-sky-500/10 blur-3xl" />

      <div className="relative z-10 space-y-4">
        <div>
          <h3 className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-[0.2em] text-slate-400">
            <Activity size={14} className="text-cyan-400" />
            Risk Driver Map
          </h3>
        </div>

        <div className="rounded-[28px] border border-slate-800/80 bg-[#081426]/80 p-4 sm:p-6">
          <div className="h-[360px] sm:h-[420px]">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="52%" outerRadius="74%" data={data}>
                <PolarGrid stroke="#23344d" />
                <PolarAngleAxis
                  dataKey="shortLabel"
                  tick={{
                    fill: "#dbe7f5",
                    fontSize: 12,
                    fontFamily: "monospace",
                  }}
                />
                <PolarRadiusAxis
                  angle={18}
                  domain={[0, 35]}
                  tick={{ fill: "#6b86a4", fontSize: 10 }}
                  axisLine={false}
                />
                <Tooltip
                  cursor={false}
                  position={{ x: 10, y: -10 }}
                  content={
                    <InsightTooltip
                      title="Risk Driver"
                      labelFormatter={(label, payload) => {
                        const factor = payload?.[0]?.payload?.factor;
                        return factor ? factor.replace(/_/g, " ") : label;
                      }}
                      valueFormatter={(value, _name) => ({
                        value: `${Number(value).toFixed(1)} pts`,
                        note: "Average contribution of this factor across the visible CVEs.",
                      })}
                    />
                  }
                />
                <defs>
                  <linearGradient
                    id="riskDriverFill"
                    x1="0"
                    y1="0"
                    x2="1"
                    y2="1"
                  >
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
                    <stop
                      offset="100%"
                      stopColor="#0ea5e9"
                      stopOpacity="0.12"
                    />
                  </linearGradient>
                </defs>
                <Radar
                  name="Contribution"
                  dataKey="value"
                  stroke="#22d3ee"
                  fill="url(#riskDriverFill)"
                  fillOpacity={1}
                  strokeWidth={2.5}
                  dot={{
                    r: 4,
                    fill: "#67e8f9",
                    stroke: "#083344",
                    strokeWidth: 2,
                  }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FactorInsightsChart;
