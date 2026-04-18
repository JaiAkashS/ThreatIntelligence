import React from "react";

const InsightTooltip = ({
  active,
  label,
  payload,
  title,
  labelFormatter,
  valueFormatter,
}) => {
  if (!active || !payload?.length) {
    return null;
  }

  const resolvedLabel = labelFormatter ? labelFormatter(label, payload) : label;

  return (
    <div className="min-w-[200px] overflow-hidden rounded-lg border border-slate-700/60 bg-[#020817]/80 shadow-[0_8px_25px_rgba(2,8,23,0.4)] backdrop-blur-sm">
      <div className="h-1 w-full bg-gradient-to-r from-cyan-400 via-sky-500 to-fuchsia-500" />
      <div className="space-y-3 p-4">
        <div>
          {title && (
            <p className="text-[10px] font-mono uppercase tracking-[0.22em] text-slate-500">
              {title}
            </p>
          )}
          {resolvedLabel && (
            <p className="mt-1 text-sm font-semibold text-slate-100">
              {resolvedLabel}
            </p>
          )}
        </div>

        <div className="space-y-2">
          {payload.map((entry, index) => {
            const resolved = valueFormatter
              ? valueFormatter(entry.value, entry.name, entry, payload)
              : { value: entry.value, note: entry.name };

            const value =
              typeof resolved === "object" ? resolved.value : resolved;
            const note =
              typeof resolved === "object" ? resolved.note : entry.name;

            return (
              <div
                key={`${entry.dataKey || entry.name || "metric"}-${index}`}
                className="flex items-start justify-between gap-4 rounded-xl border border-slate-800/80 bg-slate-900/40 px-3 py-2"
              >
                <div className="flex items-start gap-2">
                  <span
                    className="mt-1.5 h-2.5 w-2.5 rounded-full shadow-[0_0_16px_currentColor]"
                    style={{
                      backgroundColor:
                        entry.color || entry.payload?.fill || "#22d3ee",
                      color: entry.color || entry.payload?.fill || "#22d3ee",
                    }}
                  />
                  <div>
                    <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500">
                      {entry.name || "Value"}
                    </p>
                    {note && (
                      <p className="mt-1 text-xs text-slate-300">{note}</p>
                    )}
                  </div>
                </div>
                <p className="text-right text-sm font-black tracking-tight text-slate-100">
                  {value}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default InsightTooltip;
