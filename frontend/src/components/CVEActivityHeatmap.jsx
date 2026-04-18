import React from "react";
import { CalendarDays } from "lucide-react";

const CELL_STYLES = [
  "bg-slate-900/70 border-slate-800 text-slate-600",
  "bg-cyan-950/70 border-cyan-900/60 text-cyan-300",
  "bg-cyan-900/80 border-cyan-700/70 text-cyan-200",
  "bg-sky-700/80 border-sky-500/70 text-white",
  "bg-red-600/85 border-red-400/80 text-white",
];

const WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

const getMonthStart = (dates) => {
  if (!dates.length) {
    const now = new Date();
    return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  }

  const latest = new Date(Math.max(...dates.map((date) => date.getTime())));
  return new Date(Date.UTC(latest.getUTCFullYear(), latest.getUTCMonth(), 1));
};

const normalizeDate = (value) => {
  if (!value) {
    return null;
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return new Date(
    Date.UTC(
      parsed.getUTCFullYear(),
      parsed.getUTCMonth(),
      parsed.getUTCDate(),
    ),
  );
};

const getIntensityClass = (count, maxCount) => {
  if (count <= 0 || maxCount <= 0) {
    return CELL_STYLES[0];
  }

  const ratio = count / maxCount;
  if (ratio >= 0.85) return CELL_STYLES[4];
  if (ratio >= 0.6) return CELL_STYLES[3];
  if (ratio >= 0.35) return CELL_STYLES[2];
  return CELL_STYLES[1];
};

const buildCalendarCells = (monthStart, countsByDay, maxCount) => {
  const year = monthStart.getUTCFullYear();
  const month = monthStart.getUTCMonth();
  const startWeekday = (monthStart.getUTCDay() + 6) % 7;
  const daysInMonth = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  const cells = [];

  for (let index = 0; index < startWeekday; index += 1) {
    cells.push({ key: `empty-start-${index}`, empty: true });
  }

  for (let day = 1; day <= daysInMonth; day += 1) {
    const key = `${year}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
    const count = countsByDay.get(key) || 0;
    cells.push({
      key,
      day,
      count,
      className: getIntensityClass(count, maxCount),
    });
  }

  while (cells.length % 7 !== 0) {
    cells.push({ key: `empty-end-${cells.length}`, empty: true });
  }

  return cells;
};

const CVEActivityHeatmap = ({ cves = [] }) => {
  const datedEntries = cves
    .map((cve) => ({
      id: cve.id,
      date: normalizeDate(cve.publish_date || cve.published || cve.date),
    }))
    .filter((entry) => entry.date);

  const dates = datedEntries.map((entry) => entry.date);
  const monthStart = getMonthStart(dates);
  const monthLabel = monthStart.toLocaleString("en-US", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });

  const countsByDay = datedEntries.reduce((map, entry) => {
    const key = entry.date.toISOString().slice(0, 10);
    map.set(key, (map.get(key) || 0) + 1);
    return map;
  }, new Map());

  const dailyCounts = [...countsByDay.values()];
  const maxCount = dailyCounts.length ? Math.max(...dailyCounts) : 0;
  const totalVisible = datedEntries.length;
  const activeDays = dailyCounts.filter((count) => count > 0).length;
  const calendarCells = buildCalendarCells(monthStart, countsByDay, maxCount);

  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-800/80 bg-[#0f172a]/40 p-6 shadow-[0_8px_30px_rgb(0,0,0,0.4)] backdrop-blur-xl">
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-transparent via-violet-500/30 to-transparent"></div>

      <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-[0.2em] text-slate-400">
            <CalendarDays size={14} className="text-violet-400" />
            CVE Activity Calendar
          </h3>
          <p className="mt-2 max-w-xl text-sm text-slate-400">
            Daily publication activity for the currently visible CVEs.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono uppercase tracking-[0.16em] text-slate-500">
          <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
            <span className="block text-slate-500">Month</span>
            <span className="mt-1 block text-sm font-bold normal-case tracking-normal text-slate-200">
              {monthLabel}
            </span>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
            <span className="block text-slate-500">Active Days</span>
            <span className="mt-1 block text-sm font-bold normal-case tracking-normal text-slate-200">
              {activeDays}
            </span>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
            <span className="block text-slate-500">Dated CVEs</span>
            <span className="mt-1 block text-sm font-bold normal-case tracking-normal text-slate-200">
              {totalVisible}
            </span>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
            <span className="block text-slate-500">Peak Day</span>
            <span className="mt-1 block text-sm font-bold normal-case tracking-normal text-slate-200">
              {maxCount || 0}
            </span>
          </div>
        </div>
      </div>

      {datedEntries.length ? (
        <>
          <div className="mb-3 grid grid-cols-7 gap-2">
            {WEEKDAY_LABELS.map((label) => (
              <div
                key={label}
                className="text-center text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500"
              >
                {label}
              </div>
            ))}
          </div>

          <div className="grid grid-cols-7 gap-2">
            {calendarCells.map((cell) => (
              <div
                key={cell.key}
                className={
                  cell.empty
                    ? "h-16 rounded-xl border border-transparent"
                    : `group relative h-16 rounded-xl border p-2 transition-transform duration-200 hover:-translate-y-0.5 ${cell.className}`
                }
              >
                {!cell.empty && (
                  <div className="flex h-full flex-col justify-between">
                    <span className="text-xs font-bold">{cell.day}</span>
                    <span className="text-[10px] font-mono uppercase tracking-[0.16em]">
                      {cell.count} hit{cell.count === 1 ? "" : "s"}
                    </span>
                  </div>
                )}
                {!cell.empty && (
                  <div className="pointer-events-none absolute bottom-[calc(100%+0.75rem)] left-1/2 z-20 w-44 -translate-x-1/2 rounded-2xl border border-slate-700/80 bg-[#020817]/95 p-3 opacity-0 shadow-[0_18px_50px_rgba(2,8,23,0.7)] backdrop-blur-xl transition-all duration-200 group-hover:translate-y-[-2px] group-hover:opacity-100">
                    <div className="absolute left-1/2 top-full h-3 w-3 -translate-x-1/2 -translate-y-1/2 rotate-45 border-b border-r border-slate-700/80 bg-[#020817]/95" />
                    <p className="text-[10px] font-mono uppercase tracking-[0.22em] text-slate-500">
                      Activity Day
                    </p>
                    <p className="mt-1 text-sm font-semibold text-slate-100">
                      {cell.key}
                    </p>
                    <div className="mt-3 rounded-xl border border-slate-800/80 bg-slate-900/40 px-3 py-2">
                      <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500">
                        Published CVEs
                      </p>
                      <p className="mt-1 text-sm font-black tracking-tight text-slate-100">
                        {cell.count}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="mt-5 flex items-center gap-3 text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500">
            <span>Low</span>
            {CELL_STYLES.map((style, index) => (
              <span
                key={style}
                className={`h-3 w-8 rounded-full border ${index === 0 ? CELL_STYLES[1] : style}`}
              />
            ))}
            <span>High</span>
          </div>
        </>
      ) : (
        <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-950/40 p-8 text-center">
          <p className="text-sm font-medium text-slate-300">
            No dated CVE records available for the calendar view yet.
          </p>
          <p className="mt-2 text-sm text-slate-500">
            Add a `published_date` field to your CVE dataset to activate daily
            activity tracking.
          </p>
        </div>
      )}
    </div>
  );
};

export default CVEActivityHeatmap;
