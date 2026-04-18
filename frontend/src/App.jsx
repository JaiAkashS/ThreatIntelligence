import React, { useState, useEffect, useMemo } from "react";
import { Search, Crosshair, Database, Fingerprint } from "lucide-react";
import StatsCards from "./components/StatsCards";
import RiskChart from "./components/RiskChart";
import TopThreatsChart from "./components/TopThreatsChart";
import FactorInsightsChart from "./components/FactorInsightsChart";
import CVETable from "./components/CVETable";

const App = () => {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [activeFilter, setActiveFilter] = useState(null);

  const mockData = [
    {
      id: "CVE-2024-001",
      risk_score: 9.5,
      priority: "CRITICAL",
      dominant_factor: "Active Public Exploit",
      factor_breakdown: { exploitability: 9.8, impact: 9.1, base_score: 9.5 },
      recommended_actions: ["Isolate affected subnet", "Apply emergency patch"],
      explainations: {
        summary:
          "Highly targeted vulnerability with weaponized exploits in the wild.",
      },
    },
    {
      id: "CVE-2024-002",
      risk_score: 7.8,
      priority: "HIGH",
      dominant_factor: "Network Vector",
      factor_breakdown: { exploitability: 7.2, impact: 8.4 },
      recommended_actions: [
        "Update firewall rules",
        "Monitor for anomalous traffic",
      ],
      explainations: {
        summary:
          "Remote code execution possible, but requires specific configuration.",
      },
    },
    {
      id: "CVE-2024-003",
      risk_score: 5.4,
      priority: "MEDIUM",
      dominant_factor: "Privilege Escalation",
      factor_breakdown: { exploitability: 4.1, impact: 6.2 },
      recommended_actions: [
        "Audit user permissions",
        "Patch during next maintenance window",
      ],
      explainations: {
        summary: "Local access required. Minimal risk to perimeter.",
      },
    },
  ];

  useEffect(() => {
    const fetchCVEs = async () => {
      try {
        setLoading(true);
        const response = await fetch("http://localhost:8000/cves");
        if (!response.ok) throw new Error("Network response was not ok");
        const data = await response.json();
        console.log("BACKEND DATA:", data.cves);
        setCves(data.cves);
      } catch (error) {
        setCves(mockData);
      } finally {
        setLoading(false);
      }
    };
    fetchCVEs();
  }, []);

  const stats = useMemo(() => {
    return cves.reduce(
      (acc, cve) => {
        const p = (cve.priority || "LOW").toUpperCase();
        if (p === "CRITICAL") acc.critical += 1;
        else if (p === "HIGH") acc.high += 1;
        else if (p === "MEDIUM") acc.medium += 1;
        else acc.low += 1;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 },
    );
  }, [cves]);

  const filteredCVEs = useMemo(() => {
    return cves.filter((cve) => {
      const searchStr =
        `${cve.id} ${cve.explainations?.summary} ${cve.dominant_factor}`.toLowerCase();
      const matchesSearch = searchStr.includes(searchTerm.toLowerCase());
      const matchesFilter = activeFilter
        ? (cve.priority || "").toUpperCase() === activeFilter
        : true;
      return matchesSearch && matchesFilter;
    });
  }, [cves, searchTerm, activeFilter]);

  const factorInsightsData = useMemo(() => {
    const factorMap = new Map();

    filteredCVEs.forEach((cve) => {
      const breakdown = cve.factor_breakdown || {};

      Object.entries(breakdown).forEach(([factor, value]) => {
        const contribution =
          typeof value === "number"
            ? value
            : Number(value?.contribution ?? value?.raw_value ?? 0);

        if (!Number.isFinite(contribution)) {
          return;
        }

        if (!factorMap.has(factor)) {
          factorMap.set(factor, { total: 0, count: 0 });
        }

        const current = factorMap.get(factor);
        current.total += contribution;
        current.count += 1;
      });
    });

    return [...factorMap.entries()]
      .map(([factor, aggregate]) => {
        const average = aggregate.count ? aggregate.total / aggregate.count : 0;
        return {
          factor,
          shortLabel: factor
            .replace(/_/g, " ")
            .split(" ")
            .map((token) => token[0]?.toUpperCase() || "")
            .join("")
            .slice(0, 4),
          value: Number(average.toFixed(1)),
        };
      })
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [filteredCVEs]);

  if (loading) {
    return (
      <div className="flex flex-col justify-center items-center h-screen bg-[#030712]">
        <div className="relative">
          <Crosshair
            className="animate-[spin_3s_linear_infinite] text-cyan-500 mb-6"
            size={64}
            strokeWidth={1}
          />
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
            <div className="w-2 h-2 bg-cyan-400 rounded-full animate-ping"></div>
          </div>
        </div>
        <p className="text-cyan-500/80 font-mono tracking-[0.3em] uppercase text-xs animate-pulse shadow-cyan-500 drop-shadow-md">
          Decrypting Threat Streams...
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#020617] bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(6,182,212,0.15),rgba(255,255,255,0))] text-slate-300 font-sans pb-16 selection:bg-cyan-900/50 selection:text-cyan-200">
      <nav className="bg-[#020617]/50 backdrop-blur-2xl border-b border-slate-800/80 sticky top-0 z-50 shadow-[0_4px_30px_rgba(0,0,0,0.5)]">
        <div className="max-w-[90rem] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative group cursor-pointer">
              <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-purple-600 rounded-xl blur opacity-60 group-hover:opacity-100 transition duration-500"></div>
              <div className="relative bg-[#020617] p-2.5 rounded-xl border border-slate-800">
                <Fingerprint size={24} className="text-cyan-400" />
              </div>
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-widest text-slate-200">
                NEXUS
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500">
                  AI
                </span>
              </h1>
              <p className="text-slate-500 text-[9px] font-mono uppercase tracking-[0.3em] mt-0.5">
                Advanced Threat Heuristics
              </p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-8 text-[11px] font-mono tracking-widest text-slate-400">
            <span className="flex items-center gap-2 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800">
              <div className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </div>
              NODE LINK SECURE
            </span>
            <span className="flex items-center gap-2 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800">
              <Database size={12} className="text-purple-400" />
              ML ENGINE ACTIVE
            </span>
          </div>
        </div>
      </nav>

      <div className="max-w-[90rem] mx-auto px-6 mt-10 space-y-8">
        <div className="flex flex-col md:flex-row justify-between items-center gap-4 bg-[#0f172a]/40 backdrop-blur-md p-2 pl-4 rounded-2xl border border-slate-800/80 shadow-[0_0_40px_rgba(0,0,0,0.3)] hover:border-slate-700/80 transition-all duration-300">
          <div className="relative w-full md:w-1/2 flex items-center">
            <Search className="absolute left-3 text-cyan-500/50" size={20} />
            <input
              type="text"
              placeholder="> Initiate manual query (CVE ID, Vector, Context)..."
              className="w-full pl-12 pr-4 py-3 bg-transparent border-none focus:outline-none focus:ring-0 text-slate-200 placeholder-slate-600 font-mono text-sm tracking-wide"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          {activeFilter && (
            <button
              onClick={() => setActiveFilter(null)}
              className="text-[10px] font-mono text-slate-400 hover:text-red-400 px-6 py-3 transition-colors tracking-widest uppercase bg-slate-900/80 rounded-xl border border-slate-800 hover:border-red-900/50"
            >
              [ Terminate Override ]
            </button>
          )}
        </div>

        {/* --- NEW LAYOUT: Cards and Pie Chart in one row --- */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          <div className="xl:col-span-8 w-full">
            <StatsCards
              stats={stats}
              activeFilter={activeFilter}
              onFilterChange={setActiveFilter}
            />
          </div>
          <div className="xl:col-span-4 w-full">
            <RiskChart stats={stats} />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <TopThreatsChart cves={filteredCVEs} />
          <FactorInsightsChart data={factorInsightsData} />
        </div>

        

        <CVETable cves={filteredCVEs} />
      </div>
    </div>
  );
};

export default App;
