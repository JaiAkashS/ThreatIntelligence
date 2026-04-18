import React, { useState, useEffect, useMemo } from 'react';
import { Search, Activity, Server, Database } from 'lucide-react';
import StatsCards from './components/StatsCards';
import RiskChart from './components/RiskChart';
// import TopThreatsChart from './components/TopThreatsChart';
import CVETable from './components/CVETable';

const App = () => {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState(null);

  // Fallback data matching your exact backend schema
  const mockData = [
    {
      id: "CVE-2024-001",
      risk_score: 9.5,
      priority: "CRITICAL",
      dominant_factor: "Active Public Exploit",
      factor_breakdown: { exploitability: 9.8, impact: 9.1, base_score: 9.5 },
      recommended_actions: ["Isolate affected subnet", "Apply emergency patch"],
      explainations: { summary: "Highly targeted vulnerability with weaponized exploits in the wild." }
    },
    {
      id: "CVE-2024-002",
      risk_score: 7.8,
      priority: "HIGH",
      dominant_factor: "Network Vector",
      factor_breakdown: { exploitability: 7.2, impact: 8.4 },
      recommended_actions: ["Update firewall rules", "Monitor for anomalous traffic"],
      explainations: { summary: "Remote code execution possible, but requires specific configuration." }
    },
    {
      id: "CVE-2024-003",
      risk_score: 5.4,
      priority: "MEDIUM",
      dominant_factor: "Privilege Escalation",
      factor_breakdown: { exploitability: 4.1, impact: 6.2 },
      recommended_actions: ["Audit user permissions", "Patch during next maintenance window"],
      explainations: { summary: "Local access required. Minimal risk to perimeter." }
    }
  ];

  useEffect(() => {
    const fetchCVEs = async () => {
      try {
        setLoading(true);
        // Replace with your actual backend URL
        const response = await fetch('http://localhost:8000/cves');
        if (!response.ok) throw new Error("Network response was not ok");
        const data = await response.json();
        setCves(data);
      } catch (error) {
        console.error("Backend connection failed. Using fallback data.", error);
        setCves(mockData);
      } finally {
        setLoading(false);
      }
    };

    fetchCVEs();
  }, []);

  // Compute stats using the new backend 'priority' field
  const stats = useMemo(() => {
    return cves.reduce((acc, cve) => {
      const p = (cve.priority || 'LOW').toUpperCase(); 
      if (p === 'CRITICAL') acc.critical += 1;
      else if (p === 'HIGH') acc.high += 1;
      else if (p === 'MEDIUM') acc.medium += 1;
      else acc.low += 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
  }, [cves]);

  // Apply search filtering
  const filteredCVEs = useMemo(() => {
    return cves.filter(cve => {
      const searchStr = `${cve.id} ${cve.explainations?.summary} ${cve.dominant_factor}`.toLowerCase();
      const matchesSearch = searchStr.includes(searchTerm.toLowerCase());
      const matchesFilter = activeFilter ? (cve.priority || '').toUpperCase() === activeFilter : true;
      return matchesSearch && matchesFilter;
    });
  }, [cves, searchTerm, activeFilter]);

  if (loading) {
    return (
      <div className="flex flex-col justify-center items-center h-screen bg-slate-50">
        <Activity className="animate-pulse text-indigo-600 mb-4" size={48} />
        <p className="text-slate-600 font-medium animate-pulse">Fetching Threat Data...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 font-sans pb-12">
      {/* Navigation */}
      <nav className="bg-slate-900 text-white shadow-md">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-indigo-600 p-2 rounded-lg">
              <Activity size={24} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-wide">NexusAI Security</h1>
              <p className="text-slate-400 text-xs uppercase tracking-wider">Threat Prioritization Dashboard</p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-4 text-sm font-medium text-slate-300">
            <span className="flex items-center gap-2"><Server size={16} /> API Connected</span>
            <span className="flex items-center gap-2"><Database size={16} /> Model Active</span>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 mt-8 space-y-6">
        
        {/* Search Bar */}
        <div className="flex flex-col md:flex-row justify-between items-center gap-4 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <div className="relative w-full md:w-96">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" size={20} />
            <input 
              type="text" 
              placeholder="Search threat context or ID..." 
              className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition-all"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          {activeFilter && (
            <button 
              onClick={() => setActiveFilter(null)}
              className="text-sm text-slate-500 hover:text-indigo-600 font-medium px-4 py-2 transition-colors"
            >
              Clear Filters
            </button>
          )}
        </div>

        {/* Top Row: Stats Cards */}
        <div className="w-full">
          <StatsCards stats={stats} activeFilter={activeFilter} onFilterChange={setActiveFilter} />
        </div>

        {/* Middle Row: Dual Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <RiskChart stats={stats} />
          {/* <TopThreatsChart cves={filteredCVEs} /> */}
        </div>

        {/* Bottom Row: Data Table with Expandable Rows */}
        <CVETable cves={filteredCVEs} />

      </div>
    </div>
  );
};

export default App;