import React, { useState, useEffect, useMemo } from 'react';
import { Search, Activity, Server, Database } from 'lucide-react';
import StatsCards from './components/StatsCards';
import RiskChart from './components/RiskChart';
import CVETable from './components/CVETable';

const App = () => {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState(null);

  useEffect(() => {
    const fetchCVEs = async () => {
      try {
        setLoading(true);
        // Point this to your actual backend URL
        const response = await fetch('http://localhost:8000/cves');
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        setCves(data);
      } catch (error) {
        console.error("Backend connection failed. Check CORS and server status.", error);
      } finally {
        setLoading(false);
      }
    };

    fetchCVEs();
  }, []);

  const getSeverityLabel = (score) => {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  };

  // Compute total stats (unfiltered) using the new 'cvss' key
  const stats = useMemo(() => {
    return cves.reduce((acc, cve) => {
      const sev = getSeverityLabel(cve.cvss);
      if (sev === 'CRITICAL') acc.critical += 1;
      else if (sev === 'HIGH') acc.high += 1;
      else if (sev === 'MEDIUM') acc.medium += 1;
      else acc.low += 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
  }, [cves]);

  // Apply search text and active category filters using 'desc' and 'cvss'
  const filteredCVEs = useMemo(() => {
    return cves.filter(cve => {
      const matchesSearch = cve.id.toLowerCase().includes(searchTerm.toLowerCase()) || 
                            cve.desc.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesFilter = activeFilter ? getSeverityLabel(cve.cvss) === activeFilter : true;
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
        {/* Search & Filter Controls */}
        <div className="flex flex-col md:flex-row justify-between items-center gap-4 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <div className="relative w-full md:w-96">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" size={20} />
            <input 
              type="text" 
              placeholder="Search ID or description..." 
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

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <StatsCards stats={stats} activeFilter={activeFilter} onFilterChange={setActiveFilter} />
          </div>
          <div className="lg:col-span-1">
            <RiskChart stats={stats} />
          </div>
        </div>

        {/* Table Component */}
        <CVETable cves={filteredCVEs} />
      </div>
    </div>
  );
};

export default App;