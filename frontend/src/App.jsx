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

  const mockData = [
    { id: "CVE-2023-44487", description: "HTTP/2 protocol allows a denial of service (server resource consumption).", score: 7.5, explanation: "High potential for DoS attacks; prioritize patching perimeter proxies." },
    { id: "CVE-2021-44228", description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.", score: 10.0, explanation: "Log4Shell: Critical RCE. Immediate mitigation required." },
    { id: "CVE-2024-21626", description: "runc container breakout vulnerability allowing environment escape.", score: 8.6, explanation: "High risk for containerized environments. Update runc immediately." },
    { id: "CVE-2020-1472", description: "Elevation of privilege via vulnerable Netlogon secure channel connection.", score: 10.0, explanation: "Zerologon: Critical risk to Active Directory infrastructure." },
    { id: "CVE-2023-38545", description: "SOCKS5 heap buffer overflow in curl and libcurl.", score: 5.3, explanation: "Medium risk. Update curl if SOCKS5 proxies are utilized." },
    { id: "CVE-2023-12345", description: "Minor information disclosure in legacy admin panel.", score: 3.2, explanation: "Low risk. Patch during the next standard maintenance window." }
  ];

  useEffect(() => {
    // Simulating API fetch
    setTimeout(() => {
      setCves(mockData);
      setLoading(false);
    }, 600);
  }, []);

  const getSeverityLabel = (score) => {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  };

  // Compute total stats (unfiltered) for the cards and chart
  const stats = useMemo(() => {
    return cves.reduce((acc, cve) => {
      const sev = getSeverityLabel(cve.score);
      if (sev === 'CRITICAL') acc.critical += 1;
      else if (sev === 'HIGH') acc.high += 1;
      else if (sev === 'MEDIUM') acc.medium += 1;
      else acc.low += 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
  }, [cves]);

  // Apply search text and active category filters
  const filteredCVEs = useMemo(() => {
    return cves.filter(cve => {
      const matchesSearch = cve.id.toLowerCase().includes(searchTerm.toLowerCase()) || 
                            cve.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesFilter = activeFilter ? getSeverityLabel(cve.score) === activeFilter : true;
      return matchesSearch && matchesFilter;
    });
  }, [cves, searchTerm, activeFilter]);

  if (loading) {
    return (
      <div className="flex flex-col justify-center items-center h-screen bg-slate-50">
        <Activity className="animate-pulse text-indigo-600 mb-4" size={48} />
        <p className="text-slate-600 font-medium animate-pulse">Initializing Threat Matrix...</p>
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
              placeholder="Search vulnerabilities..." 
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

        {/* Dashboard Grid (Cards + Chart) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <StatsCards 
              stats={stats} 
              activeFilter={activeFilter} 
              onFilterChange={setActiveFilter} 
            />
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