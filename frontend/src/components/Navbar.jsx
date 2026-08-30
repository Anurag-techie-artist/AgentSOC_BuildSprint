import React from 'react';
import { Shield, Radio, Activity, RefreshCw } from 'lucide-react';

export const Navbar = ({ onRefresh, isLoading }) => {
  return (
    <header className="bg-[#111827] border-b border-[#1F2937] px-6 py-3.5 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-md shadow-blue-950">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-gray-100 uppercase">
              AgentSOC
            </h1>
            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              AUTONOMOUS SOC
            </span>
          </div>
          <p className="text-xs text-gray-400 font-mono">
            Autonomous Incident Investigation & Response Platform
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded bg-[#182234]/80 border border-[#1F2937] text-xs font-mono">
          <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span className="text-gray-300">AGENT STATUS:</span>
          <span className="text-emerald-400 font-bold">ONLINE (READY)</span>
        </div>

        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="p-2 rounded bg-[#182234] hover:bg-gray-800 border border-[#1F2937] text-gray-300 transition-colors flex items-center gap-2 text-xs font-mono"
          title="Refresh Data"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-blue-400' : ''}`} />
          <span className="hidden md:inline">REFRESH</span>
        </button>
      </div>
    </header>
  );
};
