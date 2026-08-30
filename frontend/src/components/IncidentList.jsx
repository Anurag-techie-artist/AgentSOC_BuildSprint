import React from 'react';
import { SeverityBadge } from './SeverityBadge';
import { AlertTriangle, Clock, Server, User, ShieldAlert } from 'lucide-react';

export const IncidentList = ({ incidents, selectedIncidentId, onSelectIncident }) => {
  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-lg overflow-hidden flex flex-col h-full">
      <div className="px-4 py-3 bg-[#1F2937]/50 border-b border-[#1F2937] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-blue-400" />
          <h2 className="text-sm font-semibold tracking-wide uppercase text-gray-200">
            Active Incidents ({incidents.length})
          </h2>
        </div>
        <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          LIVE FEED
        </span>
      </div>

      <div className="p-2 overflow-y-auto space-y-2 flex-1">
        {incidents.map((incident) => {
          const isSelected = incident.incident_id === selectedIncidentId;
          return (
            <button
              key={incident.incident_id}
              onClick={() => onSelectIncident(incident.incident_id)}
              className={`w-full text-left p-3 rounded-md transition-all border ${
                isSelected
                  ? 'bg-blue-950/40 border-blue-500/60 shadow-lg shadow-blue-950/50'
                  : 'bg-[#182234]/60 border-[#1F2937] hover:bg-[#1E293B] hover:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-xs font-semibold text-blue-400">
                  {incident.incident_id}
                </span>
                <SeverityBadge severity={incident.initial_severity} />
              </div>

              <h3 className="text-sm font-medium text-gray-100 line-clamp-2 mb-2">
                {incident.title}
              </h3>

              <div className="flex flex-wrap items-center gap-3 text-xs text-gray-400 font-mono">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3 text-gray-500" />
                  {new Date(incident.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3 text-gray-500" />
                  {incident.entities.hosts?.[0] || 'N/A'}
                </span>
                <span className="flex items-center gap-1">
                  <User className="w-3 h-3 text-gray-500" />
                  {incident.entities.users?.[0] || 'N/A'}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
