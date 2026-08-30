import React from 'react';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { Server, User, Network, Calendar, ShieldCheck } from 'lucide-react';

export const IncidentDetail = ({ incident, agentOutput }) => {
  if (!incident) return null;

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-5 mb-5 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 mb-4 border-b border-[#1F2937]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-xs px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              {incident.incident_id}
            </span>
            <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-gray-800 text-gray-300">
              STATUS: {incident.status}
            </span>
          </div>
          <h1 className="text-xl font-bold text-gray-100">{incident.title}</h1>
        </div>

        <div className="flex items-center gap-3">
          <SeverityBadge severity={agentOutput?.assessed_severity || incident.initial_severity} />
          {agentOutput && <ConfidenceBadge score={agentOutput.confidence_score} />}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono bg-[#182234]/40 p-3 rounded-md border border-[#1F2937]">
        <div className="flex items-start gap-2">
          <Calendar className="w-4 h-4 text-gray-400 mt-0.5" />
          <div>
            <span className="text-gray-400 block">DETECTED AT</span>
            <span className="text-gray-200 font-semibold">{new Date(incident.created_at).toLocaleString()}</span>
          </div>
        </div>

        <div className="flex items-start gap-2">
          <Server className="w-4 h-4 text-gray-400 mt-0.5" />
          <div>
            <span className="text-gray-400 block">HOSTS</span>
            <span className="text-gray-200 font-semibold">{incident.entities.hosts.join(', ') || 'None'}</span>
          </div>
        </div>

        <div className="flex items-start gap-2">
          <User className="w-4 h-4 text-gray-400 mt-0.5" />
          <div>
            <span className="text-gray-400 block">USERS</span>
            <span className="text-gray-200 font-semibold">{incident.entities.users.join(', ') || 'None'}</span>
          </div>
        </div>

        <div className="flex items-start gap-2">
          <Network className="w-4 h-4 text-gray-400 mt-0.5" />
          <div>
            <span className="text-gray-400 block">SOURCE IP ADDRESSES</span>
            <span className="text-gray-200 font-semibold">{incident.entities.ip_addresses.join(', ') || 'None'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
