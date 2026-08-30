import React from 'react';
import { SeverityBadge } from './SeverityBadge';
import { Activity, Clock, Terminal, User, Server, Globe } from 'lucide-react';

export const IncidentTimeline = ({ events }) => {
  if (!events || events.length === 0) {
    return (
      <div className="p-4 text-xs text-gray-500 font-mono italic">
        No security events recorded for this incident.
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-5">
      <div className="flex items-center gap-2 mb-4 pb-2 border-b border-[#1F2937]">
        <Activity className="w-4 h-4 text-blue-400" />
        <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wide">
          Event Chronology Timeline ({events.length})
        </h3>
      </div>

      <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1F2937]">
        {events.map((evt, idx) => (
          <div key={evt.event_id} className="relative group">
            {/* Timeline node */}
            <div className="absolute -left-6 top-1.5 w-3 h-3 rounded-full bg-blue-500 border-2 border-[#111827] group-hover:scale-125 transition-transform" />

            <div className="bg-[#182234]/60 border border-[#1F2937] rounded-md p-3 hover:border-gray-700 transition-colors">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-blue-400 font-bold">
                    {evt.event_id}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">
                    {evt.event_type}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 font-mono flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </span>
                  <SeverityBadge severity={evt.severity} />
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono text-gray-400 my-2 bg-[#0B0F19]/40 p-2 rounded">
                <span className="flex items-center gap-1">
                  <Terminal className="w-3 h-3 text-gray-500" />
                  {evt.source}
                </span>
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3 text-gray-500" />
                  {evt.host}
                </span>
                <span className="flex items-center gap-1">
                  <User className="w-3 h-3 text-gray-500" />
                  {evt.user}
                </span>
                <span className="flex items-center gap-1">
                  <Globe className="w-3 h-3 text-gray-500" />
                  {evt.ip_address}
                </span>
              </div>

              {evt.raw_data && (
                <div className="mt-2 text-xs font-mono bg-black/40 text-emerald-400 p-2 rounded border border-gray-800/80 overflow-x-auto">
                  <span className="text-gray-500 block mb-0.5">RAW DATA:</span>
                  <code>{JSON.stringify(evt.raw_data, null, 2)}</code>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
