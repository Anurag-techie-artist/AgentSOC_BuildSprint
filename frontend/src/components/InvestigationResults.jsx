import React from 'react';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { Brain, FileSearch, ShieldCheck, Tag, Cpu, CheckCircle2 } from 'lucide-react';

export const InvestigationResults = ({ agentOutput }) => {
  if (!agentOutput) {
    return (
      <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 text-center text-gray-500 font-mono text-sm">
        No investigation results available for this incident.
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-5 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
        <div className="flex items-center gap-2">
          <Brain className="w-5 h-5 text-purple-400" />
          <h2 className="text-base font-bold text-gray-100 uppercase tracking-wide">
            Autonomous Agent Findings
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={agentOutput.assessed_severity} />
          <ConfidenceBadge score={agentOutput.confidence_score} />
        </div>
      </div>

      {/* Summary & Root Cause */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#182234]/60 border border-[#1F2937] rounded-md p-4">
          <div className="flex items-center gap-2 mb-2 text-blue-400 text-xs font-mono font-bold uppercase tracking-wider">
            <Cpu className="w-4 h-4" />
            Executive Summary
          </div>
          <p className="text-xs text-gray-300 leading-relaxed font-sans">
            {agentOutput.summary}
          </p>
        </div>

        <div className="bg-[#182234]/60 border border-[#1F2937] rounded-md p-4">
          <div className="flex items-center gap-2 mb-2 text-amber-400 text-xs font-mono font-bold uppercase tracking-wider">
            <FileSearch className="w-4 h-4" />
            Identified Root Cause
          </div>
          <p className="text-xs text-gray-300 leading-relaxed font-sans">
            {agentOutput.root_cause}
          </p>
        </div>
      </div>

      {/* MITRE Tactics */}
      {agentOutput.mitre_tactics && agentOutput.mitre_tactics.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2 text-xs font-mono font-bold text-gray-400 uppercase">
            <Tag className="w-4 h-4 text-purple-400" />
            Mapped MITRE ATT&CK Tactics
          </div>
          <div className="flex flex-wrap gap-2">
            {agentOutput.mitre_tactics.map((tactic, i) => (
              <span
                key={i}
                className="text-xs font-mono px-2.5 py-1 rounded bg-purple-950/60 border border-purple-800/60 text-purple-300"
              >
                {tactic}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Reasoning Steps */}
      {agentOutput.reasoning_steps && agentOutput.reasoning_steps.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3 text-xs font-mono font-bold text-gray-400 uppercase">
            <Brain className="w-4 h-4 text-emerald-400" />
            Agent Reasoning Sequence
          </div>
          <div className="space-y-2">
            {agentOutput.reasoning_steps.map((step) => (
              <div
                key={step.step}
                className="bg-[#182234]/40 border border-[#1F2937] rounded p-3 text-xs font-mono"
              >
                <div className="flex items-center gap-2 text-emerald-400 font-bold mb-1">
                  <span className="w-5 h-5 rounded bg-emerald-950 border border-emerald-800 flex items-center justify-center text-xs">
                    {step.step}
                  </span>
                  <span>{step.action}</span>
                </div>
                <p className="text-gray-300 pl-7 text-xs">{step.finding}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Evidence */}
      {agentOutput.evidence && agentOutput.evidence.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3 text-xs font-mono font-bold text-gray-400 uppercase">
            <ShieldCheck className="w-4 h-4 text-blue-400" />
            Correlated Evidence Artifacts
          </div>
          <div className="space-y-2">
            {agentOutput.evidence.map((ev, idx) => (
              <div
                key={idx}
                className="bg-[#182234]/40 border border-[#1F2937] rounded p-3 text-xs flex flex-col md:flex-row md:items-center justify-between gap-2"
              >
                <div>
                  <span className="text-gray-200 font-semibold block mb-0.5">
                    {ev.description}
                  </span>
                  <span className="text-gray-400 text-xs font-mono">
                    Relevance: {ev.relevance}
                  </span>
                </div>
                <span className="font-mono text-xs px-2.5 py-1 rounded bg-blue-950 text-blue-400 border border-blue-800 shrink-0 self-start md:self-auto">
                  EVENT: {ev.source_event_id}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
