import React, { useState } from 'react';
import { Shield, Play, CheckCircle, Terminal, RefreshCcw, AlertCircle } from 'lucide-react';
import { respondToIncident } from '../services/api';

export const ResponseActions = ({ actions, incidentId }) => {
  const [simulatedActions, setSimulatedActions] = useState({});
  const [loadingActions, setLoadingActions] = useState({});
  const [actionErrors, setActionErrors] = useState({});

  const handleSimulateAction = async (actionId) => {
    if (loadingActions[actionId]) return;

    setLoadingActions(prev => ({ ...prev, [actionId]: true }));
    setActionErrors(prev => ({ ...prev, [actionId]: null }));

    try {
      const responseData = await respondToIncident(incidentId, actionId);
      setSimulatedActions(prev => ({
        ...prev,
        [actionId]: {
          status: responseData.status || 'SIMULATED',
          timestamp: responseData.executed_at
            ? new Date(responseData.executed_at).toLocaleTimeString()
            : new Date().toLocaleTimeString()
        }
      }));
    } catch (err) {
      setActionErrors(prev => ({
        ...prev,
        [actionId]: err.message || 'Execution failed'
      }));
    } finally {
      setLoadingActions(prev => ({ ...prev, [actionId]: false }));
    }
  };

  if (!actions || actions.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-5">
        <div className="flex items-center gap-2 mb-2 pb-2 border-b border-[#1F2937]">
          <Shield className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wide">
            Recommended Response Actions
          </h3>
        </div>
        <p className="text-xs text-gray-400 font-mono italic">
          No automated response actions required for this incident.
        </p>
      </div>
    );
  }

  const riskColors = {
    LOW: 'text-blue-400 bg-blue-950/60 border-blue-800',
    MEDIUM: 'text-amber-400 bg-amber-950/60 border-amber-800',
    HIGH: 'text-red-400 bg-red-950/60 border-red-800'
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-5">
      <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#1F2937]">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wide">
            Recommended Response Actions ({actions.length})
          </h3>
        </div>
        <span className="text-xs font-mono text-gray-400">
          MODE: SIMULATION ONLY
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {actions.map((act) => {
          const simState = simulatedActions[act.action_id];
          const isSimulated = !!simState;
          const isLoading = !!loadingActions[act.action_id];
          const actionError = actionErrors[act.action_id];

          return (
            <div
              key={act.action_id}
              className={`border rounded-lg p-4 flex flex-col justify-between transition-all ${
                isSimulated
                  ? 'bg-emerald-950/20 border-emerald-600/60 shadow-lg shadow-emerald-950/30'
                  : 'bg-[#182234]/60 border-[#1F2937] hover:border-gray-700'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-bold text-gray-400">
                    {act.action_id}
                  </span>
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${riskColors[act.risk_level] || riskColors.LOW}`}>
                    RISK: {act.risk_level}
                  </span>
                </div>

                <h4 className="text-sm font-bold text-gray-100 mb-1.5">
                  {act.title}
                </h4>

                <p className="text-xs text-gray-300 mb-3">
                  {act.description}
                </p>

                {act.automated_script && (
                  <div className="bg-black/60 p-2 rounded text-[11px] font-mono text-emerald-400 mb-3 border border-gray-800 flex items-center gap-1.5 overflow-x-auto">
                    <Terminal className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                    <code>{act.automated_script}</code>
                  </div>
                )}

                {actionError && (
                  <div className="bg-red-950/60 border border-red-800/80 rounded p-2 mb-3 text-[11px] font-mono text-red-300 flex items-start gap-1.5">
                    <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                    <span>{actionError}</span>
                  </div>
                )}
              </div>

              <div>
                {isSimulated ? (
                  <div className="flex items-center justify-between text-xs font-mono text-emerald-400 bg-emerald-950/50 p-2 rounded border border-emerald-800">
                    <span className="flex items-center gap-1.5 font-bold">
                      <CheckCircle className="w-4 h-4" />
                      SIMULATION COMPLETED
                    </span>
                    <span className="text-[10px] text-gray-400">{simState.timestamp}</span>
                  </div>
                ) : (
                  <button
                    onClick={() => handleSimulateAction(act.action_id)}
                    disabled={isLoading}
                    className={`w-full py-2 px-3 font-mono text-xs font-bold rounded flex items-center justify-center gap-2 transition-colors shadow-md ${
                      isLoading
                        ? 'bg-blue-950 text-blue-300 border border-blue-800 cursor-not-allowed'
                        : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-900/40'
                    }`}
                  >
                    {isLoading ? (
                      <>
                        <RefreshCcw className="w-3.5 h-3.5 animate-spin text-blue-300" />
                        <span>EXECUTING...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        <span>SIMULATE ACTION</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
