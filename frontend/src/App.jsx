import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { IncidentList } from './components/IncidentList';
import { IncidentDetail } from './components/IncidentDetail';
import { IncidentTimeline } from './components/IncidentTimeline';
import { InvestigationResults } from './components/InvestigationResults';
import { ResponseActions } from './components/ResponseActions';
import { fetchIncidents, fetchIncidentById, fetchEvents, investigateIncident } from './services/api';
import { mockEventsMap, mockAgentOutputs } from './data/mockData';
import { ShieldAlert, AlertCircle, RefreshCcw, Inbox } from 'lucide-react';

export function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncidentDetail, setSelectedIncidentDetail] = useState(null);
  const [realEvents, setRealEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [error, setError] = useState(null);

  const loadData = async (showLoading = true) => {
    if (showLoading) {
      setIsLoading(true);
      setError(null);
    }
    try {
      const data = await fetchIncidents();
      setIncidents(data);
      if (data && data.length > 0) {
        setSelectedIncidentId(prev => prev || data[0].incident_id);
      } else {
        setSelectedIncidentId(null);
        setSelectedIncidentDetail(null);
      }
    } catch (err) {
      if (showLoading) {
        setError(err.message || 'Failed to connect to backend incident API');
        setIncidents([]);
        setSelectedIncidentId(null);
        setSelectedIncidentDetail(null);
      }
    } finally {
      if (showLoading) {
        setIsLoading(false);
      }
    }
  };

  useEffect(() => {
    loadData(true);

    const interval = setInterval(() => {
      loadData(false);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  // Fetch detailed incident & associated real events when selectedIncidentId changes
  useEffect(() => {
    if (!selectedIncidentId) {
      setSelectedIncidentDetail(null);
      setRealEvents([]);
      return;
    }

    let isMounted = true;
    const loadIncidentDetail = async () => {
      setIsDetailLoading(true);
      try {
        const [detail, events] = await Promise.all([
          fetchIncidentById(selectedIncidentId),
          fetchEvents()
        ]);
        if (isMounted) {
          setSelectedIncidentDetail(detail);
          setRealEvents(events);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message || `Failed to fetch incident details for ${selectedIncidentId}`);
        }
      } finally {
        if (isMounted) {
          setIsDetailLoading(false);
        }
      }
    };

    loadIncidentDetail();

    return () => {
      isMounted = false;
    };
  }, [selectedIncidentId]);

  const handleRunInvestigation = async () => {
    if (!selectedIncidentId || isInvestigating) return;

    setIsInvestigating(true);
    setError(null);
    try {
      const agentOutput = await investigateIncident(selectedIncidentId);
      // Immediately update selected incident detail with returned investigation result
      setSelectedIncidentDetail(prev => ({
        ...prev,
        status: 'INVESTIGATING',
        investigation_result: agentOutput
      }));
    } catch (err) {
      setError(err.message || 'Investigation execution failed');
    } finally {
      setIsInvestigating(false);
    }
  };

  const selectedIncident = selectedIncidentDetail || incidents.find(inc => inc.incident_id === selectedIncidentId);

  // Filter real events associated with this incident, or fallback to mock map if events list is empty
  const incidentEventIds = selectedIncident?.event_ids || [];
  const associatedRealEvents = realEvents.filter(e => incidentEventIds.includes(e.event_id));
  const selectedEvents = associatedRealEvents.length > 0
    ? associatedRealEvents
    : (selectedIncidentId ? mockEventsMap[selectedIncidentId] || [] : []);

  // Use backend investigation_result if present, otherwise fallback to mock for reference
  const selectedAgentOutput = selectedIncident?.investigation_result || (selectedIncidentId ? mockAgentOutputs[selectedIncidentId] : null);

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col font-sans">
      <Navbar onRefresh={loadData} isLoading={isLoading} />

      <main className="flex-1 p-4 md:p-6 max-w-7xl w-full mx-auto">
        {/* Loading State */}
        {isLoading && (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <RefreshCcw className="w-8 h-8 text-blue-500 animate-spin" />
            <p className="font-mono text-sm text-gray-400">Loading AgentSOC Security Dashboard...</p>
          </div>
        )}

        {/* Error State */}
        {!isLoading && error && (
          <div className="bg-red-950/40 border border-red-800 rounded-lg p-6 my-10 flex items-center gap-4 text-red-200">
            <AlertCircle className="w-8 h-8 text-red-400 shrink-0" />
            <div>
              <h3 className="font-bold text-sm uppercase font-mono">System Error</h3>
              <p className="text-xs text-red-300">{error}</p>
            </div>
            <button
              onClick={loadData}
              className="ml-auto px-3 py-1.5 bg-red-900 hover:bg-red-800 text-xs font-mono rounded"
            >
              Retry
            </button>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && !error && incidents.length === 0 && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-12 text-center my-10">
            <Inbox className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <h3 className="text-base font-bold text-gray-300 font-mono uppercase">No Active Incidents</h3>
            <p className="text-xs text-gray-500 font-mono mt-1">
              All systems operating within normal security parameters.
            </p>
          </div>
        )}

        {/* Selected Incident State */}
        {!isLoading && !error && incidents.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left sidebar - Incident List */}
            <div className="lg:col-span-4 h-[calc(100vh-120px)] sticky top-20">
              <IncidentList
                incidents={incidents}
                selectedIncidentId={selectedIncidentId}
                onSelectIncident={(id) => setSelectedIncidentId(id)}
              />
            </div>

            {/* Right main area - Incident Detail & Findings */}
            <div className="lg:col-span-8 space-y-6">
              {isDetailLoading && (
                <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-12 text-center text-gray-400 font-mono flex items-center justify-center gap-2">
                  <RefreshCcw className="w-5 h-5 text-blue-400 animate-spin" />
                  <span>Loading incident details...</span>
                </div>
              )}

              {!isDetailLoading && selectedIncident ? (
                <>
                  <IncidentDetail
                    incident={selectedIncident}
                    agentOutput={selectedAgentOutput}
                    onInvestigate={handleRunInvestigation}
                    isInvestigating={isInvestigating}
                  />

                  <InvestigationResults
                    agentOutput={selectedAgentOutput}
                  />

                  <ResponseActions
                    actions={selectedAgentOutput?.response_actions}
                    incidentId={selectedIncident.incident_id}
                  />

                  <IncidentTimeline
                    events={selectedEvents}
                  />
                </>
              ) : (
                !isDetailLoading && (
                  <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-12 text-center text-gray-500 font-mono">
                    Select an incident from the list to inspect details.
                  </div>
                )
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
