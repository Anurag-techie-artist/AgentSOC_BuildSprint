const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const eventService = require('./event.service');
const agentAdapter = require('./agent.adapter');
const { incidentSchema } = require('../models/schemas');

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
const validateIncident = ajv.compile(incidentSchema);

const CORRELATION_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

class IncidentService {
  constructor() {
    this.incidents = new Map();
    this.incidentCounter = 1;
  }

  getAllIncidents() {
    return Array.from(this.incidents.values());
  }

  getIncidentById(incidentId) {
    return this.incidents.get(incidentId) || null;
  }

  createIncident(incidentData) {
    if (this.incidents.has(incidentData.incident_id)) {
      throw new Error(`Incident with ID ${incidentData.incident_id} already exists`);
    }

    const isValid = validateIncident(incidentData);
    if (!isValid) {
      const errors = validateIncident.errors.map(err => `${err.instancePath} ${err.message}`).join(', ');
      throw new Error(`Incident Validation Error: ${errors}`);
    }

    this.incidents.set(incidentData.incident_id, incidentData);
    return incidentData;
  }

  /**
   * Run investigation for an existing incident using AgentAdapter.
   */
  async investigateIncident(incidentId) {
    const incident = this.getIncidentById(incidentId);
    if (!incident) {
      const error = new Error('Incident not found');
      error.statusCode = 404;
      throw error;
    }

    // Load associated security events from eventService
    const events = incident.event_ids
      .map(id => eventService.getEventById(id))
      .filter(Boolean);

    // Construct AgentInput
    const agentInput = {
      incident_id: incident.incident_id,
      title: incident.title,
      created_at: incident.created_at,
      initial_severity: incident.initial_severity,
      entities: incident.entities,
      events
    };

    // Invoke Agent Adapter (which runs Mock Agent / real agent)
    const agentOutput = await agentAdapter.analyzeIncident(agentInput);

    // Update incident in-memory storage with investigation result
    incident.investigation_result = agentOutput;
    incident.status = 'INVESTIGATING';
    incident.updated_at = new Date().toISOString();

    this.incidents.set(incidentId, incident);

    return agentOutput;
  }

  /**
   * Get stored investigation result for an incident.
   */
  getInvestigation(incidentId) {
    const incident = this.getIncidentById(incidentId);
    if (!incident) {
      const error = new Error('Incident not found');
      error.statusCode = 404;
      throw error;
    }

    if (!incident.investigation_result) {
      const error = new Error('No investigation result found for this incident');
      error.statusCode = 404;
      throw error;
    }

    return incident.investigation_result;
  }

  /**
   * Correlate events based on 5-min time windowing and suspicious sequence rules.
   */
  correlateEvents(eventsToCorrelate = null) {
    const events = eventsToCorrelate || eventService.getAllEvents();
    if (!events || events.length === 0) {
      return [];
    }

    // Sort events chronologically
    const sortedEvents = [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // Group events by shared key (host or IP)
    const entityGroups = new Map();
    for (const event of sortedEvents) {
      const key = event.host || event.ip_address || 'unknown';
      if (!entityGroups.has(key)) {
        entityGroups.set(key, []);
      }
      entityGroups.get(key).push(event);
    }

    // Window each entity group into clusters where adjacent events are within 5 minutes of each other
    const clusters = [];
    for (const [key, groupEvents] of entityGroups.entries()) {
      let currentCluster = [];
      for (const event of groupEvents) {
        if (currentCluster.length === 0) {
          currentCluster.push(event);
        } else {
          const lastEventTime = new Date(currentCluster[currentCluster.length - 1].timestamp).getTime();
          const currentEventTime = new Date(event.timestamp).getTime();
          if (currentEventTime - lastEventTime <= CORRELATION_WINDOW_MS) {
            currentCluster.push(event);
          } else {
            clusters.push({ key, events: currentCluster });
            currentCluster = [event];
          }
        }
      }
      if (currentCluster.length > 0) {
        clusters.push({ key, events: currentCluster });
      }
    }

    const createdIncidents = [];

    for (const { key, events: clusterEvents } of clusters) {
      // Rule 2: Suspicious sequence checks
      const hasHighOrCritical = clusterEvents.some(e => e.severity === 'HIGH' || e.severity === 'CRITICAL');
      const hasFailedLogin = clusterEvents.some(e => e.event_type === 'ssh_login_failure');
      const hasSuccessLogin = clusterEvents.some(e => e.event_type === 'ssh_login_success');
      const hasSudo = clusterEvents.some(e => e.event_type === 'sudo_command_execution' || e.severity === 'CRITICAL');

      const isBruteForceSequence = hasFailedLogin && hasSuccessLogin;
      const isPrivilegeEscalationSequence = (hasSuccessLogin || hasFailedLogin) && hasSudo;
      const isSuspicious = hasHighOrCritical || isBruteForceSequence || isPrivilegeEscalationSequence;

      // Rule 3: Benign safety - skip if not meeting suspicious sequence criteria
      if (!isSuspicious) {
        continue;
      }

      const clusterEventIds = clusterEvents.map(e => e.event_id);

      // Rule 5: Duplicate protection
      // Check if any existing incident already covers all these event IDs or overlaps completely
      const existing = Array.from(this.incidents.values()).find(inc =>
        clusterEventIds.every(id => inc.event_ids.includes(id)) ||
        inc.event_ids.every(id => clusterEventIds.includes(id))
      );

      if (existing) {
        continue;
      }

      // Extract unique entities
      const hosts = Array.from(new Set(clusterEvents.map(e => e.host).filter(Boolean)));
      const users = Array.from(new Set(clusterEvents.map(e => e.user).filter(Boolean)));
      const ip_addresses = Array.from(new Set(clusterEvents.map(e => e.ip_address).filter(Boolean)));

      // Highest severity in cluster
      const severityLevels = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
      let maxSev = 'LOW';
      for (const e of clusterEvents) {
        if ((severityLevels[e.severity] || 0) > (severityLevels[maxSev] || 0)) {
          maxSev = e.severity;
        }
      }

      const timestamps = clusterEvents.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t));
      const latestTime = timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : new Date().toISOString();

      const incidentId = `INC-${new Date().getFullYear()}-${String(this.incidentCounter++).padStart(4, '0')}`;
      const title = `Correlated Security Activity on ${key}`;

      const incident = {
        incident_id: incidentId,
        title,
        status: 'OPEN',
        created_at: latestTime,
        updated_at: latestTime,
        initial_severity: maxSev,
        entities: {
          hosts,
          users,
          ip_addresses
        },
        event_ids: clusterEventIds,
        investigation_result: null
      };

      this.createIncident(incident);
      createdIncidents.push(incident);
    }

    return createdIncidents;
  }

  clearIncidents() {
    this.incidents.clear();
    this.incidentCounter = 1;
  }
}

module.exports = new IncidentService();
