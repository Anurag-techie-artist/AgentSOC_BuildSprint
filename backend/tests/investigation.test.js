const request = require('supertest');
const app = require('../src/app');
const eventService = require('../src/services/event.service');
const incidentService = require('../src/services/incident.service');
const agentAdapter = require('../src/services/agent.adapter');
const realAgent = require('../src/services/real.agent');
const mockAgent = require('../src/services/mock.agent');

const attackEvents = [
  {
    event_id: 'EVT-INV-1001',
    timestamp: '2026-08-29T10:00:00Z',
    source: 'auth.log',
    event_type: 'ssh_login_failure',
    severity: 'LOW',
    host: 'srv-prod-db01',
    user: 'root',
    ip_address: '192.168.1.105',
    raw_data: { port: 22, failure_reason: 'Invalid password', attempts: 1 }
  },
  {
    event_id: 'EVT-INV-1002',
    timestamp: '2026-08-29T10:00:05Z',
    source: 'auth.log',
    event_type: 'ssh_login_failure',
    severity: 'LOW',
    host: 'srv-prod-db01',
    user: 'root',
    ip_address: '192.168.1.105',
    raw_data: { port: 22, failure_reason: 'Invalid password', attempts: 5 }
  },
  {
    event_id: 'EVT-INV-1003',
    timestamp: '2026-08-29T10:00:12Z',
    source: 'auth.log',
    event_type: 'ssh_login_success',
    severity: 'HIGH',
    host: 'srv-prod-db01',
    user: 'admin_user',
    ip_address: '192.168.1.105',
    raw_data: { port: 22, auth_method: 'publickey_and_password' }
  },
  {
    event_id: 'EVT-INV-1004',
    timestamp: '2026-08-29T10:01:00Z',
    source: 'syslog',
    event_type: 'sudo_command_execution',
    severity: 'CRITICAL',
    host: 'srv-prod-db01',
    user: 'admin_user',
    ip_address: '192.168.1.105',
    raw_data: { command: '/usr/bin/cat /etc/shadow', elevated_user: 'root' }
  }
];

describe('POST /api/v1/incidents/:incident_id/investigate', () => {
  let createdIncident;

  beforeEach(async () => {
    eventService.clearEvents();
    incidentService.clearIncidents();

    // End-to-end setup: ingest events and correlate
    for (const evt of attackEvents) {
      await request(app).post('/api/v1/events/ingest').send(evt);
    }
    const correlated = incidentService.correlateEvents();
    createdIncident = correlated[0];
  });

  it('1. Successful investigation returns 200 and valid AgentOutput', async () => {
    const res = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('success');

    const output = res.body.data;
    expect(output.incident_id).toBe(createdIncident.incident_id);
    expect(output.summary).toBeDefined();
    expect(output.root_cause).toBeDefined();
    expect(output.assessed_severity).toBeDefined();
    expect(output.confidence_score).toBeGreaterThan(0);
    expect(Array.isArray(output.mitre_tactics)).toBe(true);
    expect(Array.isArray(output.reasoning_steps)).toBe(true);
    expect(Array.isArray(output.evidence)).toBe(true);
    expect(Array.isArray(output.response_actions)).toBe(true);
  });

  it('2. Returned AgentOutput passes agent_output.json schema validation', async () => {
    const res = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    expect(() => agentAdapter.validateOutput(res.body.data)).not.toThrow();
  });

  it('3. Investigation of a missing incident returns 404', async () => {
    const res = await request(app)
      .post('/api/v1/incidents/INC-9999-9999/investigate');

    expect(res.statusCode).toBe(404);
    expect(res.body.error.message).toBe('Incident not found');
  });

  it('4. Stored investigation result can be retrieved via GET /api/v1/incidents/:incident_id/investigation', async () => {
    // Before investigation -> 404
    let getRes = await request(app)
      .get(`/api/v1/incidents/${createdIncident.incident_id}/investigation`);
    expect(getRes.statusCode).toBe(404);

    // Run investigation
    await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    // After investigation -> 200 with stored result
    getRes = await request(app)
      .get(`/api/v1/incidents/${createdIncident.incident_id}/investigation`);
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.data.incident_id).toBe(createdIncident.incident_id);
  });

  it('5. Re-investigating an incident updates stored result without duplicates', async () => {
    await request(app).post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);
    await request(app).post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    const inc = incidentService.getIncidentById(createdIncident.incident_id);
    expect(inc.investigation_result).toBeDefined();
    expect(inc.status).toBe('INVESTIGATING');
  });

  it('6. REAL Agent E2E: HTTP POST /investigate invokes REAL Python Agent, not Mock Agent', async () => {
    const realAgentSpy = jest.spyOn(realAgent, 'runInvestigation');
    const mockAgentSpy = jest.spyOn(mockAgent, 'runInvestigation');

    try {
      const res = await request(app)
        .post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');

      // Prove that RealAgent (python runner) was invoked
      expect(realAgentSpy).toHaveBeenCalledTimes(1);
      expect(mockAgentSpy).not.toHaveBeenCalled();

      // Validate returned AgentOutput against schema
      expect(() => agentAdapter.validateOutput(res.body.data)).not.toThrow();
      expect(res.body.data.incident_id).toBe(createdIncident.incident_id);
      expect(res.body.data.summary).toBeDefined();
    } finally {
      realAgentSpy.mockRestore();
      mockAgentSpy.mockRestore();
    }
  });
});
