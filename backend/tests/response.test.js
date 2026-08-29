const request = require('supertest');
const app = require('../src/app');
const eventService = require('../src/services/event.service');
const incidentService = require('../src/services/incident.service');

const attackEvents = [
  {
    event_id: 'EVT-RESP-1001',
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
    event_id: 'EVT-RESP-1002',
    timestamp: '2026-08-29T10:00:12Z',
    source: 'auth.log',
    event_type: 'ssh_login_success',
    severity: 'HIGH',
    host: 'srv-prod-db01',
    user: 'admin_user',
    ip_address: '192.168.1.105',
    raw_data: { port: 22, auth_method: 'publickey_and_password' }
  }
];

describe('POST /api/v1/incidents/:incident_id/respond', () => {
  let createdIncident;

  beforeEach(async () => {
    eventService.clearEvents();
    incidentService.clearIncidents();

    for (const evt of attackEvents) {
      await request(app).post('/api/v1/events/ingest').send(evt);
    }
    const correlated = incidentService.correlateEvents();
    createdIncident = correlated[0];
  });

  it('1. Valid response action is simulated successfully', async () => {
    // Run investigation first
    await request(app).post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    const res = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/respond`)
      .send({ action_id: 'ACT-001' });

    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('success');

    const data = res.body.data;
    expect(data.incident_id).toBe(createdIncident.incident_id);
    expect(data.action_id).toBe('ACT-001');
    expect(data.title).toContain('Block IP address');
    expect(data.status).toBe('SIMULATED');
    expect(data.executed_at).toBeDefined();
  });

  it('2. Missing incident returns 404', async () => {
    const res = await request(app)
      .post('/api/v1/incidents/INC-9999-9999/respond')
      .send({ action_id: 'ACT-001' });

    expect(res.statusCode).toBe(404);
    expect(res.body.error.message).toBe('Incident not found');
  });

  it('3. Incident with no investigation cannot be responded to (returns 409)', async () => {
    const res = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/respond`)
      .send({ action_id: 'ACT-001' });

    expect(res.statusCode).toBe(409);
    expect(res.body.error.message).toContain('must be investigated before responding');
  });

  it('4. Unknown action_id returns 400', async () => {
    await request(app).post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    const res = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/respond`)
      .send({ action_id: 'ACT-INVALID-999' });

    expect(res.statusCode).toBe(400);
    expect(res.body.error.message).toContain("Unknown response action_id 'ACT-INVALID-999'");
  });

  it('5. Repeated response does not create duplicate state', async () => {
    await request(app).post(`/api/v1/incidents/${createdIncident.incident_id}/investigate`);

    const res1 = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/respond`)
      .send({ action_id: 'ACT-001' });

    const res2 = await request(app)
      .post(`/api/v1/incidents/${createdIncident.incident_id}/respond`)
      .send({ action_id: 'ACT-001' });

    expect(res1.statusCode).toBe(200);
    expect(res2.statusCode).toBe(200);

    const inc = incidentService.getIncidentById(createdIncident.incident_id);
    expect(inc.responses.size).toBe(1);
    expect(inc.status).toBe('RESOLVED');
  });
});
