const request = require('supertest');
const app = require('../src/app');
const eventService = require('../src/services/event.service');
const incidentService = require('../src/services/incident.service');

const attackEvents = [
  {
    event_id: 'EVT-CORR-1001',
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
    event_id: 'EVT-CORR-1002',
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
    event_id: 'EVT-CORR-1003',
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
    event_id: 'EVT-CORR-1004',
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

const benignEvent = {
  event_id: 'EVT-BENIGN-001',
  timestamp: '2026-08-29T10:05:00Z',
  source: 'auth.log',
  event_type: 'ssh_login_success',
  severity: 'LOW',
  host: 'srv-workstation-01',
  user: 'alice',
  ip_address: '10.0.0.12',
  raw_data: { port: 22 }
};

const distantTimeEvent = {
  event_id: 'EVT-DISTANT-001',
  timestamp: '2026-08-29T12:00:00Z', // 2 hours later
  source: 'auth.log',
  event_type: 'ssh_login_failure',
  severity: 'LOW',
  host: 'srv-prod-db01',
  user: 'bob',
  ip_address: '192.168.1.105',
  raw_data: { port: 22 }
};

const unrelatedMediumEvents = [
  {
    event_id: 'EVT-MED-001',
    timestamp: '2026-08-29T14:00:00Z',
    source: 'syslog',
    event_type: 'config_change',
    severity: 'MEDIUM',
    host: 'srv-web-01',
    user: 'charlie',
    ip_address: '10.0.0.50',
    raw_data: { setting: 'timeout' }
  },
  {
    event_id: 'EVT-MED-002',
    timestamp: '2026-08-29T14:01:00Z',
    source: 'syslog',
    event_type: 'service_restart',
    severity: 'MEDIUM',
    host: 'srv-web-01',
    user: 'charlie',
    ip_address: '10.0.0.50',
    raw_data: { service: 'nginx' }
  }
];

describe('Incident API and Correlation', () => {
  beforeEach(() => {
    eventService.clearEvents();
    incidentService.clearIncidents();
  });

  it('1. Existing attack sequence -> exactly one CRITICAL incident', () => {
    for (const evt of attackEvents) {
      eventService.createEvent(evt);
    }

    const created = incidentService.correlateEvents();
    expect(created.length).toBe(1);

    const inc = created[0];
    expect(inc.incident_id).toMatch(/^INC-\d{4}-\d{4}$/);
    expect(inc.initial_severity).toBe('CRITICAL');
    expect(inc.entities.hosts).toContain('srv-prod-db01');
    expect(inc.entities.users).toContain('root');
    expect(inc.entities.users).toContain('admin_user');
    expect(inc.entities.ip_addresses).toContain('192.168.1.105');
    expect(inc.event_ids).toHaveLength(4);
    expect(inc.status).toBe('OPEN');
    expect(inc.investigation_result).toBeNull();
  });

  it('2. Single benign LOW event -> zero incidents', () => {
    eventService.createEvent(benignEvent);

    const created = incidentService.correlateEvents();
    expect(created.length).toBe(0);

    const allIncidents = incidentService.getAllIncidents();
    expect(allIncidents.length).toBe(0);
  });

  it('3. Unrelated events on same host outside 5-min time window should not be correlated into attack incident', () => {
    for (const evt of attackEvents) {
      eventService.createEvent(evt);
    }
    eventService.createEvent(distantTimeEvent);

    const created = incidentService.correlateEvents();
    expect(created.length).toBe(1);
    expect(created[0].event_ids).not.toContain('EVT-DISTANT-001');
  });

  it('4. Unrelated MEDIUM events without suspicious sequence -> zero incidents', () => {
    for (const evt of unrelatedMediumEvents) {
      eventService.createEvent(evt);
    }

    const created = incidentService.correlateEvents();
    expect(created.length).toBe(0);
  });

  it('5. Re-running correlation on same events -> no duplicate incident', () => {
    for (const evt of attackEvents) {
      eventService.createEvent(evt);
    }

    const run1 = incidentService.correlateEvents();
    expect(run1.length).toBe(1);

    const run2 = incidentService.correlateEvents();
    expect(run2.length).toBe(0);

    expect(incidentService.getAllIncidents().length).toBe(1);
  });

  it('GET /api/v1/incidents should return all incidents', async () => {
    for (const evt of attackEvents) {
      await request(app).post('/api/v1/events/ingest').send(evt);
    }
    incidentService.correlateEvents();

    const res = await request(app).get('/api/v1/incidents');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.count).toBe(1);
    expect(res.body.data[0].event_ids).toHaveLength(4);
  });

  it('GET /api/v1/incidents/:incident_id should return incident by ID', async () => {
    for (const evt of attackEvents) {
      await request(app).post('/api/v1/events/ingest').send(evt);
    }
    const [created] = incidentService.correlateEvents();

    const res = await request(app).get(`/api/v1/incidents/${created.incident_id}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.incident_id).toBe(created.incident_id);
    expect(res.body.data.initial_severity).toBe('CRITICAL');
  });

  it('GET /api/v1/incidents/:incident_id should return 404 for missing incident', async () => {
    const res = await request(app).get('/api/v1/incidents/INC-9999-9999');
    expect(res.statusCode).toBe(404);
    expect(res.body.error.message).toBe('Incident not found');
  });
});
