const request = require('supertest');
const app = require('../src/app');
const eventService = require('../src/services/event.service');

const validEvent = {
  "event_id": "EVT-TEST-1001",
  "timestamp": "2026-08-29T10:00:00Z",
  "source": "auth.log",
  "event_type": "ssh_login_failure",
  "severity": "LOW",
  "host": "srv-prod-db01",
  "user": "root",
  "ip_address": "192.168.1.105",
  "raw_data": {
    "port": 22,
    "failure_reason": "Invalid password",
    "attempts": 1
  }
};

const invalidEvent = {
  "event_id": "EVT-TEST-1002",
  "timestamp": "2026-08-29T10:00:00Z",
  // missing "source"
  "event_type": "ssh_login_failure",
  // missing "severity"
  "raw_data": {}
};

describe('Event API endpoints', () => {
  beforeEach(() => {
    eventService.clearEvents();
  });

  describe('POST /api/v1/events/ingest', () => {
    it('should successfully create a valid event', async () => {
      const res = await request(app)
        .post('/api/v1/events/ingest')
        .send(validEvent);
      
      expect(res.statusCode).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.event_id).toBe(validEvent.event_id);
    });

    it('should reject an invalid event', async () => {
      const res = await request(app)
        .post('/api/v1/events/ingest')
        .send(invalidEvent);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.error.message).toContain('Validation Error');
    });
    
    it('should reject a duplicate event_id', async () => {
      await request(app).post('/api/v1/events/ingest').send(validEvent);
      
      const res = await request(app)
        .post('/api/v1/events/ingest')
        .send(validEvent);
        
      expect(res.statusCode).toBe(409);
    });
  });

  describe('GET /api/v1/events', () => {
    it('should return an empty array when no events exist', async () => {
      const res = await request(app).get('/api/v1/events');
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data).toEqual([]);
      expect(res.body.count).toBe(0);
    });

    it('should return all stored events', async () => {
      await request(app).post('/api/v1/events/ingest').send(validEvent);
      
      const res = await request(app).get('/api/v1/events');
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.length).toBe(1);
      expect(res.body.data[0].event_id).toBe(validEvent.event_id);
    });
  });

  describe('GET /api/v1/events/:id', () => {
    it('should return 404 for a non-existent event', async () => {
      const res = await request(app).get('/api/v1/events/NON-EXISTENT');
      
      expect(res.statusCode).toBe(404);
      expect(res.body.error.message).toBe('Event not found');
    });

    it('should return the correct event by ID', async () => {
      await request(app).post('/api/v1/events/ingest').send(validEvent);
      
      const res = await request(app).get(`/api/v1/events/${validEvent.event_id}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.event_id).toBe(validEvent.event_id);
    });
  });
});
