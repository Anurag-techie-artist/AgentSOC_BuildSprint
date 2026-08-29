const request = require('supertest');
const app = require('../src/app');

describe('Health API', () => {
  it('should return status UP on GET /api/health', async () => {
    const res = await request(app).get('/api/health');
    
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('status', 'UP');
    expect(res.body).toHaveProperty('timestamp');
  });
});
