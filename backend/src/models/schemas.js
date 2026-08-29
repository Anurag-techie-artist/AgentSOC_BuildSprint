const fs = require('fs');
const path = require('path');

const eventSchemaPath = path.resolve(__dirname, '../../../contracts/schemas/security_event.json');
const incidentSchemaPath = path.resolve(__dirname, '../../../contracts/schemas/incident.json');

let securityEventSchema;
let incidentSchema;

try {
  securityEventSchema = JSON.parse(fs.readFileSync(eventSchemaPath, 'utf8'));
  incidentSchema = JSON.parse(fs.readFileSync(incidentSchemaPath, 'utf8'));
} catch (error) {
  console.error('Failed to load schemas from contracts.', error);
  throw error;
}

module.exports = {
  securityEventSchema,
  incidentSchema
};
