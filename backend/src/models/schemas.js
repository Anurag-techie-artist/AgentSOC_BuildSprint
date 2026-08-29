const fs = require('fs');
const path = require('path');

const eventSchemaPath = path.resolve(__dirname, '../../../contracts/schemas/security_event.json');
const incidentSchemaPath = path.resolve(__dirname, '../../../contracts/schemas/incident.json');
const agentInputSchemaPath = path.resolve(__dirname, '../../../contracts/schemas/agent_input.json');
const agentOutputSchemaPath = path.resolve(__dirname, '../../../contracts/schemas/agent_output.json');

let securityEventSchema;
let incidentSchema;
let agentInputSchema;
let agentOutputSchema;

try {
  securityEventSchema = JSON.parse(fs.readFileSync(eventSchemaPath, 'utf8'));
  incidentSchema = JSON.parse(fs.readFileSync(incidentSchemaPath, 'utf8'));
  agentInputSchema = JSON.parse(fs.readFileSync(agentInputSchemaPath, 'utf8'));
  agentOutputSchema = JSON.parse(fs.readFileSync(agentOutputSchemaPath, 'utf8'));
} catch (error) {
  console.error('Failed to load schemas from contracts.', error);
  throw error;
}

module.exports = {
  securityEventSchema,
  incidentSchema,
  agentInputSchema,
  agentOutputSchema
};
