const fs = require('fs');
const path = require('path');

// Read the schema from the single source of truth in contracts/
const schemaPath = path.resolve(__dirname, '../../../contracts/schemas/security_event.json');
let securityEventSchema;

try {
  securityEventSchema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
} catch (error) {
  console.error('Failed to load security_event.json schema from contracts. Is the path correct?', error);
  // Fallback for tests if they run from a different root, or just rethrow
  throw error;
}

module.exports = {
  securityEventSchema
};
