const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const { agentInputSchema, agentOutputSchema, securityEventSchema } = require('../models/schemas');
const realAgent = require('./real.agent');
const mockAgent = require('./mock.agent');

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

// Register security_event schema so $ref in agent_input.json resolves correctly
ajv.addSchema(securityEventSchema, 'security_event.json');

const validateAgentInput = ajv.compile(agentInputSchema);
const validateAgentOutput = ajv.compile(agentOutputSchema);

const defaultAgent = process.env.USE_MOCK_AGENT === 'true' ? mockAgent : realAgent;

class AgentAdapter {
  constructor(agentImpl = defaultAgent) {
    this.agent = agentImpl;
  }

  validateInput(input) {
    const isValid = validateAgentInput(input);
    if (!isValid) {
      const errors = validateAgentInput.errors.map(e => `${e.instancePath} ${e.message}`).join(', ');
      throw new Error(`Invalid AgentInput: ${errors}`);
    }
  }

  validateOutput(output) {
    const isValid = validateAgentOutput(output);
    if (!isValid) {
      const errors = validateAgentOutput.errors.map(e => `${e.instancePath} ${e.message}`).join(', ');
      throw new Error(`Invalid AgentOutput: ${errors}`);
    }
  }

  /**
   * Main adapter interface: accepts AgentInput, validates input, calls agent implementation,
   * validates returned AgentOutput, and returns output.
   */
  async analyzeIncident(agentInput) {
    this.validateInput(agentInput);

    const result = await this.agent.runInvestigation(agentInput);

    this.validateOutput(result);

    return result;
  }
}

module.exports = new AgentAdapter();
