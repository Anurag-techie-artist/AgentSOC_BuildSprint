const agentAdapter = require('../src/services/agent.adapter');
const mockAgentInputFixture = require('../../contracts/mocks/mock_agent_input.json');

describe('Agent Adapter & Mock Agent', () => {
  it('1. Mock Agent accepts valid AgentInput and returns valid AgentOutput', async () => {
    const result = await agentAdapter.analyzeIncident(mockAgentInputFixture);
    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();
    expect(result.root_cause).toBeDefined();
  });

  it('2. Returned incident_id matches input incident_id', async () => {
    const result = await agentAdapter.analyzeIncident(mockAgentInputFixture);
    expect(result.incident_id).toBe(mockAgentInputFixture.incident_id);
  });

  it('3. AgentOutput passes agent_output.json validation', async () => {
    const result = await agentAdapter.analyzeIncident(mockAgentInputFixture);
    expect(() => agentAdapter.validateOutput(result)).not.toThrow();
  });

  it('4. Invalid AgentInput is rejected', async () => {
    const invalidInput = { ...mockAgentInputFixture };
    delete invalidInput.incident_id;

    await expect(agentAdapter.analyzeIncident(invalidInput)).rejects.toThrow(/Invalid AgentInput/);
  });

  it('5. Mock Agent is deterministic for the same input', async () => {
    const res1 = await agentAdapter.analyzeIncident(mockAgentInputFixture);
    const res2 = await agentAdapter.analyzeIncident(mockAgentInputFixture);

    expect(res1).toEqual(res2);
  });

  it('6. Adapter rejects invalid AgentOutput produced by broken agent implementation', async () => {
    const brokenAgent = {
      runInvestigation: async () => ({ incident_id: 'INC-001' }) // Missing required fields
    };
    const { default: _, ...mockModule } = jest.requireActual('../src/services/agent.adapter');
    const AgentAdapterClass = agentAdapter.constructor;
    const testAdapter = new AgentAdapterClass(brokenAgent);

    await expect(testAdapter.analyzeIncident(mockAgentInputFixture)).rejects.toThrow(/Invalid AgentOutput/);
  });
});
