const agentAdapter = require('../src/services/agent.adapter');
const realAgent = require('../src/services/real.agent');
const mockAgent = require('../src/services/mock.agent');
const mockAgentInputFixture = require('../../contracts/mocks/mock_agent_input.json');

describe('Agent Adapter & Real / Mock Agents', () => {
  it('1. Real Agent accepts valid AgentInput and returns valid AgentOutput', async () => {
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

  it('5. Agent is deterministic for the same input', async () => {
    const res1 = await agentAdapter.analyzeIncident(mockAgentInputFixture);
    const res2 = await agentAdapter.analyzeIncident(mockAgentInputFixture);

    expect(res1).toEqual(res2);
  });

  it('6. Adapter rejects invalid AgentOutput produced by broken agent implementation', async () => {
    const brokenAgent = {
      runInvestigation: async () => ({ incident_id: 'INC-001' }) // Missing required fields
    };
    const AgentAdapterClass = agentAdapter.constructor;
    const testAdapter = new AgentAdapterClass(brokenAgent);

    await expect(testAdapter.analyzeIncident(mockAgentInputFixture)).rejects.toThrow(/Invalid AgentOutput/);
  });

  it('7. Mock Agent fallback works correctly when instantiated with mockAgent', async () => {
    const AgentAdapterClass = agentAdapter.constructor;
    const mockAdapter = new AgentAdapterClass(mockAgent);
    const result = await mockAdapter.analyzeIncident(mockAgentInputFixture);
    expect(result).toBeDefined();
    expect(result.incident_id).toBe(mockAgentInputFixture.incident_id);
  });

  it('8. Explicitly proves AgentAdapter invokes RealAgent implementation by default', async () => {
    const realAgentSpy = jest.spyOn(realAgent, 'runInvestigation');
    const mockAgentSpy = jest.spyOn(mockAgent, 'runInvestigation');

    try {
      await agentAdapter.analyzeIncident(mockAgentInputFixture);

      expect(realAgentSpy).toHaveBeenCalledTimes(1);
      expect(realAgentSpy).toHaveBeenCalledWith(mockAgentInputFixture);
      expect(mockAgentSpy).not.toHaveBeenCalled();
    } finally {
      realAgentSpy.mockRestore();
      mockAgentSpy.mockRestore();
    }
  });
});
