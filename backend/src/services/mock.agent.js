/**
 * Mock Agent Implementation
 * Receives valid AgentInput and returns deterministic valid AgentOutput.
 * Never calls an LLM or external AI provider.
 */
class MockAgent {
  async runInvestigation(agentInput) {
    const { incident_id, title, initial_severity, entities, events } = agentInput;

    const hostStr = (entities.hosts && entities.hosts.length > 0) ? entities.hosts.join(', ') : 'unknown host';
    const userStr = (entities.users && entities.users.length > 0) ? entities.users.join(', ') : 'unknown user';
    const ipStr = (entities.ip_addresses && entities.ip_addresses.length > 0) ? entities.ip_addresses.join(', ') : 'unknown IP';

    // Build evidence from provided events
    const evidence = events.map(evt => ({
      description: `${evt.event_type} event on ${evt.host || hostStr} by user ${evt.user || userStr}`,
      source_event_id: evt.event_id,
      relevance: `Event logged with severity ${evt.severity} from ${evt.source}`
    }));

    // Build reasoning steps
    const reasoning_steps = [
      {
        step: 1,
        action: `Analyzed security events associated with incident ${incident_id}.`,
        finding: `Evaluated ${events.length} event(s) across host(s) [${hostStr}] and IP(s) [${ipStr}].`
      },
      {
        step: 2,
        action: `Evaluated entity behavior for user(s) [${userStr}].`,
        finding: `Correlated event activity with initial severity assessment of ${initial_severity}.`
      },
      {
        step: 3,
        action: 'Formulated recommended response actions and mitigation steps.',
        finding: `Identified containment steps for involved entities [${ipStr}].`
      }
    ];

    // Build response actions
    const response_actions = [
      {
        action_id: 'ACT-001',
        title: `Block IP address ${ipStr}`,
        description: `Add ${ipStr} to edge firewall blocklist to contain traffic.`,
        risk_level: 'LOW',
        automated_script: `iptables -A INPUT -s ${ipStr.split(', ')[0]} -j DROP`
      },
      {
        action_id: 'ACT-002',
        title: `Revoke credentials for ${userStr}`,
        description: `Enforce password reset and invalidate active sessions for ${userStr}.`,
        risk_level: 'MEDIUM',
        automated_script: `passwd -l ${userStr.split(', ')[0]} && pkill -u ${userStr.split(', ')[0]}`
      }
    ];

    return {
      incident_id,
      summary: `Automated investigation completed for incident ${incident_id} (${title}). Analyzed ${events.length} event(s) involving host(s) ${hostStr}.`,
      root_cause: `Suspicious security activity detected involving user ${userStr} on host ${hostStr} from IP ${ipStr}.`,
      assessed_severity: initial_severity || 'HIGH',
      confidence_score: 0.90,
      mitre_tactics: [
        'TA0001: Initial Access',
        'TA0004: Privilege Escalation'
      ],
      reasoning_steps,
      evidence,
      response_actions
    };
  }
}

module.exports = new MockAgent();
