# AgentSOC

## Autonomous Incident Investigation & Response Platform

> **From raw security telemetry to autonomous incident investigation and response intelligence.**

AgentSOC is an autonomous Security Operations Center designed to reduce the manual effort required to investigate security incidents.

Instead of treating security events as isolated alerts, AgentSOC correlates related telemetry into incidents, investigates the resulting attack sequence, evaluates the available evidence, maps observed behavior to MITRE ATT&CK tactics, and generates actionable response recommendations.

```text
Telemetry
    ↓
Correlation
    ↓
Incident Creation
    ↓
Autonomous Investigation
    ↓
Evidence Analysis
    ↓
Security Reasoning
    ↓
MITRE ATT&CK Mapping
    ↓
Response Recommendations
```

---

# The Problem

Security Operations Centers generate enormous amounts of telemetry.

The challenge is not simply detecting an individual suspicious event. A real investigation requires connecting multiple pieces of evidence and understanding what they mean together.

An analyst may need to answer:

* Which events belong to the same attack?
* Is the activity actually malicious?
* What happened first?
* How did the attacker progress?
* What evidence supports the conclusion?
* What is the likely root cause?
* What should be done next?

Traditional alert-driven workflows can leave analysts manually performing this correlation and investigation.

**AgentSOC is built to automate this investigation loop.**

---

# What AgentSOC Does

## 1. Ingest Security Events

AgentSOC accepts security telemetry through a REST API.

The system can process events representing:

* Authentication failures
* Successful authentication
* Privilege escalation
* Sensitive resource access
* Outbound data transfer

Each event contains security context such as:

```text
Event ID
Timestamp
Source
Event Type
Severity
Host
User
Source IP
Raw Event Data
```

---

## 2. Correlate Events Into Incidents

Instead of treating every event independently, AgentSOC identifies related security activity and groups it into an incident.

For example:

```text
SSH Login Failures
        │
        ▼
Successful Authentication
        │
        ▼
Privilege Escalation
        │
        ▼
Sensitive Resource Access
        │
        ▼
Outbound Data Transfer
        │
        ▼
   SECURITY INCIDENT
```

This changes the workflow from:

```text
Alert → Analyst manually investigates
```

to:

```text
Events → Correlation → Incident → Agent Investigation
```

---

## 3. Autonomous Agent Investigation

The investigation layer is implemented as a dedicated Python agent connected to the Node.js backend.

When an incident is investigated, the agent evaluates the available security evidence and produces a structured investigation.

The investigation includes:

* Executive summary
* Security assessment
* Root-cause inference
* Confidence assessment
* MITRE ATT&CK mapping
* Investigation reasoning sequence
* Correlated evidence artifacts
* Recommended response actions

The goal is not simply to classify an incident.

The goal is to explain **why** the incident is considered malicious and **what should happen next**.

---

## 4. Evidence-Grounded Reasoning

AgentSOC exposes the evidence supporting its conclusions.

For example:

```text
Failed Authentication
        ↓
Successful Authentication
        ↓
Privilege Escalation
        ↓
Sensitive File Access
        ↓
Database Dump Access
        ↓
Outbound Transfer
        ↓
Threat Synthesis
```

The investigation output references the underlying event IDs, allowing an analyst to trace findings back to the original telemetry.

This makes the agent's output easier to inspect and validate.

---

## 5. MITRE ATT&CK Mapping

AgentSOC maps observed behavior to relevant MITRE ATT&CK tactics.

For the primary demonstration scenario, the investigation identifies tactics including:

```text
TA0001 — Initial Access
TA0002 — Execution
TA0004 — Privilege Escalation
```

This provides a standardized representation of the attack progression.

---

## 6. Response Intelligence

After investigation, AgentSOC generates recommended containment actions based on the observed threat.

Example response actions include:

```text
Block malicious source IP
        ↓
Block suspicious destination IP
        ↓
Reset compromised credentials
        ↓
Isolate affected host
```

The current implementation intentionally operates these actions in:

```text
SIMULATION ONLY
```

This allows the complete detection-to-response workflow to be demonstrated without performing destructive changes against real infrastructure.

---

# Architecture

```text
                          ┌─────────────────────┐
                          │  Security Telemetry │
                          │                     │
                          │ Auth / Syslog / EDR │
                          │ Audit / Network     │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │   Event Ingestion   │
                          │      REST API       │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │  Event Correlation  │
                          │                     │
                          │ Events → Incidents  │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │  Incident Service   │
                          │                     │
                          │ Lifecycle / State   │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │    Agent Adapter    │
                          │                     │
                          │ Node.js → Python    │
                          └──────────┬──────────┘
                                     │
                                     ▼
                   ┌─────────────────────────────────┐
                   │       Autonomous Agent          │
                   │                                 │
                   │ Analysis                        │
                   │ Reasoning                       │
                   │ Validation                      │
                   │ Response Intelligence           │
                   └───────────────┬─────────────────┘
                                   │
                                   ▼
                          ┌─────────────────────┐
                          │ Investigation Output│
                          │                     │
                          │ Evidence            │
                          │ Reasoning           │
                          │ MITRE ATT&CK        │
                          │ Recommendations     │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │    SOC Dashboard    │
                          │                     │
                          │ Incidents           │
                          │ Findings            │
                          │ Timeline            │
                          │ Response Actions    │
                          └─────────────────────┘
```

---

# Technology Stack

| Layer            | Technology       |
| ---------------- | ---------------- |
| Frontend         | React            |
| Frontend Tooling | Vite             |
| Styling          | Tailwind CSS     |
| Backend          | Node.js          |
| API              | Express          |
| Validation       | AJV              |
| Backend Testing  | Jest             |
| Agent            | Python           |
| Agent Testing    | Pytest           |
| Integration      | Node.js ↔ Python |
| Security Mapping | MITRE ATT&CK     |

---

# Project Structure

```text
AgentSOC_BuildSprint/
│
├── agent/
│   ├── src/
│   │   ├── agent.py
│   │   ├── analyzer.py
│   │   ├── providers.py
│   │   ├── reasoning.py
│   │   ├── runner.py
│   │   └── validator.py
│   │
│   └── tests/
│       └── test_agent.py
│
├── backend/
│   ├── src/
│   │   ├── controllers/
│   │   ├── middleware/
│   │   ├── models/
│   │   ├── routes/
│   │   └── services/
│   │
│   └── tests/
│       ├── agent.test.js
│       ├── events.test.js
│       ├── health.test.js
│       ├── incidents.test.js
│       ├── investigation.test.js
│       └── response.test.js
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── data/
│   │   ├── services/
│   │   ├── App.jsx
│   │   └── main.jsx
│   │
│   └── vite.config.js
│
├── data/
│   └── scenarios/
│       ├── primary_attack.json
│       └── benign_activity.json
│
└── README.md
```

---

# Demonstration Attack Scenario

AgentSOC includes a deterministic multi-stage attack scenario for demonstrating the complete investigation pipeline.

The primary scenario contains seven correlated events:

```text
EVT-2001
SSH login failure

EVT-2002
SSH login failure

EVT-2003
Successful SSH authentication

EVT-2004
Privilege escalation

EVT-2005
Sensitive resource access

EVT-2006
Sensitive resource access

EVT-2007
Outbound data transfer
```

The events represent an attack progression:

```text
Credential Probing
       ↓
Credential Compromise
       ↓
Remote Access
       ↓
Privilege Escalation
       ↓
Credential / Sensitive Resource Access
       ↓
Database Dump Access
       ↓
Data Exfiltration
```

These events are correlated into:

```text
INC-2026-0001
Correlated Security Activity on srv-prod-db01
```

The dashboard then exposes the resulting:

* Incident severity
* Confidence score
* Executive summary
* Root cause
* MITRE ATT&CK tactics
* Agent reasoning
* Correlated evidence
* Event chronology
* Response recommendations

---

# Benign Scenario

A separate benign activity scenario is included:

```text
data/scenarios/benign_activity.json
```

It can be used to verify that normal activity can be ingested without being confused with the primary attack scenario.

---

# Running AgentSOC

## Prerequisites

Install:

* Node.js
* npm
* Python 3
* pip
* Git

---

## Clone

```bash
git clone https://github.com/Anurag-techie-artist/AgentSOC_BuildSprint.git
cd AgentSOC_BuildSprint
```

---

## Install Backend

```bash
cd backend
npm install
```

---

## Install Frontend

```bash
cd ../frontend
npm install
```

---

## Start Backend

From `backend/`:

```bash
npm start
```

Backend:

```text
http://localhost:3000
```

---

## Start Frontend

From `frontend/`:

```bash
npm run dev
```

Frontend:

```text
http://localhost:5173
```

The frontend and backend intentionally use separate ports.

---

# API

## Health

```http
GET /api/health
```

---

## Events

### Ingest Event

```http
POST /api/v1/events/ingest
```

### List Events

```http
GET /api/v1/events
```

### Get Event

```http
GET /api/v1/events/:id
```

---

## Incidents

### List Incidents

```http
GET /api/v1/incidents
```

### Get Incident

```http
GET /api/v1/incidents/:id
```

### Investigate Incident

```http
POST /api/v1/incidents/:incident_id/investigate
```

### Simulate Response

```http
POST /api/v1/incidents/:incident_id/respond
```

---

# Replay the Primary Attack

The primary attack scenario can be replayed through PowerShell.

From the repository root:

```powershell
$scenario = Get-Content data\scenarios\primary_attack.json | ConvertFrom-Json

foreach ($e in $scenario.events) {
    $body = $e | ConvertTo-Json -Depth 10

    $result = Invoke-RestMethod `
        -Uri "http://localhost:3000/api/v1/events/ingest" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body

    Write-Host "$($e.event_id) -> $($result.status)"
}
```

Expected ingestion flow:

```text
EVT-2001 → success
EVT-2002 → success
EVT-2003 → success
EVT-2004 → success
EVT-2005 → success
EVT-2006 → success
EVT-2007 → success
```

Once the events are correlated, the incident becomes available through the API and SOC dashboard.

---

# Investigation

An incident can be investigated through the dashboard using:

```text
RUN AGENT INVESTIGATION
```

or through the API:

```http
POST /api/v1/incidents/:incident_id/investigate
```

The resulting investigation exposes:

```text
Executive Summary
        +
Identified Root Cause
        +
MITRE ATT&CK Tactics
        +
Agent Reasoning Sequence
        +
Correlated Evidence
        +
Recommended Response Actions
```

---

# Verification

AgentSOC contains automated tests covering the backend, agent, investigation, and response workflows.

## Backend Tests

From `backend/`:

```bash
npm test
```

The repository includes tests for:

* Agent integration
* Event ingestion
* Health checks
* Incident creation
* Investigation
* Response simulation

## Agent Tests

From the repository root:

```bash
python -m pytest agent/tests/
```

## Frontend Build

From `frontend/`:

```bash
npm run build
```

---

# Design Principles

## Evidence Before Conclusion

The investigation should be grounded in the underlying security telemetry.

## Correlation Before Escalation

A single event can be ambiguous. Multiple related events can reveal an attack sequence.

## Explainable Investigation

The agent exposes its reasoning sequence and supporting evidence rather than returning only a final verdict.

## Safe Response

Response actions are currently simulated to demonstrate the workflow without affecting production infrastructure.

## Modular Architecture

The frontend, backend, and agent are separated so that each layer can evolve independently.

---

# What Makes AgentSOC Different?

Traditional security monitoring often follows:

```text
Detect → Alert → Human Investigation
```

AgentSOC explores a more autonomous workflow:

```text
Detect
  ↓
Correlate
  ↓
Investigate
  ↓
Reason
  ↓
Recommend
  ↓
Respond
  ↓
Verify
```

The key idea is not to replace the security analyst.

It is to reduce the repetitive investigation work that happens between an alert being generated and an analyst understanding what actually happened.

---

# Current Scope

AgentSOC is a working hackathon prototype demonstrating an autonomous SOC investigation workflow.

The current implementation provides:

* Security event ingestion
* Event correlation
* Automatic incident creation
* Incident lifecycle handling
* Autonomous agent investigation
* Evidence analysis
* Explainable reasoning
* Root-cause inference
* Confidence assessment
* MITRE ATT&CK mapping
* Response recommendations
* Response simulation
* SOC dashboard visualization
* Backend and agent test coverage

---

# Future Direction

The current prototype provides the foundation for a more capable autonomous SOC.

Future development can extend AgentSOC with:

## Real-Time Security Telemetry

Integrate continuous event streams from:

* SIEM platforms
* EDR systems
* IAM systems
* Firewalls
* Cloud infrastructure
* Application logs

## Advanced Correlation

Move beyond deterministic correlation toward:

* Multi-host attack chains
* Identity-based correlation
* Process relationships
* Temporal attack graphs
* Cross-source behavioral correlation

## Adaptive Investigation

Allow the agent to dynamically determine:

```text
What evidence should I inspect next?
        ↓
What hypothesis does it support?
        ↓
What additional evidence is required?
        ↓
Is the threat confirmed?
```

## Threat Intelligence

Enrich investigations using:

* IP reputation
* Domain intelligence
* Malware intelligence
* IOC feeds
* Threat actor context

## Policy-Governed Autonomous Response

Move from simulation toward controlled execution with:

* Approval policies
* Risk thresholds
* Human-in-the-loop controls
* Rollback mechanisms
* Post-action verification

---

# Long-Term Vision

The long-term goal is a closed-loop autonomous security operation:

```text
┌──────────┐
│  DETECT  │
└────┬─────┘
     ↓
┌──────────┐
│CORRELATE │
└────┬─────┘
     ↓
┌──────────────┐
│ INVESTIGATE  │
└──────┬───────┘
       ↓
┌──────────┐
│  REASON  │
└────┬─────┘
     ↓
┌──────────┐
│ RESPOND  │
└────┬─────┘
     ↓
┌──────────┐
│  VERIFY  │
└────┬─────┘
     │
     └──────────────→ CONTINUE MONITORING
```

AgentSOC aims to move security operations from **alert-centric monitoring** toward **evidence-driven autonomous investigation**.

---

# Security Notice

AgentSOC is a security research and hackathon prototype.

Response actions displayed by the system currently operate in simulation mode. The commands shown by the dashboard should not be executed against production infrastructure without appropriate authorization, validation, safeguards, and operational controls.

---

# Built for LatentForce BuildSprint

## AgentSOC

> **From alerts to autonomous investigation.**
