const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000';

export async function fetchIncidents() {
  const response = await fetch(`${API_BASE_URL}/api/v1/incidents`);
  if (!response.ok) {
    throw new Error(`Failed to fetch incidents: ${response.status} ${response.statusText}`);
  }
  const json = await response.json();
  return json.data || [];
}

export async function fetchIncidentById(incidentId) {
  const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch incident ${incidentId}: ${response.status} ${response.statusText}`);
  }
  const json = await response.json();
  return json.data;
}

export async function fetchEvents() {
  const response = await fetch(`${API_BASE_URL}/api/v1/events`);
  if (!response.ok) {
    throw new Error(`Failed to fetch events: ${response.status} ${response.statusText}`);
  }
  const json = await response.json();
  return json.data || [];
}

export async function investigateIncident(incidentId) {
  const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/investigate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    let errorMsg = `Investigation failed: ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson.error && errJson.error.message) {
        errorMsg = errJson.error.message;
      }
    } catch (e) {
      // Use fallback errorMsg
    }
    throw new Error(errorMsg);
  }

  const json = await response.json();
  return json.data;
}

export async function respondToIncident(incidentId, actionId) {
  const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/respond`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ action_id: actionId })
  });

  if (!response.ok) {
    let errorMsg = `Response execution failed: ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson.error && errJson.error.message) {
        errorMsg = errJson.error.message;
      }
    } catch (e) {
      // Use fallback errorMsg
    }
    throw new Error(errorMsg);
  }

  const json = await response.json();
  return json.data;
}
