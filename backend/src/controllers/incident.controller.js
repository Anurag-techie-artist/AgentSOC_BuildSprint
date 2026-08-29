const incidentService = require('../services/incident.service');

exports.getAllIncidents = (req, res, next) => {
  try {
    const incidents = incidentService.getAllIncidents();
    return res.status(200).json({
      status: 'success',
      count: incidents.length,
      data: incidents
    });
  } catch (error) {
    next(error);
  }
};

exports.getIncidentById = (req, res, next) => {
  try {
    const { incident_id } = req.params;
    const incident = incidentService.getIncidentById(incident_id);

    if (!incident) {
      const error = new Error('Incident not found');
      error.statusCode = 404;
      throw error;
    }

    return res.status(200).json({
      status: 'success',
      data: incident
    });
  } catch (error) {
    next(error);
  }
};

exports.investigateIncident = async (req, res, next) => {
  try {
    const { incident_id } = req.params;
    const agentOutput = await incidentService.investigateIncident(incident_id);

    return res.status(200).json({
      status: 'success',
      data: agentOutput
    });
  } catch (error) {
    if (error.message && error.message.startsWith('Invalid AgentInput')) {
      error.statusCode = 400;
    } else if (error.message && error.message.startsWith('Invalid AgentOutput')) {
      error.statusCode = 500;
    }
    next(error);
  }
};

exports.getInvestigation = (req, res, next) => {
  try {
    const { incident_id } = req.params;
    const result = incidentService.getInvestigation(incident_id);

    return res.status(200).json({
      status: 'success',
      data: result
    });
  } catch (error) {
    next(error);
  }
};
