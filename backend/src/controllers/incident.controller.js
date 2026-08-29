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
