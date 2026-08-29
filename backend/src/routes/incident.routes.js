const express = require('express');
const router = express.Router();
const incidentController = require('../controllers/incident.controller');

router.get('/', incidentController.getAllIncidents);
router.get('/:incident_id', incidentController.getIncidentById);
router.post('/:incident_id/investigate', incidentController.investigateIncident);
router.get('/:incident_id/investigation', incidentController.getInvestigation);
router.post('/:incident_id/respond', incidentController.respondToIncident);

module.exports = router;
