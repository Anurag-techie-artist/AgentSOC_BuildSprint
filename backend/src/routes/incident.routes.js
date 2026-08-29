const express = require('express');
const router = express.Router();
const incidentController = require('../controllers/incident.controller');

router.get('/', incidentController.getAllIncidents);
router.get('/:incident_id', incidentController.getIncidentById);

module.exports = router;
