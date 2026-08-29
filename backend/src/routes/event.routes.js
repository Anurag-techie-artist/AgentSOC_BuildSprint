const express = require('express');
const router = express.Router();
const eventController = require('../controllers/event.controller');
const validateSchema = require('../middleware/validateSchema');
const { securityEventSchema } = require('../models/schemas');

router.post('/ingest', validateSchema(securityEventSchema), eventController.createEvent);
router.get('/', eventController.getAllEvents);
router.get('/:id', eventController.getEventById);

module.exports = router;
