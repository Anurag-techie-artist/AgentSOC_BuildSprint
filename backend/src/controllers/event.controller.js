const eventService = require('../services/event.service');

exports.createEvent = (req, res, next) => {
  try {
    const newEvent = eventService.createEvent(req.body);
    
    res.status(201).json({
      status: 'success',
      data: newEvent,
      id: newEvent.event_id
    });
  } catch (error) {
    if (error.message.includes('already exists')) {
      error.statusCode = 409;
    }
    next(error);
  }
};

exports.getAllEvents = (req, res, next) => {
  try {
    const events = eventService.getAllEvents();
    
    res.status(200).json({
      status: 'success',
      count: events.length,
      data: events
    });
  } catch (error) {
    next(error);
  }
};

exports.getEventById = (req, res, next) => {
  try {
    const { id } = req.params;
    const event = eventService.getEventById(id);
    
    if (!event) {
      const error = new Error('Event not found');
      error.statusCode = 404;
      throw error;
    }
    
    res.status(200).json({
      status: 'success',
      data: event
    });
  } catch (error) {
    next(error);
  }
};
