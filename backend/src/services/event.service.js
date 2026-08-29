class EventService {
  constructor() {
    this.events = new Map();
  }

  createEvent(eventData) {
    // Schema already requires event_id, so we just use it
    if (this.events.has(eventData.event_id)) {
      throw new Error(`Event with ID ${eventData.event_id} already exists`);
    }
    
    this.events.set(eventData.event_id, eventData);
    return eventData;
  }

  getAllEvents() {
    return Array.from(this.events.values());
  }

  getEventById(eventId) {
    return this.events.get(eventId) || null;
  }
  
  // For testing primarily
  clearEvents() {
    this.events.clear();
  }
}

// Export as a singleton instance so controllers share the same memory state
module.exports = new EventService();
