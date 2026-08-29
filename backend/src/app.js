const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const healthRoutes = require('./routes/health.routes');
const eventRoutes = require('./routes/event.routes');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/health', healthRoutes);
app.use('/api/v1/events', eventRoutes);

// Error Handling
app.use(errorHandler);

module.exports = app;
