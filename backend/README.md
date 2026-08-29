# AgentSOC Backend

This is the lightweight REST backend foundation for the AgentSOC hackathon MVP. It's built with Node.js and Express.

## Prerequisites

- Node.js (v14 or higher recommended)
- npm

## Installation

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## How to Start the Backend

To start the server for local development:

```bash
npm run dev
```

Or start normally:

```bash
npm start
```

The server runs on port 3000 by default (configurable via the `PORT` env var).

## How to Run Tests

The backend uses Jest for testing. To run the test suite:

```bash
npm test
```

## Available Endpoint(s)

### Health Check
- **Endpoint**: `GET /api/health`
- **Description**: Verifies that the backend API is up and running.
- **Response Format**:
  ```json
  {
    "status": "UP",
    "timestamp": "2026-08-29T17:00:00.000Z"
  }
  ```

## Architecture Notes
- Uses `express` for routing
- Uses `helmet` for security headers
- Uses `cors` configured for future frontend integration
- Centralized error handling via `src/middleware/errorHandler.js`
- JSON Schema validation via `src/middleware/validateSchema.js` (ready to consume existing shared contracts)
