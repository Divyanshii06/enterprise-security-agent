# Secure API Automation and Testing Service

A high-performance FastAPI scaffold featuring strict Pydantic validation, JWT/API key security, and asynchronous REST endpoints designed for secure and scalable API automation.

## Features

* 15+ REST API endpoints for users, transactions, logs, audit trails, automation jobs, and system status monitoring.
* API Key and JWT-based authentication for secure access control.
* Asynchronous request handling using `async/await` for high-performance execution.
* Synthetic response times optimized for sub-200ms performance.
* Interactive Swagger/OpenAPI documentation.
* Strong Pydantic schema validation for complex JSON payloads.
* Centralized security middleware for authentication and authorization.

## Technology Stack

* Python 3.11+
* FastAPI
* Pydantic
* JWT Authentication
* Uvicorn
* Pytest

## Installation

### Prerequisites

* Python 3.11 or higher

### Install Dependencies

```bash
cd secure_api_automation_service
python -m pip install -r requirements.txt
```

## Running the Service

```bash
cd secure_api_automation_service
uvicorn main:app --reload --port 8000
```

The application will be available at:

```text
http://localhost:8000
```

## Authentication

The service supports two authentication methods:

### API Key Authentication

Include the following header in your requests:

```http
X-API-Key: super-secret-api-key
```

### JWT Authentication

Obtain a JWT token by calling:

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "super-secret-api-key"}'
```

The response will return an access token:

```json
{
  "access_token": "<token>",
  "token_type": "bearer"
}
```

Use the token in subsequent requests:

```http
Authorization: Bearer <token>
```

## API Documentation

Interactive API documentation is available at:

### Swagger UI

```text
http://localhost:8000/docs
```

### ReDoc

```text
http://localhost:8000/redoc
```

## Example Endpoints

### User Management

* `POST /users`
* `GET /users`

### Transaction Management

* `POST /transactions`
* `GET /transactions`

### Automation Services

* `POST /automation/jobs`
* `POST /automation/validate`

### System Monitoring

* `GET /status/health`
* `GET /status/metrics`

## Testing

Run the test suite using:

```bash
cd secure_api_automation_service
pytest
```

A minimal test suite is included to verify authentication and health-check functionality.

## Coding Standards

* Asynchronous handlers are used throughout the service for low-latency execution.
* Pydantic models enforce strict schema and payload validation.
* Security middleware centrally validates API keys and JWT tokens.
* Endpoint metadata includes tags and summaries for automatic OpenAPI generation.
* Clean service-layer separation improves maintainability and scalability.

## Project Goals

This project demonstrates modern API development practices, including secure authentication, robust validation, asynchronous processing, automated documentation generation, and production-ready FastAPI architecture.
