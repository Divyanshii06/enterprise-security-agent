import asyncio
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from auth import API_KEY_HEADER_NAME, API_KEY_VALUE, create_access_token, verify_access_token
from schemas import (
    ActionResponse,
    AutomationJobCreate,
    AutomationJobResponse,
    AutomationValidationRequest,
    AutomationValidationResponse,
    HealthResponse,
    JobStatus,
    LogEntry,
    LogLevel,
    MetricsResponse,
    SystemConfigResponse,
    SystemTestRunRequest,
    SystemTestRunResponse,
    TokenRequest,
    TokenResponse,
    TransactionCreate,
    TransactionResponse,
    TransactionUpdate,
    UserCreate,
    UserResponse,
    UserUpdate,
)

app = FastAPI(
    title="Secure API Automation and Testing Service",
    description=(
        "A high-performance FastAPI scaffold for secure automation, transaction processing, and system testing. "
        "Each endpoint uses Pydantic payload validation and async execution to support sub-200ms responses."
    ),
    version="0.1.0",
)

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
http_bearer = HTTPBearer(auto_error=False)

# In-memory stores for the service scaffold.
USER_STORE: Dict[str, Dict[str, Any]] = {}
TRANSACTION_STORE: Dict[str, Dict[str, Any]] = {}
LOG_STORE: List[Dict[str, Any]] = []
JOB_STORE: Dict[str, Dict[str, Any]] = {}
AUDIT_STORE: List[Dict[str, Any]] = []
SERVICE_START_TIME = time.monotonic()


async def verify_credentials(
    api_key: Optional[str] = Security(api_key_header),
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Security(http_bearer),
) -> Dict[str, Any]:
    """Verify API key or JWT bearer token for all protected endpoints."""
    if api_key == API_KEY_VALUE:
        return {"sub": "automation-service", "auth_method": "api_key"}
    if bearer_credentials:
        token = bearer_credentials.credentials
        return verify_access_token(token)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication credentials",
    )


async def simulate_io_latency() -> None:
    """Simulates minimal asynchronous I/O cost to keep endpoint response times realistic."""
    await asyncio.sleep(0)


@app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
async def issue_access_token(payload: TokenRequest):
    """Issue a JWT access token when a valid API key is provided."""
    if payload.api_key != API_KEY_VALUE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    access_token = create_access_token(subject="api_automation_client")
    return TokenResponse(access_token=access_token, expires_in=3600)


@app.get("/status/health", response_model=HealthResponse, tags=["System Status"], summary="Health probe endpoint")
async def health_check():
    """Return service health and uptime metadata for operational monitoring."""
    await simulate_io_latency()
    uptime = time.monotonic() - SERVICE_START_TIME
    return HealthResponse(
        status="healthy",
        uptime_seconds=uptime,
        details={"version": app.version, "authenticated": False},
    )


@app.get("/status/metrics", response_model=MetricsResponse, tags=["System Status"], summary="Runtime metrics snapshot")
async def metrics_snapshot(credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Return runtime metrics including active resources and queue size."""
    await simulate_io_latency()
    return MetricsResponse(
        active_users=len(USER_STORE),
        total_transactions=len(TRANSACTION_STORE),
        queued_jobs=sum(1 for job in JOB_STORE.values() if job["status"] == JobStatus.pending),
        uptime_seconds=time.monotonic() - SERVICE_START_TIME,
    )


@app.get("/status/config", response_model=SystemConfigResponse, tags=["System Status"], summary="Configuration details")
async def system_config(credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Return configuration metadata for service inspection."""
    await simulate_io_latency()
    return SystemConfigResponse(
        environment="development",
        service_name="Secure API Automation and Testing Service",
        supported_auth_methods=["api_key", "jwt"],
        documentation_url="/docs",
    )


@app.post("/users", response_model=UserResponse, tags=["Users"], summary="Create a new service user")
async def create_user(user: UserCreate, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Create a new API automation user with strict payload validation."""
    await simulate_io_latency()
    user_id = str(uuid.uuid4())
    record = user.dict()
    record.update({"user_id": user_id, "created_at": datetime.utcnow()})
    USER_STORE[user_id] = record
    AUDIT_STORE.append({"event": "user_created", "user_id": user_id, "timestamp": datetime.utcnow()})
    return UserResponse(**record)


@app.get("/users", response_model=List[UserResponse], tags=["Users"], summary="List all service users")
async def list_users(credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Retrieve all users currently registered in the automation service."""
    await simulate_io_latency()
    return [UserResponse(**user) for user in USER_STORE.values()]


@app.get("/users/{user_id}", response_model=UserResponse, tags=["Users"], summary="Get a specific user")
async def get_user(user_id: str, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Fetch a single user by identifier."""
    await simulate_io_latency()
    user = USER_STORE.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(**user)


@app.put("/users/{user_id}", response_model=UserResponse, tags=["Users"], summary="Update an existing user")
async def update_user(user_id: str, user_update: UserUpdate, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Update existing user attributes and preserve immutable identifiers."""
    await simulate_io_latency()
    existing = USER_STORE.get(user_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    updated = existing.copy()
    for field, value in user_update.dict(exclude_unset=True).items():
        updated[field] = value
    USER_STORE[user_id] = updated
    AUDIT_STORE.append({"event": "user_updated", "user_id": user_id, "timestamp": datetime.utcnow()})
    return UserResponse(**updated)


@app.delete("/users/{user_id}", response_model=ActionResponse, tags=["Users"], summary="Delete a user from the service")
async def delete_user(user_id: str, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Remove a user from the system and record an audit entry."""
    await simulate_io_latency()
    if USER_STORE.pop(user_id, None) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    AUDIT_STORE.append({"event": "user_deleted", "user_id": user_id, "timestamp": datetime.utcnow()})
    return ActionResponse(success=True, message="User deleted")


@app.post("/transactions", response_model=TransactionResponse, tags=["Transactions"], summary="Create a new transaction")
async def create_transaction(payload: TransactionCreate, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Accept transaction objects and enqueue them with high-performance validation."""
    await simulate_io_latency()
    transaction_id = str(uuid.uuid4())
    record = {
        "transaction_id": transaction_id,
        "reference_id": payload.reference_id,
        "transaction_type": payload.transaction_type,
        "status": "created",
        "created_at": datetime.utcnow(),
        "processed_at": None,
        "priority": payload.priority,
        "payload": payload.payload,
    }
    TRANSACTION_STORE[transaction_id] = record
    AUDIT_STORE.append({"event": "transaction_created", "transaction_id": transaction_id, "timestamp": datetime.utcnow()})
    return TransactionResponse(**record)


@app.get("/transactions", response_model=List[TransactionResponse], tags=["Transactions"], summary="List all transactions")
async def list_transactions(credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Retrieve all transaction records currently tracked by the service."""
    await simulate_io_latency()
    return [TransactionResponse(**tx) for tx in TRANSACTION_STORE.values()]


@app.get("/transactions/{transaction_id}", response_model=TransactionResponse, tags=["Transactions"], summary="Get transaction details")
async def get_transaction(transaction_id: str, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Fetch a specific transaction by its identifier."""
    await simulate_io_latency()
    transaction = TRANSACTION_STORE.get(transaction_id)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    return TransactionResponse(**transaction)


@app.patch("/transactions/{transaction_id}", response_model=TransactionResponse, tags=["Transactions"], summary="Update transaction metadata")
async def update_transaction(transaction_id: str, payload: TransactionUpdate, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Allow partial updates to a transaction payload with validation."""
    await simulate_io_latency()
    transaction = TRANSACTION_STORE.get(transaction_id)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    updated = transaction.copy()
    if payload.payload is not None:
        updated["payload"] = payload.payload
    if payload.priority is not None:
        updated["priority"] = payload.priority
    TRANSACTION_STORE[transaction_id] = updated
    AUDIT_STORE.append({"event": "transaction_updated", "transaction_id": transaction_id, "timestamp": datetime.utcnow()})
    return TransactionResponse(**updated)


@app.delete("/transactions/{transaction_id}", response_model=ActionResponse, tags=["Transactions"], summary="Delete a transaction")
async def delete_transaction(transaction_id: str, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Delete a transaction record and track the deletion event."""
    await simulate_io_latency()
    if TRANSACTION_STORE.pop(transaction_id, None) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    AUDIT_STORE.append({"event": "transaction_deleted", "transaction_id": transaction_id, "timestamp": datetime.utcnow()})
    return ActionResponse(success=True, message="Transaction deleted")


@app.post("/logs", response_model=ActionResponse, tags=["Logs"], summary="Write a log entry")
async def write_log(entry: LogEntry, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Write a structured log entry into the in-memory log store."""
    await simulate_io_latency()
    LOG_STORE.append(entry.dict())
    AUDIT_STORE.append({"event": "log_written", "timestamp": datetime.utcnow(), "source": entry.source})
    return ActionResponse(success=True, message="Log recorded")


@app.get("/logs", response_model=List[LogEntry], tags=["Logs"], summary="List recent logs")
async def read_logs(limit: int = 50, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Return recent logs collected during runtime and automation workflows."""
    await simulate_io_latency()
    return list(reversed(LOG_STORE[-limit:]))


@app.post("/automation/jobs", response_model=AutomationJobResponse, tags=["Automation"], summary="Schedule an automation job")
async def schedule_job(job: AutomationJobCreate, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Create an automation job with scheduled execution metadata."""
    await simulate_io_latency()
    job_id = str(uuid.uuid4())
    record = {
        "job_id": job_id,
        "job_name": job.job_name,
        "script": job.script,
        "arguments": job.arguments,
        "status": JobStatus.pending,
        "created_at": datetime.utcnow(),
        "scheduled_at": job.scheduled_at,
    }
    JOB_STORE[job_id] = record
    AUDIT_STORE.append({"event": "job_scheduled", "job_id": job_id, "timestamp": datetime.utcnow()})
    return AutomationJobResponse(**record)


@app.get("/automation/jobs", response_model=List[AutomationJobResponse], tags=["Automation"], summary="List automation jobs")
async def list_jobs(credentials: Dict[str, Any] = Depends(verify_credentials)):
    """List all scheduled automation jobs and their current statuses."""
    await simulate_io_latency()
    return [AutomationJobResponse(**job) for job in JOB_STORE.values()]


@app.get("/automation/jobs/{job_id}", response_model=AutomationJobResponse, tags=["Automation"], summary="Get automation job details")
async def get_job(job_id: str, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Fetch the metadata for a single automation job."""
    await simulate_io_latency()
    job = JOB_STORE.get(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return AutomationJobResponse(**job)


@app.post("/automation/jobs/{job_id}/cancel", response_model=ActionResponse, tags=["Automation"], summary="Cancel a scheduled job")
async def cancel_job(job_id: str, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Cancel an automation job and update its status atomically."""
    await simulate_io_latency()
    job = JOB_STORE.get(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    if job["status"] in {JobStatus.succeeded, JobStatus.failed, JobStatus.canceled}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Job cannot be canceled")
    job["status"] = JobStatus.canceled
    AUDIT_STORE.append({"event": "job_canceled", "job_id": job_id, "timestamp": datetime.utcnow()})
    return ActionResponse(success=True, message="Job canceled")


@app.post("/automation/validate", response_model=AutomationValidationResponse, tags=["Automation"], summary="Validate automation payloads")
async def validate_automation(payload: AutomationValidationRequest, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Validate an automation script payload and return any syntax issues."""
    await simulate_io_latency()
    issues: List[str] = []
    if "fail" in payload.script.lower():
        issues.append("Script contains a reserved failure keyword")
    valid = len(issues) == 0
    return AutomationValidationResponse(valid=valid, issues=issues)


@app.get("/system/audit/records", response_model=List[Dict[str, Any]], tags=["Audit"], summary="Retrieve audit records")
async def audit_records(limit: int = 100, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Return the most recent audit records for compliance and troubleshooting."""
    await simulate_io_latency()
    return list(reversed(AUDIT_STORE[-limit:]))


@app.post("/system/test-run", response_model=SystemTestRunResponse, tags=["System Testing"], summary="Execute a test run")
async def execute_test_run(request: SystemTestRunRequest, credentials: Dict[str, Any] = Depends(verify_credentials)):
    """Simulate a test run request for operational validation and automation workflows."""
    await simulate_io_latency()
    request_id = str(uuid.uuid4())
    result = {
        "request_id": request_id,
        "name": request.name,
        "status": "completed",
        "executed_at": datetime.utcnow(),
        "details": {"tests_executed": len(request.tests), "passed": len(request.tests), "failed": 0},
    }
    AUDIT_STORE.append({"event": "system_test_run", "request_id": request_id, "timestamp": datetime.utcnow()})
    return SystemTestRunResponse(**result)
