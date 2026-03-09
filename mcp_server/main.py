from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict

import requests
from fastapi import FastAPI, HTTPException, Request

from mcp_server.detector import detect_secrets
from mcp_server.llm_plan_generator import LLMPlanGenerator
from mcp_server.models import (
    RepoScanRequest,
    RepoScanResponse,
    DetectionRequest,
    DetectionResponse,
    PluginValidationRequest,
    PluginValidationResponse,
    ScanRequest,
    ScanResponse,
    ScanSecretResult,
    ServiceInferenceRequest,
    ServiceInferenceResponse,
    ValidationExecutionRequest,
    ValidationExecutionResponse,
    ValidationStatus,
    RiskLevel,
)
from mcp_server.repo_scanner import scan_repository, scan_repository_async
from mcp_server.security import SlidingWindowRateLimiter, redact_secret, validate_url_safety


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("mcp_server")

app = FastAPI(title="LLM-Based Dynamic Secret Detection and Validation Engine", version="1.0.0")
rate_limiter = SlidingWindowRateLimiter()
llm = LLMPlanGenerator()
executor = ThreadPoolExecutor(max_workers=8)
plugins: Dict[str, Callable[[PluginValidationRequest], PluginValidationResponse]] = {}


def _rate_limit(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


@app.post("/detect", response_model=DetectionResponse)
def detect(request: DetectionRequest, raw_request: Request) -> DetectionResponse:
    _rate_limit(raw_request)
    detections = detect_secrets(request)
    return DetectionResponse(detections=detections)


@app.post("/infer-plan", response_model=ServiceInferenceResponse)
def infer_plan(request: ServiceInferenceRequest, raw_request: Request) -> ServiceInferenceResponse:
    _rate_limit(raw_request)
    return llm.infer_service(request.secret, request.context)


def execute_validation(secret: str, endpoint: str) -> ValidationExecutionResponse:
    try:
        validate_url_safety(endpoint)
        response = requests.get(
            endpoint,
            headers={"Authorization": f"Bearer {secret}"},
            timeout=5,
        )
        if response.status_code == 200:
            return ValidationExecutionResponse(status=ValidationStatus.VALID, risk=RiskLevel.HIGH, reason="Endpoint accepted secret")
        if response.status_code in {401, 403}:
            return ValidationExecutionResponse(status=ValidationStatus.INVALID, risk=RiskLevel.LOW, reason=f"Rejected by endpoint ({response.status_code})")
        return ValidationExecutionResponse(status=ValidationStatus.UNKNOWN, risk=RiskLevel.MEDIUM, reason=f"Unexpected status ({response.status_code})")
    except Exception as exc:
        logger.exception("validation_error endpoint=%s secret=%s err=%s", endpoint, redact_secret(secret), exc)
        return ValidationExecutionResponse(status=ValidationStatus.ERROR, risk=RiskLevel.MEDIUM, reason=str(exc))


@app.post("/validate", response_model=ValidationExecutionResponse)
def validate(request: ValidationExecutionRequest, raw_request: Request) -> ValidationExecutionResponse:
    _rate_limit(raw_request)
    if request.plan.method != "GET":
        raise HTTPException(status_code=400, detail="Only GET method is allowed")
    return execute_validation(request.secret, str(request.plan.endpoint))


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest, raw_request: Request) -> ScanResponse:
    _rate_limit(raw_request)

    detections = detect_secrets(
        DetectionRequest(files=request.files, min_confidence=request.min_detection_confidence)
    )

    futures = {}
    for d in detections:
        futures[executor.submit(llm.infer_service, d.secret, d.context)] = d

    results = []
    for future in as_completed(futures):
        d = futures[future]
        inference = future.result()
        validation = None

        if inference.confidence >= request.min_plan_confidence:

            endpoint = str(inference.validation_plan.endpoint)

            plugin = plugins.get(inference.service)

            if plugin:
                plugin_result = plugin(
                    PluginValidationRequest(
                    service=inference.service,
                    secret=d.secret,
                    context=d.context
                    )
                )

                validation = ValidationExecutionResponse(
                    status=plugin_result.status,
                    risk=RiskLevel.MEDIUM,
                    reason=f"Plugin validation: {plugin_result.reason}",
                )

            else:
                validation = execute_validation(
                d.secret,
                endpoint
            )

        results.append(ScanSecretResult(detection=d, inference=inference, validation=validation))

    summary = {
        "detected": len(detections),
        "validated": sum(1 for r in results if r.validation is not None),
        "valid": sum(1 for r in results if r.validation and r.validation.status == ValidationStatus.VALID),
        "invalid": sum(1 for r in results if r.validation and r.validation.status == ValidationStatus.INVALID),
        "errors": sum(1 for r in results if r.validation and r.validation.status == ValidationStatus.ERROR),
    }

    logger.info("scan_completed detected=%s validated=%s", summary["detected"], summary["validated"])
    return ScanResponse(results=results, summary=summary)


@app.post("/plugins/{service}")
def register_plugin(service: str) -> dict:
    if service in plugins:
        raise HTTPException(status_code=409, detail="Plugin already registered")

    def _not_implemented(_: PluginValidationRequest) -> PluginValidationResponse:
        return PluginValidationResponse(status=ValidationStatus.UNKNOWN, reason="Plugin stub not implemented")

    plugins[service] = _not_implemented
    return {"status": "registered", "service": service}


@app.post("/scan-repo", response_model=RepoScanResponse)
def scan_repo(request: RepoScanRequest, raw_request: Request) -> RepoScanResponse:
    _rate_limit(raw_request)
    try:
        return scan_repository(
            request=request,
            infer_service=llm.infer_service,
            execute_validation=execute_validation,
            workspace_root=Path.cwd(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan-repo-async", response_model=RepoScanResponse)
async def scan_repo_async(request: RepoScanRequest, raw_request: Request) -> RepoScanResponse:
    _rate_limit(raw_request)
    try:
        return await scan_repository_async(
            request=request,
            infer_service=llm.infer_service,
            execute_validation=execute_validation,
            workspace_root=Path.cwd(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
