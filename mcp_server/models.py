from __future__ import annotations

from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ValidationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class SourceFile(BaseModel):
    path: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)


class DetectionResult(BaseModel):
    secret: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str
    context: str
    source_file: str
    line_number: int
    secret_hash: str


class DetectionRequest(BaseModel):
    files: List[SourceFile]
    min_confidence: float = Field(0.55, ge=0.0, le=1.0)


class DetectionResponse(BaseModel):
    detections: List[DetectionResult]


class ValidationPlan(BaseModel):
    method: Literal["GET"]
    endpoint: HttpUrl
    auth_type: str


class ServiceInferenceResponse(BaseModel):
    is_secret: bool
    service: str
    secret_type: str
    validation_plan: ValidationPlan
    confidence: float
    reason: str


class ServiceInferenceRequest(BaseModel):
    secret: str
    context: str


class ValidationExecutionRequest(BaseModel):
    secret: str
    plan: ValidationPlan
    source: Optional[str] = "external"


class ValidationExecutionResponse(BaseModel):
    status: ValidationStatus
    risk: RiskLevel
    reason: str


class ScanRequest(BaseModel):
    files: List[SourceFile]
    min_detection_confidence: float = Field(0.55, ge=0.0, le=1.0)
    min_plan_confidence: float = Field(0.6, ge=0.0, le=1.0)


class ScanSecretResult(BaseModel):
    detection: DetectionResult
    inference: Optional[ServiceInferenceResponse] = None
    validation: Optional[ValidationExecutionResponse] = None


class ScanResponse(BaseModel):
    results: List[ScanSecretResult]
    summary: Dict[str, int]


class PluginValidationRequest(BaseModel):
    service: str
    secret: str
    context: str


class PluginValidationResponse(BaseModel):
    status: ValidationStatus
    reason: str




class RepoScanRequest(BaseModel):
    path: Optional[str] = None
    github_url: Optional[HttpUrl] = None
    min_detection_confidence: float = Field(0.55, ge=0.0, le=1.0)
    min_validation_confidence: float = Field(0.6, ge=0.0, le=1.0)
    max_workers: int = Field(4, ge=1, le=16)
    validation_timeout_seconds: int = Field(30, ge=1, le=120)
    report_output_path: Optional[str] = None
    config_path: Optional[str] = None


class RepoScanResult(BaseModel):
    file: str
    secret: str
    service: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    validation_result: Dict[str, object]


class RepoScanResponse(BaseModel):
    total_files_scanned: int
    total_secrets_detected: int
    total_valid_secrets: int
    results: List[RepoScanResult]

class InternalEndpointRule(BaseModel):
    service: str
    endpoint: HttpUrl
    notes: Optional[str] = None

    @field_validator("endpoint")
    @classmethod
    def enforce_https(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme != "https":
            raise ValueError("Only HTTPS internal endpoints are allowed")
        return v
