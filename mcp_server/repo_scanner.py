from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple

from mcp_server.detector import detect_secrets
from mcp_server.models import (
    DetectionRequest,
    RepoScanRequest,
    RepoScanResponse,
    RepoScanResult,
    SourceFile,
    ValidationExecutionResponse,
)
from mcp_server.security import redact_secret
from mcp_server.validator import validate_secret

logger = logging.getLogger("mcp_server.repo_scanner")

DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024
DEFAULT_MAX_WORKERS = 6
DEFAULT_IGNORE_PATTERNS = {".git", "node_modules", "__pycache__"}


class ResultCache:
    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[Any, Any]] = {}
        self._lock = Lock()

    def get(self, key: str) -> Optional[Tuple[Any, Any]]:
        with self._lock:
            return self._cache.get(key)

    def set(self, key: str, value: Tuple[Any, Any]) -> None:
        with self._lock:
            self._cache[key] = value


def load_ignore_patterns(config_path: str | None = None) -> Set[str]:
    cfg = Path(config_path or "mcp_server/repo_scanner_config.json")

    if not cfg.exists():
        return set(DEFAULT_IGNORE_PATTERNS)

    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
        return set(data.get("ignore_patterns", [])) | DEFAULT_IGNORE_PATTERNS
    except Exception:
        logger.warning("invalid_repo_scanner_config path=%s", cfg)
        return set(DEFAULT_IGNORE_PATTERNS)


def _is_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:2048]
    except Exception:
        return True
    return b"\x00" in sample


def _safe_local_root(path: str, workspace_root: Path) -> Path:
    candidate = Path(path).expanduser().resolve()

    if not str(candidate).startswith(str(workspace_root.resolve())):
        raise ValueError("Path traversal blocked")

    if not candidate.exists() or not candidate.is_dir():
        raise ValueError("Path must be an existing directory")

    return candidate


def _clone_github_repo(github_url: str) -> Tuple[Path, Path]:
    temp_parent = Path(tempfile.mkdtemp(prefix="repo-scan-"))
    target = temp_parent / "repo"

    cmd = ["git", "clone", "--depth", "1", github_url, str(target)]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    if result.returncode != 0:
        shutil.rmtree(temp_parent, ignore_errors=True)
        raise ValueError(f"Git clone failed: {result.stderr.strip()}")

    return temp_parent, target


def os_walk(root: Path):
    import os
    return os.walk(root)


def gather_source_files(root: Path, ignore_patterns: Set[str]) -> List[SourceFile]:
    files: List[SourceFile] = []

    for current, dirs, names in os_walk(root):

        dirs[:] = [d for d in dirs if d not in ignore_patterns]

        for name in names:
            path = Path(current) / name

            if any(part in ignore_patterns for part in path.parts):
                continue

            if not path.is_file():
                continue

            if path.stat().st_size > DEFAULT_MAX_FILE_SIZE:
                continue

            if _is_binary(path):
                continue

            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
            except Exception:
                continue

            if not content or not content.strip():
                continue

            files.append(SourceFile(path=str(path), content=content))

    return files


def generate_validation_plan(secret: str, context: str, infer_service):
    """Run service inference using LLM or prefix detection."""
    return infer_service(secret, context)


def validate_plan(secret: str, endpoint: str, execute_validation) -> ValidationExecutionResponse:
    return validate_secret(secret, endpoint, execute_validation)


def _process_detection(
    detection,
    infer_service,
    execute_validation,
    cache: ResultCache,
    min_validation_confidence: float,
) -> RepoScanResult:

    cached = cache.get(detection.secret_hash)

    if cached:
        inference, validation = cached

    else:

        try:
            inference = generate_validation_plan(
                detection.secret,
                detection.context,
                infer_service
            )
        except Exception as exc:
            logger.exception("service_inference_failed secret_hash=%s", detection.secret_hash)
            inference = None

        validation = None

        # skip validation if service inference confidence is low
        if inference and getattr(inference, "confidence", 0.0) < 0.5:
            logger.info(
                "validation_skipped_low_service_confidence secret_hash=%s service=%s confidence=%.2f",
                detection.secret_hash[:12],
                getattr(inference, "service", "unknown"),
                getattr(inference, "confidence", 0.0),
            )

        elif (
            inference
            and detection.confidence >= min_validation_confidence
            and getattr(inference, "service", "unknown") != "unknown"
            and getattr(inference, "validation_plan", None)
        ):

            endpoint = str(inference.validation_plan.endpoint)

            if endpoint and endpoint != "https://invalid.local":
                try:
                    validation = validate_plan(
                        detection.secret,
                        endpoint,
                        execute_validation,
                    )
                except Exception:
                    logger.exception("validation_failed endpoint=%s", endpoint)

        cache.set(detection.secret_hash, (inference, validation))

    service_name = "unknown"

    if inference and getattr(inference, "service", None):
        service_name = inference.service

    return RepoScanResult(
        file=detection.source_file,
        secret=redact_secret(detection.secret),
        service=service_name,
        confidence=detection.confidence,
        validation_result=validation.model_dump()
        if validation
        else {"status": "INVALID", "reason": "Low service inference confidence"},
    )


def _export_report(report: RepoScanResponse, output_file: str | None):

    if not output_file:
        return

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )


def scan_repository(
    request: RepoScanRequest,
    infer_service,
    execute_validation,
    workspace_root: Path,
) -> RepoScanResponse:

    start = time.time()

    ignore_patterns = load_ignore_patterns(request.config_path)

    temp_parent: Path | None = None

    if request.github_url:
        temp_parent, root = _clone_github_repo(str(request.github_url))

    elif request.path:
        root = _safe_local_root(request.path, workspace_root)

    else:
        raise ValueError("Either path or github_url must be provided")

    logger.info("repo_scan_start root=%s", root)

    try:

        source_files = gather_source_files(root, ignore_patterns)

        logger.info(
            "repo_scan_files_discovered count=%s",
            len(source_files),
        )

        detections = detect_secrets(
            DetectionRequest(
                files=source_files,
                min_confidence=request.min_detection_confidence,
            )
        )

        logger.info(
            "repo_scan_llm_secrets_detected count=%s",
            len(detections),
        )

        cache = ResultCache()

        results: List[RepoScanResult] = []

        workers = min(request.max_workers, DEFAULT_MAX_WORKERS)

        with ThreadPoolExecutor(max_workers=workers) as pool:

            futures = {
                pool.submit(
                    _process_detection,
                    det,
                    infer_service,
                    execute_validation,
                    cache,
                    request.min_validation_confidence,
                ): det
                for det in detections
            }

            for future in as_completed(futures):

                try:
                    results.append(future.result())

                except Exception as exc:

                    det = futures[future]

                    results.append(
                        RepoScanResult(
                            file=det.source_file,
                            secret=redact_secret(det.secret),
                            service="unknown",
                            confidence=det.confidence,
                            validation_result={
                                "status": "ERROR",
                                "reason": str(exc),
                            },
                        )
                    )

        valid_count = sum(
            1 for r in results
            if r.validation_result.get("status") == "VALID"
        )

        report = RepoScanResponse(
            total_files_scanned=len(source_files),
            total_secrets_detected=len(detections),
            total_valid_secrets=valid_count,
            results=results,
        )

        _export_report(report, request.report_output_path)

        logger.info(
            "repo_scan_complete files=%s secrets=%s valid=%s took_s=%.2f",
            report.total_files_scanned,
            report.total_secrets_detected,
            report.total_valid_secrets,
            time.time() - start,
        )

        return report

    finally:
        if temp_parent:
            shutil.rmtree(temp_parent, ignore_errors=True)


async def scan_repository_async(
    request: RepoScanRequest,
    infer_service,
    execute_validation,
    workspace_root: Path,
) -> RepoScanResponse:

    return await asyncio.to_thread(
        scan_repository,
        request,
        infer_service,
        execute_validation,
        workspace_root,
    )