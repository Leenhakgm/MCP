from __future__ import annotations

import logging
from typing import List

from mcp_server.advanced_secret_detection import scan_obfuscated_secrets
from mcp_server.llm_plan_generator import LLMPlanGenerator
from mcp_server.models import DetectionRequest, DetectionResult
from mcp_server.security import secret_hash


logger = logging.getLogger("mcp_server.detector")


def detect_secrets(request: DetectionRequest) -> List[DetectionResult]:
    """Hybrid secret detection using deterministic obfuscation scanning + LLM context."""

    findings: List[DetectionResult] = []
    llm = LLMPlanGenerator()

    for src in request.files:
        combined_findings = []

        # deterministic pre-scan for obfuscated and encoded secret patterns
        obfuscated_findings = scan_obfuscated_secrets(src.content)
        combined_findings.extend(obfuscated_findings)

        llm_findings = llm.detect_secrets_in_file(src.path, src.content)

        # normalize response (Gemini sometimes returns dict instead of list)
        if isinstance(llm_findings, dict):
            llm_findings = [llm_findings]

        if not isinstance(llm_findings, list):
            llm_findings = []

        combined_findings.extend(llm_findings)

        for item in combined_findings:

            if not isinstance(item, dict):
                continue

            secret = str(item.get("secret", "")).strip()
            confidence = float(item.get("confidence", 0.0) or 0.0)

            if not secret or confidence < request.min_confidence:
                continue

            reason = str(item.get("reason", "Contextual secret candidate"))
            context = str(item.get("context", "")) or src.content[:300]
            line_number = int(item.get("line_number", 1) or 1)

            service = "unknown"
            if item.get("secret_type") != "obfuscated":
                service_info = llm.infer_service(secret, context)
                service = service_info.service

            finding = DetectionResult(
                secret=secret,
                confidence=max(0.0, min(confidence, 1.0)),
                reason=reason,
                context=context,
                source_file=src.path,
                line_number=line_number,
                secret_hash=secret_hash(secret),
                service=service,
            )

            findings.append(finding)

            logger.info(
                "secret_detected_llm file=%s line=%s hash=%s confidence=%.2f",
                src.path,
                line_number,
                finding.secret_hash[:12],
                finding.confidence,
            )

    return findings
