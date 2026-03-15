from __future__ import annotations

import logging
from typing import List
import re

from mcp_server.llm_plan_generator import LLMPlanGenerator
from mcp_server.models import DetectionRequest, DetectionResult
from mcp_server.security import secret_hash


logger = logging.getLogger("mcp_server.detector")


def detect_secrets(request: DetectionRequest) -> List[DetectionResult]:

    findings: List[DetectionResult] = []
    llm = LLMPlanGenerator()

    for src in request.files:

        llm_findings = llm.detect_secrets_in_file(src.path, src.content)

        # normalize response
        if isinstance(llm_findings, dict):
            llm_findings = [llm_findings]

        if not isinstance(llm_findings, list):
            llm_findings = []

        # add reconstructed secrets
        extra_secrets = reconstruct_split_secrets(src.content)

        for secret in extra_secrets:
            llm_findings.append({
                "secret": secret,
                "confidence": 0.95,
                "reason": "reconstructed split secret",
                "line_number": 1,
                "context": src.content[:200]
            })

        for item in llm_findings:

            if not isinstance(item, dict):
                continue

            secret = str(item.get("secret", "")).strip()
            confidence = float(item.get("confidence", 0.0) or 0.0)

            if not secret or confidence < request.min_confidence:
                continue

            reason = str(item.get("reason", "Contextual secret candidate"))
            context = str(item.get("context", "")) or src.content[:300]
            line_number = int(item.get("line_number", 1) or 1)

            service_info = llm.infer_service(secret, context)
            service = service_info.service

            print("DETECTED SERVICE:", service)

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

            # remove duplicates / partial secrets
            skip = False
            for f in findings:

                if secret in f.secret or f.secret in secret:

                    if len(secret) <= len(f.secret):
                        skip = True
                        break
                    else:
                        findings.remove(f)
                        break

            if skip:
                continue

            findings.append(finding)

            logger.info(
                "secret_detected_llm file=%s line=%s hash=%s confidence=%.2f",
                src.path,
                line_number,
                finding.secret_hash[:12],
                finding.confidence,
            )

    return findings


def reconstruct_split_secrets(content: str):

    lines = [l.strip() for l in content.splitlines() if l.strip()]
    reconstructed = []

    buffer = ""

    for line in lines:

        # fragment-like line
        if re.match(r"^[A-Za-z0-9_\-]{5,}$", line):

            buffer += line

            # if long enough, treat as potential secret
            if len(buffer) >= 20:
                reconstructed.append(buffer)

        else:
            buffer = ""

    return reconstructed