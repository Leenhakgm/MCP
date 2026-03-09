from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

from google import genai
from google.genai import types  # type: ignore

from mcp_server.models import ServiceInferenceResponse, ValidationPlan


logger = logging.getLogger("mcp_server.llm")


class LLMPlanGenerator:
    """
    LLM module responsible for:
    1. Contextual secret detection
    2. Service inference
    3. Generating validation endpoints for MCP
    """

    def __init__(self, model: str = "gemini-2.5-flash") -> None:
        self.model = model
        api_key = os.getenv("GEMINI_API_KEY")
        self.client = genai.Client(api_key=api_key) if api_key else None

    # ---------------------------------------------------
    # Fallback if LLM fails
    # ---------------------------------------------------
    def _fallback(self) -> ServiceInferenceResponse:
        return ServiceInferenceResponse(
            service="unknown",
            validation_plan=ValidationPlan(
                method="GET",
                endpoint="unknown",
                auth_type="unknown",
            ),
            confidence=0.0,
        )

    # ---------------------------------------------------
    # Robust JSON parser
    # Handles:
    # - JSON object
    # - JSON array
    # - truncated responses
    # ---------------------------------------------------
    def _ask_json(self, prompt: str):

        if not self.client:
            return None

        response = self.client.models.generate_content(
            model=self.model,
            contents=[prompt],
            config=types.GenerateContentConfig(temperature=0.0),
        )

        text = (response.text or "").strip()

        try:
            text = text.replace("```json", "").replace("```", "").strip()

            # Try direct JSON
            try:
                return json.loads(text)
            except Exception:
                pass

            # Try extracting array
            start = text.find("[")
            end = text.rfind("]")

            if start != -1:
                if end == -1:
                    # JSON truncated → close it
                    text = text[start:] + "]"
                else:
                    text = text[start:end + 1]

                try:
                    return json.loads(text)
                except Exception:
                    pass

            # Try extracting object
            start = text.find("{")
            end = text.rfind("}")

            if start != -1 and end != -1:
                try:
                    return json.loads(text[start:end + 1])
                except Exception:
                    pass

        except Exception:
            logger.exception("llm_parse_error raw=%s", text[:500])

        return None
        # ---------------------------------------------------
        # Quick service detection
        # ---------------------------------------------------
    def quick_service_guess(self, secret: str):

        if secret.startswith("hf_"):
            return "huggingface"

        if secret.startswith("sk_"):
            return "stripe"

        if secret.startswith("AKIA"):
            return "aws"

        if secret.startswith("ghp_"):
            return "github"

        return None

    # ---------------------------------------------------
    # Infer service using LLM
    # ---------------------------------------------------
    def infer_service(self, secret: str, context: str) -> ServiceInferenceResponse:

        guess = self.quick_service_guess(secret)

        if guess:
            return ServiceInferenceResponse(
                service=guess,
                validation_plan=ValidationPlan(
                    method="GET",
                    endpoint="unknown",
                    auth_type="Bearer",
                ),
                confidence=0.9,
            )

        if not self.client:
            logger.warning("gemini_unavailable_missing_api_key")
            return self._fallback()

        prompt = (
            "You are an expert cybersecurity assistant specialized in detecting secrets in source code.\n\n"

            "Your task:\n"
            "1. Identify which service the secret belongs to.\n"
            "2. Generate a public API endpoint that can validate the secret.\n\n"

            "The secret may belong to ANY service such as:\n"
            "cloud providers, SaaS APIs, ML services, payment gateways, databases, or developer platforms.\n\n"

            "Use these clues:\n"
            "- secret prefix or format\n"
            "- variable names\n"
            "- nearby URLs\n"
            "- SDK imports\n"
            "- environment variables\n\n"

            "Return ONLY a JSON object.\n\n"

            "{"
            '"service":"service_name_or_unknown",'
            '"validation_plan":{'
            '"method":"GET",'
            '"endpoint":"https://api.service.com/endpoint_or_unknown",'
            '"auth_type":"Bearer|Basic|Header|unknown"'
            "},"
            '"confidence":0.0'
            "}\n\n"

            f"Secret value: {secret}\n\n"
            f"Code context:\n{context[:2000]}"
        )

        payload = self._ask_json(prompt)

        if payload is None:
            return self._fallback()

        if isinstance(payload, list):
            if len(payload) == 0:
                return self._fallback()
            payload = payload[0]

        if not isinstance(payload, dict):
            return self._fallback()

        normalized = {
            "is_secret": True,
            "secret_type": "api_key",
            "service": str(payload.get("service", "unknown")).lower(),
            "confidence": payload.get("confidence", 0.5),
            "reason": "LLM inferred service",
            "validation_plan": payload.get(
                "validation_plan",
                {
                    "method": "GET",
                    "endpoint": "unknown",
                    "auth_type": "unknown",
                },
            ),
        }

        try:
            return ServiceInferenceResponse.model_validate(normalized)

        except Exception:
            logger.exception("llm_model_validate_error payload=%s", normalized)
            return self._fallback()

    # ---------------------------------------------------
    # Detect secrets inside a file
    # ---------------------------------------------------
    def detect_secrets_in_file(
        self,
        path: str,
        content: str,
        max_findings: int = 20,
    ) -> List[Dict[str, Any]]:

        if not self.client:
            return []

        prompt = (
            "You are a cybersecurity code auditor.\n\n"

            "Detect ANY hardcoded secrets in the following source code.\n\n"

            "Secrets may include:\n"
            "- API keys\n"
            "- tokens\n"
            "- passwords\n"
            "- credentials\n"
            "- private keys\n"
            "- database connection strings\n"
            "- cloud credentials\n\n"

            "Return ONLY valid JSON array.\n\n"

            '[{'
            '"secret":"",'
            '"secret_type":"api_key|token|password|credential|private_key|unknown",'
            '"confidence":0.0,'
            '"reason":"",'
            '"line_number":1,'
            '"context":""'
            "}]\n\n"

            f"Limit to {max_findings} findings.\n"
            f"File path: {path}\n\n"
            f"Source code:\n{content[:1500]}"
        )

        payload = self._ask_json(prompt)

        if not isinstance(payload, list):
            return []

        results: List[Dict[str, Any]] = []

        for item in payload[:max_findings]:
            if not isinstance(item, dict):
                continue
            results.append(item)

        return results