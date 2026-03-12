from __future__ import annotations

import time
import json
import logging
import os
from typing import Any, Dict, List
from urllib.parse import urlparse

from google import genai
from google.genai import types  # type: ignore

from mcp_server.models import ServiceInferenceResponse, ValidationPlan


logger = logging.getLogger("mcp_server.llm")


DEFAULT_VALIDATION_ENDPOINT = "https://invalid.local"


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
            is_secret=False,
            service="unknown",
            secret_type="unknown",
            validation_plan=ValidationPlan(
                method="GET",
                endpoint=DEFAULT_VALIDATION_ENDPOINT,
                auth_type="unknown",
            ),
            confidence=0.0,
            reason="LLM unavailable or parse failed",
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
        
        time.sleep(2)
        response = self.client.models.generate_content(
            model=self.model,
            contents=[prompt],
            config=types.GenerateContentConfig(temperature=0.0, max_output_tokens=2000,)
        )

        text = (response.text or "").strip()
        logger.info("LLM RESPONSE: %s", text[:300])
        if not text:
            logger.error("LLM returned empty response")
            return None

        cleaned = text.replace("```json", "").replace("```", "").strip()
        decoder = json.JSONDecoder()

        def _try_decode(candidate: str):
            candidate = candidate.strip()
            if not candidate:
                return None
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

            for i, ch in enumerate(candidate):
                if ch not in "[{":
                    continue
                try:
                    obj, _ = decoder.raw_decode(candidate[i:])
                    return obj
                except json.JSONDecodeError:
                    continue
            return None

        def _repair_truncated(candidate: str) -> str:
            stack: List[str] = []
            in_string = False
            escape = False

            for ch in candidate:
                if in_string:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_string = False
                    continue

                if ch == '"':
                    in_string = True
                elif ch == "{":
                    stack.append("}")
                elif ch == "[":
                    stack.append("]")
                elif ch in "}]" and stack and stack[-1] == ch:
                    stack.pop()

            repaired = candidate
            if in_string:
                repaired += '"'
            if stack:
                repaired += "".join(reversed(stack))
            return repaired

        parsed = _try_decode(cleaned)
        if parsed is not None:
            return parsed

        start_positions = [i for i, ch in enumerate(cleaned) if ch in "[{"]
        for start in start_positions:
            parsed = _try_decode(cleaned[start:])
            if parsed is not None:
                return parsed

            repaired = _repair_truncated(cleaned[start:])
            parsed = _try_decode(repaired)
            if parsed is not None:
                logger.warning("llm_parse_recovered_truncated_json")
                return parsed

        logger.error("llm_parse_error raw=%s", cleaned[:500])
        return None
        # ---------------------------------------------------
        # Quick service detection
        # ---------------------------------------------------
    def quick_service_guess(self, secret: str):
        print("PREFIX CHECK:", secret)

        if not secret:
            return None

        # normalize secret
        secret = secret.strip().strip('"').strip("'")

        if secret.startswith("hf_"):
            return "huggingface"

        if secret.startswith("sk_"):
            return "stripe"

        if secret.startswith("AKIA"):
            return "aws"

        if secret.startswith("ghp_"):
            return "github"

        if secret.startswith("xoxb-"):
            return "slack"

        if secret.startswith("AIza"):
            return "google"

        return None

    def _sanitize_validation_plan(self, plan: Any) -> Dict[str, Any]:

        if not isinstance(plan, dict):
            plan = {}

        endpoint = str(plan.get("endpoint", "")).strip()

        try:
            parsed = urlparse(endpoint)
            is_valid = bool(parsed.scheme and parsed.netloc)
        except Exception:
            is_valid = False

        if not is_valid:
            endpoint = "https://invalid.local"

        return {
            "method": "GET",
            "endpoint": endpoint,
            "auth_type": str(plan.get("auth_type", "unknown")),
        }

    # ---------------------------------------------------
    # Infer service using LLM
    # ---------------------------------------------------
    def infer_service(self, secret: str, context: str) -> ServiceInferenceResponse:

        guess = self.quick_service_guess(secret)

        if guess:
            prompt = (
                "You are a cybersecurity expert.\n\n"
                "A secret token was detected and the service is already known.\n"
                f"The service is: {guess}\n\n"

                "Generate the correct API endpoint that can validate this token.\n"

                "Examples:\n"
                "AWS -> https://sts.amazonaws.com\n"
                "HuggingFace -> https://huggingface.co/api/whoami-v2\n"
                "GitHub -> https://api.github.com/user\n"
                "Stripe -> https://api.stripe.com/v1/account\n"
                "Slack -> https://slack.com/api/auth.test\n\n"

                "Return ONLY JSON:\n"
                "{"
                '"service":"service_name",'
                '"validation_plan":{'
                '"method":"GET",'
                '"endpoint":"https://real-api-endpoint",'
                '"auth_type":"Bearer"'
                "},"
                '"confidence":0.9'
                "}"
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
                "service": guess,
                "confidence": payload.get("confidence", 0.9),
                "reason": "Prefix-based service inference",
                "validation_plan": self._sanitize_validation_plan(
                    payload.get("validation_plan", {})
                ),
            }

            try:
                return ServiceInferenceResponse.model_validate(normalized)

            except Exception:
                logger.exception("prefix_model_validate_error payload=%s", normalized)
                return self._fallback()

        prompt = (
            "You are a cybersecurity expert that validates API secrets.\n\n"

            "Your task:\n"
            "1. Identify which service the secret belongs to.\n"
            "2. Generate a REAL API endpoint that can validate the secret.\n\n"

            "Important rules:\n"
            "- DO NOT return placeholder endpoints.\n"
            "- DO NOT use example.com.\n"
            "- The endpoint must be a real API endpoint of the detected service.\n"
            "- The endpoint must return HTTP 200 when the secret is valid.\n"
            "- The endpoint must return HTTP 401 or 403 when the secret is invalid.\n\n"

            "Examples:\n"
            "AWS -> https://sts.amazonaws.com\n"
            "HuggingFace -> https://huggingface.co/api/whoami-v2\n"
            "GitHub -> https://api.github.com/user\n"
            "Stripe -> https://api.stripe.com/v1/account\n"
            "Slack -> https://slack.com/api/auth.test\n\n"

            "Return ONLY JSON in this format:\n"

            "{"
            '"service":"service_name",'
            '"validation_plan":{'
            '"method":"GET",'
            '"endpoint":"https://real-api-endpoint",'
            '"auth_type":"Bearer|Basic|Header"'
            "},"
            '"confidence":0.0'
            "}\n\n"

            f"Secret: {secret}\n"
            f"Context:\n{context[:4000]}"
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
            "validation_plan": self._sanitize_validation_plan(
                payload.get("validation_plan", {})
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
            "Your job is to detect hardcoded secrets in source code.\n\n"

            "Look for patterns like:\n"
            "- AWS keys (AKIA...)\n"
            "- Stripe keys (sk_...)\n"
            "- HuggingFace tokens (hf_...)\n"
            "- GitHub tokens (ghp_...)\n"
            "- API keys\n"
            "- passwords\n\n"

            "IMPORTANT:\n"
            "Return ONLY JSON.\n"
            "No explanations.\n\n"

            "Output format:\n"
            "[{"
            '"secret":"value",'
            '"secret_type":"api_key|token|password|credential|private_key|unknown",'
            '"confidence":0.9,'
            '"reason":"why this is a secret",'
            '"line_number":1,'
            '"context":"line of code"'
            "}]\n\n"

            "If no secrets exist return []\n\n"

            f"File path: {path}\n\n"
            f"Source code:\n{content[:1500]}"
            )
        payload = self._ask_json(prompt)

        if not payload:
            return []

        # allow single object
        if isinstance(payload, dict):
            payload = [payload]

        if not isinstance(payload, list):
            return []

        # accept single-object responses
        if isinstance(payload, dict):
            payload = [payload]

        if not isinstance(payload, list):
            return []

        results: List[Dict[str, Any]] = []

        for item in payload[:max_findings]:

            if not isinstance(item, dict):
                continue

            secret = str(item.get("secret", "")).strip()

            if not secret:
                continue

            results.append(item)

        return results
