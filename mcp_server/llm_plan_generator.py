from __future__ import annotations

import time
import json
import logging
import os
from typing import Any, Dict, List
from urllib.parse import urlparse

#from google import genai
#from google.genai import types  # type: ignore

from groq import Groq

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

    def __init__(self, model: str = "llama-3.3-70b-versatile") -> None:
        self.model = model
        api_key = os.getenv("GEMINI_API_KEY")
        self.client = Groq(api_key=api_key) if api_key else None

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
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[
            {
                "role": "system",
                "content": "You are a strict JSON generator. Never output code or explanations."
            },
            {"role": "user", "content": prompt}
        ],
            max_tokens=1000
        )

        text = response.choices[0].message.content.strip()
        logger.info("LLM RESPONSE: %s", text)
        if not text:
            logger.error("LLM returned empty response")
            return None

        cleaned = (
        text.replace("```json", "")
            .replace("```python", "")
            .replace("```", "")
            .strip()
        )
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
        "You are a cybersecurity expert specializing in API key identification.\n\n"

        "Given a secret token and its surrounding context, determine:\n"
        "1. Which service likely issued the token\n"
        "2. A real API endpoint that can validate it\n\n"

        "Important rules:\n"
        "- Infer the provider from the token format if possible\n"
        "- Many providers use identifiable prefixes\n"
        "- If the service is unknown, return service='unknown'\n"
        "- Confidence must reflect how certain you are\n\n"

        "Examples of providers:\n"
        "- AWS\n"
        "- HuggingFace\n"
        "- GitHub\n"
        "- Stripe\n"
        "- Slack\n"
        "- Groq\n"
        "- OpenAI\n"
        "- Anthropic\n"
        "- Google\n\n"

        "Return ONLY JSON:\n"
        "{"
        '"service":"provider_name",'
        '"validation_plan":{'
        '"method":"GET",'
        '"endpoint":"https://real-api-endpoint",'
        '"auth_type":"Bearer"'
        "},"
        '"confidence":0.0'
        "}\n\n"

        f"Secret: {secret}\n"
        f"Context:\n{context[:8000]}"
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
            "You are a cybersecurity secret detection engine.\n\n"

            "Analyze the following source code and detect ALL hardcoded secrets.\n\n"

            "Rules:\n"
            "- Output MUST be valid JSON.\n"
            "- Do NOT output explanations.\n"
            "- Do NOT output code.\n"
            "- Do NOT output markdown.\n"
            "- Output ONLY a JSON array.\n\n"

            "Each object must follow this schema:\n"
            "{\n"
            '  "secret": "string",\n'
            '  "secret_type": "api_key|token|password|credential|private_key|unknown",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "reason": "why this is a secret",\n'
            '  "line_number": number,\n'
            '  "context": "relevant code snippet"\n'
            "}\n\n"

            "If no secrets exist return exactly:\n"
            "[]\n\n"

            "Example output:\n"
            "[\n"
            "  {\n"
            '    "secret":"abc123token",\n'
            '    "secret_type":"token",\n'
            '    "confidence":0.9,\n'
            '    "reason":"authentication token",\n'
            '    "line_number":10,\n'
            '    "context":"token = abc123token"\n'
            "  }\n"
            "]\n\n"

            f"File path: {path}\n\n"
            f"Source code:\n{content[:80000]}"
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