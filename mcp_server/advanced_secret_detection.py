from __future__ import annotations

import ast
import base64
import binascii
import math
import re
from collections import Counter
from typing import Any, Dict, Iterable, List
from urllib.parse import parse_qs, urlparse


SUSPICIOUS_KEYWORDS = ("api", "token", "secret", "password", "key", "auth", "credential")
ENV_SENSITIVE_MARKERS = ("SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL")
SENSITIVE_CONFIG_KEYS = (
    "JWT_SECRET",
    "ENCRYPTION_KEY",
    "PRIVATE_KEY",
    "DATABASE_PASSWORD",
)

MAX_CANDIDATE_LEN = 4096
MAX_URL_TOKEN_LEN = 2048


class _VariableConcatVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.constants: Dict[str, str] = {}
        self.reconstructed: List[str] = []

    def visit_Assign(self, node: ast.Assign) -> Any:  # pragma: no cover - ast runtime path
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            resolved = self._resolve_expr(node.value)
            if resolved:
                self.constants[var_name] = resolved
                self.reconstructed.append(resolved)
        self.generic_visit(node)

    def _resolve_expr(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value

        if isinstance(node, ast.Name):
            return self.constants.get(node.id)

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_expr(node.left)
            right = self._resolve_expr(node.right)
            if left is not None and right is not None:
                combined = left + right
                return combined[:MAX_CANDIDATE_LEN]

        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                    replacement = self.constants.get(value.value.id)
                    if replacement is None:
                        return None
                    parts.append(replacement)
                else:
                    return None
            return "".join(parts)[:MAX_CANDIDATE_LEN]

        return None


def _unique(items: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        value = item.strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _likely_secret(value: str) -> bool:
    lower_value = value.lower()
    return any(keyword in lower_value for keyword in SUSPICIOUS_KEYWORDS)


def detect_split_secrets(text: str) -> List[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    visitor = _VariableConcatVisitor()
    visitor.visit(tree)

    return _unique(secret for secret in visitor.reconstructed if len(secret) >= 12)


def detect_multiline_secrets(text: str) -> List[str]:
    pattern = re.compile(r"=\s*\((?:\s*[\"'][^\"']+[\"']\s*){2,}\)", re.MULTILINE)
    findings: List[str] = []
    for match in pattern.finditer(text):
        quoted = re.findall(r"[\"']([^\"']+)[\"']", match.group(0))
        joined = "".join(quoted)
        if len(joined) >= 12:
            findings.append(joined)
    return _unique(findings)


def detect_base64_secrets(text: str) -> List[str]:
    pattern = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
    findings: List[str] = []
    for candidate in pattern.findall(text):
        if len(candidate) > MAX_CANDIDATE_LEN:
            continue
        padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
        except (ValueError, binascii.Error):
            continue

        if decoded and (_likely_secret(decoded) or _likely_secret(candidate)):
            findings.append(decoded)
    return _unique(findings)


def detect_hex_secrets(text: str) -> List[str]:
    pattern = re.compile(r"\b(?:0x)?([A-Fa-f0-9]{24,})\b")
    findings: List[str] = []
    for candidate in pattern.findall(text):
        if len(candidate) % 2 != 0 or len(candidate) > MAX_CANDIDATE_LEN:
            continue
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if decoded and (_likely_secret(decoded) or len(decoded) >= 12):
            findings.append(decoded)
    return _unique(findings)


def detect_xor_encoded_secrets(text: str) -> List[str]:
    pattern = re.compile(r"\b[A-Fa-f0-9]{20,}\b")
    xor_keys = (1, 7, 13, 23, 42, 64, 127, 255)
    findings: List[str] = []

    for candidate in pattern.findall(text):
        if len(candidate) % 2 != 0 or len(candidate) > 512:
            continue
        try:
            data = bytes.fromhex(candidate)
        except ValueError:
            continue

        for key in xor_keys:
            decoded_bytes = bytes(byte ^ key for byte in data)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded and _likely_secret(decoded):
                findings.append(decoded)
                break

    return _unique(findings)


def detect_tokens_in_urls(text: str) -> List[str]:
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    findings: List[str] = []
    for url in url_pattern.findall(text):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for key, values in query.items():
            if _likely_secret(key):
                for value in values:
                    if value and len(value) <= MAX_URL_TOKEN_LEN:
                        findings.append(value)
    return _unique(findings)


def detect_comment_credentials(text: str) -> List[str]:
    pattern = re.compile(
        r"^[ \t]*(?:#|//|;|--)[^\n]*?(?:api[_-]?key|token|secret|password|pwd|credential)\s*[:=]\s*([\"']?)([^\n\"']{4,})\1",
        re.IGNORECASE | re.MULTILINE,
    )
    return _unique(match[1].strip() for match in pattern.findall(text))


def detect_env_variables(text: str) -> List[str]:
    patterns = [
        re.compile(r"os\.getenv\(\s*[\"']([A-Za-z0-9_]+)[\"']\s*\)"),
        re.compile(r"os\.environ\[\s*[\"']([A-Za-z0-9_]+)[\"']\s*\]"),
        re.compile(r"process\.env\.([A-Za-z0-9_]+)"),
    ]
    findings: List[str] = []
    for pattern in patterns:
        for env_name in pattern.findall(text):
            if any(marker in env_name.upper() for marker in ENV_SENSITIVE_MARKERS):
                findings.append(env_name)
    return _unique(findings)


def detect_hardcoded_credentials(text: str) -> List[str]:
    pattern = re.compile(
        r"\b(?:password|passwd|pwd|db_pass|db_password|api_key|secret|token)\b\s*[:=]\s*[\"']([^\"'\n]{6,})[\"']",
        re.IGNORECASE,
    )
    return _unique(pattern.findall(text))


def detect_sensitive_config_values(text: str) -> List[str]:
    key_pattern = "|".join(SENSITIVE_CONFIG_KEYS)
    pattern = re.compile(
        rf"\b(?:{key_pattern})\b\s*[:=]\s*[\"']?([^\"'\n\s]{{6,}})",
        re.IGNORECASE,
    )
    return _unique(pattern.findall(text))


def detect_high_entropy_strings(text: str) -> List[str]:
    pattern = re.compile(r"[A-Za-z0-9_\-+/=]{21,}")
    findings: List[str] = []
    for candidate in pattern.findall(text):
        if len(candidate) > MAX_CANDIDATE_LEN:
            continue
        entropy = _calculate_entropy(candidate)
        if entropy > 4.5:
            findings.append(candidate)
    return _unique(findings)


def detect_jwt_tokens(text: str) -> List[str]:
    pattern = re.compile(r"\b([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
    findings: List[str] = []

    for token in pattern.findall(text):
        if len(token) > MAX_CANDIDATE_LEN:
            continue
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            header = base64.urlsafe_b64decode(parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)).decode(
                "utf-8", errors="ignore"
            )
            payload = base64.urlsafe_b64decode(parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)).decode(
                "utf-8", errors="ignore"
            )
        except (ValueError, binascii.Error):
            continue

        if any(keyword in (header + payload).lower() for keyword in ("alg", "sub", "exp", "iss", "aud")):
            findings.append(token)

    return _unique(findings)


def _line_number_for_secret(text: str, secret: str) -> int:
    idx = text.find(secret)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _context_for_line(text: str, line_number: int, window: int = 1) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    start = max(0, line_number - 1 - window)
    end = min(len(lines), line_number + window)
    return "\n".join(lines[start:end])[:500]


def scan_obfuscated_secrets(text: str) -> List[Dict[str, Any]]:
    detectors = [
        detect_split_secrets,
        detect_multiline_secrets,
        detect_base64_secrets,
        detect_hex_secrets,
        detect_xor_encoded_secrets,
        detect_tokens_in_urls,
        detect_comment_credentials,
        detect_env_variables,
        detect_hardcoded_credentials,
        detect_sensitive_config_values,
        detect_high_entropy_strings,
        detect_jwt_tokens,
    ]

    findings: List[Dict[str, Any]] = []
    seen = set()

    for detector in detectors:
        for secret in detector(text):
            if secret in seen:
                continue
            seen.add(secret)
            line_number = _line_number_for_secret(text, secret)
            findings.append(
                {
                    "secret": secret,
                    "secret_type": "obfuscated",
                    "confidence": 0.8,
                    "reason": f"Obfuscated secret detected via {detector.__name__}",
                    "line_number": line_number,
                    "context": _context_for_line(text, line_number),
                }
            )

    return findings
