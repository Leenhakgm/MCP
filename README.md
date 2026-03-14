# MCP Sentinel

MCP Sentinel is an AI-powered secret detection and validation engine for repositories and local file collections. It combines LLM-based contextual analysis with controlled API validation to identify likely credentials, determine exposure risk, and produce actionable security findings.

## Features

- LLM-based secret detection with contextual reasoning
- Obfuscated secret detection across noisy code and config patterns
- Encoded credential detection (e.g., Base64-like payloads)
- API validation engine for service-aware secret verification
- GitHub repository scanning and local path scanning
- CLI and FastAPI interfaces for automation and integration
- Parallel validation pipeline with bounded worker controls

## Architecture

```text
+---------------------------+        +---------------------------+        +------------------------------+
| Client / CI / SCM Hook    | -----> | FastAPI API Layer         | -----> | Audit + Structured Logging   |
+---------------------------+        +---------------------------+        +------------------------------+
                                              |        |          \
                                              |        |           \
                                              v        v            v
                                +-----------------+  +----------------------+  +----------------------+
                                | Module 1        |  | Module 2             |  | Module 3             |
                                | Secret Detector |  | LLM Plan Generator   |  | Validation Executor  |
                                +-----------------+  +----------------------+  +----------------------+
                                              \\         /                         |
                                               \\       /                          |
                                                v     v                           v
                                              +---------------------------------------+
                                              | Repo Scanner (sync + async)           |
                                              | Recursive walk + filtering + caching   |
                                              +---------------------------------------+
                                                               |
                                                               v
                                              +---------------------------------------+
                                              | Parallel Validation Queue              |
                                              +---------------------------------------+
```

### Module Overview

- **Secret Detector**: Identifies potential credentials using pattern signals and context-aware LLM inference.
- **LLM Plan Generator**: Produces constrained validation plans (service, endpoint, method rules, confidence).
- **Validation Executor**: Executes hardened checks against approved HTTPS endpoints with timeout controls.
- **Repo Scanner**: Walks local or cloned repositories, filters unsupported paths/files, and extracts candidate content.
- **Parallel Validation Queue**: Processes candidate secrets concurrently using a bounded thread pool and caching.

## Installation

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r mcp_server/requirements.txt
```

Optional CLI install:

```bash
python -m pip install .
```

## Configuration

Set environment variables before running scans:

```bash
export GEMINI_API_KEY="<your-key>"
```

- `GEMINI_API_KEY`: Enables LLM inference for contextual secret analysis and validation planning.
  - If unset, detections may fall back to reduced-confidence/unknown behavior depending on runtime settings.

## Usage

### CLI Example

```bash
mcpsentinel scan ./repo
```

Additional examples:

```bash
mcpsentinel scan https://github.com/org/repo
mcpsentinel scan ./repo --json --output report.json --max-workers 8
```

### API Example

Start the API server:

```bash
uvicorn mcp_server.main:app --host 0.0.0.0 --port 8000
```

Scan a repository with `POST /scan-repo`:

```json
{
  "path": "/workspace/mcp-secret-validator",
  "min_detection_confidence": 0.55,
  "min_validation_confidence": 0.6,
  "max_workers": 4,
  "validation_timeout_seconds": 8,
  "report_output_path": "./reports/repo_scan.json",
  "config_path": "mcp_server/repo_scanner_config.json"
}
```

GitHub scan payload:

```json
{
  "github_url": "https://github.com/org/repo.git"
}
```

## Example Output

```text
Scanning repository...

[HIGH RISK]
File: config.js
Secret: sk_...xyz
Service: stripe
Status: VALID

[MEDIUM RISK]
File: deploy.env
Secret: ghp_...9x2
Service: github
Status: INVALID
Reason: Rejected by endpoint (401)

Scan Complete

Files scanned: 127
Secrets detected: 5
Valid secrets: 2
Invalid secrets: 3
Unknown secrets: 0
```

## Security Controls

- **Path safety**: Restricts local scans to approved workspace boundaries.
- **SSRF protection**: Blocks localhost, private, and internal network targets during validation.
- **HTTPS-only validation**: Rejects non-TLS endpoints in generated validation plans.
- **Masked secrets**: Redacts findings in logs/reports (e.g., `abc...xyz`) and uses hashes where possible.
- **Execution safety**: Reads files only; does not execute repository code.
- **Timeout and method hardening**: Enforces strict request timeouts and allowed HTTP methods.

## Performance

- Uses a bounded **thread pool** for parallel validation execution.
- Applies result **caching** by secret hash to prevent duplicate checks.
- Improves throughput with **parallel validation** while maintaining server-side worker limits.
- Supports async API flow via background thread execution for scan requests.

## Limitations

- LLM inference quality depends on model availability, prompt behavior, and context quality.
- API-side validation may produce false negatives for rate-limited or non-standard services.
- Dynamic or fragmented secrets across multiple files can be harder to validate confidently.

## Future Improvements

- Redis-backed distributed cache and queueing for larger scan workloads.
- AST-based analysis for language-aware extraction and improved precision.
- SIEM integration for native alert forwarding and enterprise reporting.
