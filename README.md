# LLM-Based Dynamic Secret Detection and Validation Engine

## Architecture Diagram (Text)

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

## How to run

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r mcp_server/requirements.txt
export GEMINI_API_KEY="<your-key>"   # optional; inference falls back to unknown
uvicorn mcp_server.main:app --host 0.0.0.0 --port 8000
```

## New repository scanning API

`POST /scan-repo`

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

Optional GitHub scan:

```json
{
  "github_url": "https://github.com/org/repo.git"
}
```

Response shape:

```json
{
  "total_files_scanned": 152,
  "total_secrets_detected": 3,
  "total_valid_secrets": 1,
  "results": [
    {
      "file": "/workspace/mcp-secret-validator/example.py",
      "secret": "sk_...xyz",
      "service": "stripe",
      "confidence": 0.81,
      "validation_result": {
        "status": "INVALID",
        "risk": "LOW",
        "reason": "Rejected by endpoint (401)"
      }
    }
  ]
}
```

## Security Controls

- **Path safety**: local repo paths must remain inside the configured workspace root.
- **No execution**: scanner only reads text files; never executes code.
- **Filtering**: skips `.git`, `node_modules`, `__pycache__`, binaries, and files over 2MB.
- **SSRF mitigation**: DNS/IP policy blocks localhost/private/internal targets.
- **Method hardening**: validation plans only allow `GET`; POST/PUT are rejected.
- **Transport hardening**: HTTPS-only endpoints.
- **Timeout control**: per-request timeout and thread-pool timeout boundaries.
- **Secret exposure reduction**: outputs and logs use masked secrets (`abc...xyz`) and hashes.

## Performance notes

- Uses `ThreadPoolExecutor` for parallel validation.
- Max workers are bounded server-side to reduce API abuse.
- Results are cached by secret hash to avoid duplicate inference/validation calls.
- Async API endpoint (`/scan-repo-async`) wraps scanner with `asyncio.to_thread`.

## Example test case

1. Create repo folder with:
   - `app.py` containing `api_key = "sk_live_ABCDEF1234567890xyz"`
   - `fixtures.py` containing `token = "test_token_123"`
2. Call `/scan-repo` with path pointing to that folder.
3. Expected outcome:
   - One high-confidence secret from `app.py`.
   - Placeholder token suppressed.
   - Masked secret in report.

## Limitations

- LLM inference quality depends on Gemini availability and prompt behavior.
- Public endpoint checks may produce false negatives for throttled/atypical APIs.
- Plugin registry is in-memory.

## Future improvements

- Add persistent cache backend (Redis) and distributed queue.
- Add AST-based language analyzers and taint-aware context extraction.
- Add signed audit log sink and SIEM-native export.


## CLI usage (`mcp-scan`)

Run directly without API server:

```bash
python cli.py scan ./repo
python cli.py scan https://github.com/user/repository
```

Installable command:

```bash
python -m pip install .
mcp-scan scan ./repo
```

Optional flags:

```bash
mcp-scan scan ./repo --json
mcp-scan scan ./repo --output report.json
mcp-scan scan ./repo --max-workers 10
```

Example terminal output:

```text
Scanning repository...

[HIGH RISK]
File: config.js
Secret: sk_...xyz
Service: stripe
Status: VALID

Scan Complete

Files scanned: 127
Secrets detected: 5
Valid secrets: 2
Invalid secrets: 3
Unknown secrets: 0
```
