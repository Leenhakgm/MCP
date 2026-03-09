from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

from mcp_server.llm_plan_generator import LLMPlanGenerator
from mcp_server.models import RepoScanRequest, RepoScanResponse
from mcp_server.repo_scanner import scan_repository
from mcp_server.validator import execute_validation


def _is_github_target(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https"} and parsed.netloc.lower() == "github.com"


def _build_request(args: argparse.Namespace) -> RepoScanRequest:
    payload = {
        "min_detection_confidence": args.min_detection_confidence,
        "min_validation_confidence": args.min_validation_confidence,
        "max_workers": args.max_workers,
        "validation_timeout_seconds": args.timeout,
        "report_output_path": args.output,
        "config_path": args.config,
    }

    if _is_github_target(args.target):
        payload["github_url"] = args.target
    else:
        payload["path"] = args.target

    return RepoScanRequest.model_validate(payload)


def _print_human(report: RepoScanResponse) -> None:
    print("Scanning repository...\n")

    for item in report.results:
        status = item.validation_result.get("status", "UNKNOWN")
        risk = item.validation_result.get("risk", "LOW")

        status = str(status).replace("ValidationStatus.", "")
        risk = str(risk).replace("RiskLevel.", "")

        print(f"[{risk} RISK]")
        print(f"File: {item.file}")
        print(f"Secret: {item.secret}")
        print(f"Service: {item.service}")
        print(f"Status: {status}\n")

    invalid_count = sum(
        1 for r in report.results
        if r.validation_result.get("status") == "INVALID"
    )

    unknown_count = sum(
        1 for r in report.results
        if r.validation_result.get("status") in {"UNKNOWN", "ERROR", "SKIPPED"}
    )

    print("Scan Complete\n")
    print(f"Files scanned: {report.total_files_scanned}")
    print(f"Secrets detected: {report.total_secrets_detected}")
    print(f"Valid secrets: {report.total_valid_secrets}")
    print(f"Invalid secrets: {invalid_count}")
    print(f"Unknown secrets: {unknown_count}")


def run_scan(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        request = _build_request(args)

        llm = LLMPlanGenerator()

        report = scan_repository(
            request=request,
            infer_service=llm.infer_service,
            execute_validation=execute_validation,
            workspace_root=Path.cwd(),
        )

        if args.json:
            print(report.model_dump_json(indent=2))
        else:
            _print_human(report)

        return 0

    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="MCP Secret Validator CLI",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Scan a local repository path or GitHub URL",
    )

    scan.add_argument(
        "target",
        help="Local folder path or GitHub repository URL",
    )

    scan.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON",
    )

    scan.add_argument(
        "--output",
        help="Write report JSON to file",
    )

    scan.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Maximum parallel workers",
    )

    scan.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Per-future validation timeout in seconds",
    )

    scan.add_argument(
        "--min-detection-confidence",
        type=float,
        default=0.55,
        help="Minimum detection confidence",
    )

    scan.add_argument(
        "--min-validation-confidence",
        type=float,
        default=0.6,
        help="Minimum confidence to validate",
    )

    scan.add_argument(
        "--config",
        default="mcp_server/repo_scanner_config.json",
        help="Ignore-pattern config",
    )

    scan.set_defaults(func=run_scan)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())