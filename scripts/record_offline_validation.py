#!/usr/bin/env python3
"""Write reports/v0.8.0-build-validation.json from logs and a static audit.

This command does not configure, build, launch the game, or copy an ASI.
Feed it logs from a configure/build/ctest run that already finished.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from build_validation.offline_validation import (  # noqa: E402
    audit_repo,
    build_report,
    classify_candidate_asi,
    load_survey,
    report_exit_code,
    write_report,
)


def _read(path: Path | None) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "reports" / "v0.8.0-build-validation.json",
    )
    parser.add_argument("--configure-log", type=Path)
    parser.add_argument("--build-log", type=Path)
    parser.add_argument("--ctest-log", type=Path)
    parser.add_argument(
        "--configure-command",
        default='cmake -S . -B build -G "Visual Studio 18 2026" -A x64',
    )
    parser.add_argument(
        "--build-command",
        default="cmake --build build --config Release",
    )
    parser.add_argument(
        "--ctest-command",
        default="ctest --test-dir build -C Release --output-on-failure",
    )
    parser.add_argument("--generator", default="Visual Studio 18 2026")
    parser.add_argument("--config", default="Release")
    parser.add_argument("--architecture", default="x64")
    parser.add_argument(
        "--candidate-asi",
        type=Path,
        help="Optional ASI under <repo>/build. Paths outside build/ are refused.",
    )
    parser.add_argument(
        "--survey",
        type=Path,
        default=ROOT / "tools" / "build_validation" / "branch_survey.json",
    )
    parser.add_argument(
        "--python-test-result",
        default="not_run",
        choices=("not_run", "pass", "fail"),
    )
    parser.add_argument("--python-test-detail", default="")
    parser.add_argument(
        "--windows-gate-log",
        type=Path,
        help="Optional non-Windows configure log. Recorded as a diagnostic, not as the VS build.",
    )
    args = parser.parse_args()

    repo = args.repo.resolve()
    audit = audit_repo(repo)
    candidate = classify_candidate_asi(args.candidate_asi, repo)
    extra = None
    if args.windows_gate_log is not None:
        gate_text = _read(args.windows_gate_log)
        extra = {
            "nonWindowsConfigure": {
                "generator": "Unix Makefiles",
                "result": "fail" if "only supports Windows" in gate_text else "unknown",
                "detail": (
                    "BlackFlagCoop only supports Windows."
                    if "only supports Windows" in gate_text
                    else "Windows-only gate text was not found in the diagnostic log."
                ),
                "note": "Diagnostic only. This is not the Visual Studio 18 2026 workflow.",
            }
        }
    report = build_report(
        repo_root=repo,
        audit=audit,
        configure_log=_read(args.configure_log),
        build_log=_read(args.build_log),
        ctest_log=_read(args.ctest_log),
        configure_command=args.configure_command,
        build_command=args.build_command,
        ctest_command=args.ctest_command,
        generator=args.generator,
        config=args.config,
        architecture=args.architecture,
        candidate=candidate,
        branch_survey=load_survey(args.survey),
        python_tests={
            "result": args.python_test_result,
            "detail": args.python_test_detail,
        },
        extra_diagnostic=extra,
    )
    write_report(report, args.report, repo)
    print(args.report)
    return report_exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
