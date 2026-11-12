"""Static build audit and offline validation report.

This module never launches the game, never copies an ASI, and never writes a
deployment status other than not_deployed.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

INSTALLED_ASI_SHA256 = (
    "63B38877DDA7CC7CD9AB2619F94D3941C37F54C95A435EFE47084DC4CF2A50BE"
)
INSTALLED_ASI_VERSION = "0.5.1"
DEPLOYMENT_STATUS = "not_deployed"

_PROJECT_VERSION = re.compile(
    r"project\s*\(\s*BlackFlagCoop\b.*?VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
    re.DOTALL,
)
_PLUGIN_VERSION = re.compile(r'kPluginVersion\s*=\s*"([^"]+)"')
_TEST_NAME = re.compile(r"add_test\s*\((?:[^)]*?\bNAME\s+)([A-Za-z0-9_]+)", re.DOTALL)


class ValidationError(Exception):
    """The checkout failed a required offline gate."""


class UnsafePathError(ValidationError):
    """A path would read or write outside the allowed tree."""


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _blocked_game_path(path: Path) -> bool:
    for part in path.parts:
        lowered = part.lower()
        if lowered == "games" or "black flag resynced" in lowered:
            return True
    return False


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_cmake_comments(text: str) -> str:
    return re.sub(r"#.*?$", "", text, flags=re.MULTILINE)


def project_version(cmake_text: str) -> str | None:
    match = _PROJECT_VERSION.search(cmake_text)
    return match.group(1) if match else None


def plugin_version(main_cpp_text: str) -> str | None:
    match = _PLUGIN_VERSION.search(main_cpp_text)
    return match.group(1) if match else None


def registered_test_names(cmake_text: str) -> list[str]:
    return _TEST_NAME.findall(cmake_text)


def audit_texts(
    cmake_text: str,
    tests_cmake_text: str,
    gitignore_text: str,
    main_cpp_text: str,
    workflow_text: str,
) -> dict:
    """Return a static audit. `errors` are release-blocking; `warnings` are not."""
    errors: list[str] = []
    warnings: list[str] = []
    cmake_text = strip_cmake_comments(cmake_text)
    tests_cmake_text = strip_cmake_comments(tests_cmake_text)

    if "if(NOT WIN32)" not in cmake_text or "only supports Windows" not in cmake_text:
        errors.append("CMakeLists.txt is missing the Windows-only FATAL_ERROR gate.")
    if "CMAKE_SIZEOF_VOID_P EQUAL 4" not in cmake_text:
        errors.append("CMakeLists.txt is missing the 32-bit FATAL_ERROR gate.")
    if "include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/bfc_offline_tests.cmake)" not in cmake_text:
        errors.append("CMakeLists.txt does not include cmake/bfc_offline_tests.cmake.")
    if re.search(r"\binstall\s*\(", cmake_text) or re.search(r"\binstall\s*\(", tests_cmake_text):
        errors.append("CMake defines an install() rule. This tree must not install an ASI.")
    combined = cmake_text + "\n" + tests_cmake_text
    if "AC Black Flag" in combined or "Games\\" in combined or "Games/" in combined:
        errors.append("CMake mentions a game-install path.")

    if "enable_testing()" not in tests_cmake_text:
        errors.append("cmake/bfc_offline_tests.cmake does not call enable_testing().")
    names = registered_test_names(tests_cmake_text)
    for required in ("NetDiagSelfTest", "NetSelfTest"):
        if required not in names:
            errors.append(f"CTest is missing {required}.")
    if "--diag-self-test" not in tests_cmake_text:
        errors.append("NetDiagSelfTest is not wired to --diag-self-test.")
    if "--self-test" not in tests_cmake_text or "--port 27116" not in tests_cmake_text:
        errors.append("NetSelfTest is not wired to --self-test --port 27116.")
    if "TIMEOUT 30" not in tests_cmake_text or "TIMEOUT 60" not in tests_cmake_text:
        errors.append("Offline CTest targets are missing TIMEOUT values.")

    gitignore_lines = {line.strip() for line in gitignore_text.splitlines()}
    if "*.asi" not in gitignore_lines:
        errors.append(".gitignore does not ignore *.asi.")
    if "build/" not in gitignore_lines:
        errors.append(".gitignore does not ignore build/.")

    cmake_ver = project_version(cmake_text)
    plugin_ver = plugin_version(main_cpp_text)
    if cmake_ver is None:
        errors.append("project(BlackFlagCoop VERSION x.y.z) was not found.")
    if plugin_ver is None:
        warnings.append(
            "src/main.cpp has no literal kPluginVersion string; version skew was not compared."
        )
    elif cmake_ver is not None and plugin_ver != cmake_ver and not plugin_ver.startswith(cmake_ver):
        warnings.append(
            f"CMake project version {cmake_ver} does not match kPluginVersion {plugin_ver}."
        )

    if "/WX" not in cmake_text:
        warnings.append("MSVC warnings are not treated as errors (/WX is unset).")
    if "BlackFlagCoopExeStringProbe" in cmake_text and "ExeStringProbe" not in names:
        warnings.append(
            "BlackFlagCoopExeStringProbe is built but not registered with CTest. "
            "It needs a local game executable, which is not in the repo."
        )

    if not workflow_text.strip():
        errors.append("The offline validation workflow file is empty or missing.")
    else:
        if "unittest" not in workflow_text:
            errors.append("CI workflow does not run the recorder unit tests.")
        if "audit_cmake_surface.py" not in workflow_text:
            errors.append("CI workflow does not run the CMake surface audit.")
        lowered = workflow_text.lower()
        if "visual studio 18 2026" in lowered:
            warnings.append(
                "CI workflow names the Visual Studio 18 2026 generator. "
                "Hosted runners are not a verified source of that generator."
            )
        for banned in ("ac black flag", "games\\", "games/", "deploy"):
            if banned in lowered and banned == "deploy":
                # Allow the word only inside a negation such as no-deploy.
                if re.search(r"(?<!no-)(?<!no_)deploy", lowered):
                    errors.append("CI workflow contains a deploy step.")
            elif banned in lowered:
                errors.append(f"CI workflow mentions a game path ({banned}).")

    return {
        "ok": not errors,
        "projectVersion": cmake_ver,
        "pluginVersion": plugin_ver,
        "ctestNames": names,
        "errors": errors,
        "warnings": warnings,
    }


def audit_repo(repo_root: Path) -> dict:
    repo_root = repo_root.resolve()
    workflow = repo_root / ".github" / "workflows" / "offline-validation.yml"
    result = audit_texts(
        read_text(repo_root / "CMakeLists.txt"),
        read_text(repo_root / "cmake" / "bfc_offline_tests.cmake"),
        read_text(repo_root / ".gitignore"),
        read_text(repo_root / "src" / "main.cpp"),
        read_text(workflow) if workflow.is_file() else "",
    )
    result["repo"] = str(repo_root)
    return result


def compiler_from_configure_log(text: str) -> dict:
    match = re.search(
        r"The CXX compiler identification is ([A-Za-z0-9_+.-]+)(?:\s+([0-9][0-9.]*))?",
        text,
    )
    if not match:
        return {"id": None, "version": None}
    return {"id": match.group(1), "version": match.group(2)}


def parse_configure_log(text: str) -> dict:
    if not text.strip():
        return {"result": "not_run", "detail": "No configure log was provided."}
    if "Could not create named generator Visual Studio 18 2026" in text:
        return {
            "result": "fail",
            "detail": "CMake on this machine has no Visual Studio 18 2026 generator.",
        }
    if "only supports Windows" in text:
        return {
            "result": "fail",
            "detail": "Configure stopped on the Windows-only gate.",
        }
    if "Configuring done" in text and "Generating done" in text:
        return {"result": "pass", "detail": "CMake configure finished."}
    if "Configuring incomplete" in text or "CMake Error" in text:
        return {"result": "fail", "detail": "CMake configure reported an error."}
    return {"result": "unknown", "detail": "Configure log did not match a known outcome."}


def parse_build_log(text: str) -> dict:
    if not text.strip():
        return {"result": "not_run", "detail": "No build log was provided."}
    if "is not a directory" in text or "does not exist" in text or "Error:" in text:
        return {"result": "fail", "detail": "Build directory was not produced by configure."}
    if re.search(r"\b(error C\d+|Build FAILED|LINK : fatal error)\b", text):
        return {"result": "fail", "detail": "Build reported a compiler or linker error."}
    if "Build succeeded" in text or re.search(r"\b0 Error\(s\)", text):
        return {"result": "pass", "detail": "Build log reports success."}
    return {"result": "unknown", "detail": "Build log did not match a known outcome."}


def parse_ctest_log(text: str) -> dict:
    if not text.strip():
        return {"result": "not_run", "passed": None, "failed": None, "detail": "No ctest log was provided."}
    if "No such file or directory" in text or "Failed to change working directory" in text:
        return {
            "result": "fail",
            "passed": 0,
            "failed": None,
            "detail": "CTest had no build directory.",
        }
    summary = re.search(
        r"(\d+)% tests passed,\s*(\d+) tests failed out of (\d+)",
        text,
    )
    if summary:
        failed = int(summary.group(2))
        total = int(summary.group(3))
        return {
            "result": "pass" if failed == 0 else "fail",
            "passed": total - failed,
            "failed": failed,
            "detail": summary.group(0),
        }
    if "No tests were found" in text:
        return {"result": "fail", "passed": 0, "failed": 0, "detail": "No tests were found."}
    return {"result": "unknown", "passed": None, "failed": None, "detail": "CTest log did not match a known outcome."}


def classify_candidate_asi(candidate: Path | None, repo_root: Path) -> dict:
    """Hash a candidate ASI only when it lives under <repo>/build."""
    record = {
        "present": False,
        "path": None,
        "bytes": None,
        "sha256": None,
        "deployed": False,
    }
    if candidate is None:
        return record
    repo_root = repo_root.resolve()
    build_root = (repo_root / "build").resolve()
    resolved = candidate.resolve()
    if _blocked_game_path(resolved) or not _is_relative_to(resolved, build_root):
        raise UnsafePathError(
            "Candidate ASI must be a file under the repo build/ directory. "
            "The installed game ASI is not hashed or modified by this tool."
        )
    record["path"] = resolved.relative_to(repo_root).as_posix()
    if not resolved.is_file():
        return record
    data = resolved.read_bytes()
    record["present"] = True
    record["bytes"] = len(data)
    record["sha256"] = hashlib.sha256(data).hexdigest().upper()
    record["deployed"] = False
    return record


def _git(repo_root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def cmake_version() -> str | None:
    try:
        completed = subprocess.run(
            ["cmake", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    line = completed.stdout.splitlines()[0] if completed.stdout else ""
    match = re.search(r"(\d+\.\d+\.\d+)", line)
    return match.group(1) if match else None


def load_survey(path: Path | None) -> list[dict]:
    if path is None or not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValidationError("Branch survey must be a JSON array.")
    return data


def build_report(
    *,
    repo_root: Path,
    audit: dict,
    configure_log: str,
    build_log: str,
    ctest_log: str,
    configure_command: str,
    build_command: str,
    ctest_command: str,
    generator: str,
    config: str,
    architecture: str,
    candidate: dict,
    branch_survey: list[dict],
    python_tests: dict,
    extra_diagnostic: dict | None = None,
) -> dict:
    commit = _git(repo_root, "rev-parse", "HEAD")
    branch = _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    status = _git(repo_root, "status", "--porcelain")
    configure = parse_configure_log(configure_log)
    identified = compiler_from_configure_log(configure_log)
    return {
        "schemaVersion": 1,
        "workstream": "9/7",
        "milestone": "v0.8.0-build-validation",
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit,
        "branch": branch,
        "dirty": bool(status),
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cmake": cmake_version(),
        },
        "compiler": {
            "configured": configure["result"] == "pass",
            "id": identified["id"],
            "version": identified["version"],
            "generatorRequested": generator,
            "architectureRequested": architecture,
            "configRequested": config,
        },
        "deploymentStatus": DEPLOYMENT_STATUS,
        "deployed": False,
        "gameLaunched": False,
        "installedAsi": {
            "version": INSTALLED_ASI_VERSION,
            "sha256": INSTALLED_ASI_SHA256,
            "preserved": True,
            "modifiedByThisRun": False,
            "checkedOnThisMachine": False,
            "note": (
                "Known-good v0.5.1 hash recorded for comparison. "
                "This run did not open, hash, or replace an installed ASI."
            ),
        },
        "candidateAsi": candidate,
        "commands": {
            "configure": configure_command,
            "build": build_command,
            "ctest": ctest_command,
        },
        "configure": configure,
        "build": parse_build_log(build_log),
        "tests": {
            "ctest": parse_ctest_log(ctest_log),
            "python": python_tests,
        },
        "staticAudit": {
            "ok": audit.get("ok"),
            "projectVersion": audit.get("projectVersion"),
            "pluginVersion": audit.get("pluginVersion"),
            "ctestNames": audit.get("ctestNames"),
            "errors": audit.get("errors"),
            "warnings": audit.get("warnings"),
        },
        "branchSurvey": branch_survey,
        "extraDiagnostic": extra_diagnostic,
        "limitations": [
            "Visual Studio 18 2026 x64 Release was not available on this host, so no candidate ASI was produced.",
            "CTest for NetDiagSelfTest and NetSelfTest is registered and was not executed.",
            "Passing the Python recorder tests does not mean the ASI loads in Assassin's Creed.",
            "Specialist branches were inspected read-only and were not edited.",
            "PR #27 was not modified.",
        ],
    }


def report_exit_code(report: dict) -> int:
    """0 only when the static audit and the three Windows commands passed."""
    audit = report.get("staticAudit") or {}
    if not audit.get("ok"):
        return 1
    outcomes = [
        (report.get("configure") or {}).get("result"),
        (report.get("build") or {}).get("result"),
        ((report.get("tests") or {}).get("ctest") or {}).get("result"),
    ]
    return 0 if outcomes == ["pass", "pass", "pass"] else 1


def write_report(report: dict, dest: Path, repo_root: Path) -> None:
    repo_root = repo_root.resolve()
    reports = (repo_root / "reports").resolve()
    resolved = dest.resolve()
    if _blocked_game_path(resolved) or not _is_relative_to(resolved, reports):
        raise UnsafePathError("Validation reports must be written under the repo reports/ directory.")
    if resolved.suffix.lower() != ".json":
        raise UnsafePathError("Validation report path must end in .json.")
    # The recorder never records a successful deploy, even if a caller mutates a copy.
    report = dict(report)
    report["deploymentStatus"] = DEPLOYMENT_STATUS
    report["deployed"] = False
    if isinstance(report.get("candidateAsi"), dict):
        candidate = dict(report["candidateAsi"])
        candidate["deployed"] = False
        report["candidateAsi"] = candidate
    if isinstance(report.get("installedAsi"), dict):
        installed = dict(report["installedAsi"])
        installed["modifiedByThisRun"] = False
        report["installedAsi"] = installed
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
