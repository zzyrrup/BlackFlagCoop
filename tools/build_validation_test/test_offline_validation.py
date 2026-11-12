"""Deterministic tests for the offline validation recorder and CMake audit."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from build_validation.offline_validation import (  # noqa: E402
    DEPLOYMENT_STATUS,
    INSTALLED_ASI_SHA256,
    UnsafePathError,
    audit_repo,
    audit_texts,
    build_report,
    classify_candidate_asi,
    parse_build_log,
    parse_configure_log,
    parse_ctest_log,
    report_exit_code,
    write_report,
)


GOOD_CMAKE = """
cmake_minimum_required(VERSION 3.20)
project(BlackFlagCoop VERSION 0.5.1)
if(NOT WIN32)
    message(FATAL_ERROR "BlackFlagCoop only supports Windows.")
endif()
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "BlackFlagCoop must be built as a 64-bit (x64) binary.")
endif()
add_executable(BlackFlagCoopExeStringProbe tools/exe_string_probe/main.cpp)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/bfc_offline_tests.cmake)
"""

GOOD_TESTS = """
enable_testing()
add_test(
    NAME NetDiagSelfTest
    COMMAND BlackFlagCoopNetTest --diag-self-test
)
add_test(
    NAME NetSelfTest
    COMMAND BlackFlagCoopNetTest --self-test --port 27116
)
set_tests_properties(NetDiagSelfTest PROPERTIES TIMEOUT 30)
set_tests_properties(NetSelfTest PROPERTIES TIMEOUT 60)
"""

GOOD_GITIGNORE = "*.asi\nbuild/\n"
GOOD_MAIN = 'constexpr const char* kPluginVersion = "0.5.1";\n'
GOOD_WORKFLOW = """
name: offline-validation
jobs:
  static-audit:
    steps:
      - run: python3 -m unittest discover -s tools/build_validation_test -v
      - run: python3 scripts/audit_cmake_surface.py --repo .
"""


class AuditTests(unittest.TestCase):
    def test_good_surface_passes(self) -> None:
        result = audit_texts(GOOD_CMAKE, GOOD_TESTS, GOOD_GITIGNORE, GOOD_MAIN, GOOD_WORKFLOW)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["ctestNames"], ["NetDiagSelfTest", "NetSelfTest"])
        self.assertEqual(result["projectVersion"], "0.5.1")

    def test_missing_windows_gate_fails(self) -> None:
        result = audit_texts(
            GOOD_CMAKE.replace("only supports Windows", "builds everywhere"),
            GOOD_TESTS,
            GOOD_GITIGNORE,
            GOOD_MAIN,
            GOOD_WORKFLOW,
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("Windows-only" in item for item in result["errors"]))

    def test_missing_asi_ignore_fails(self) -> None:
        result = audit_texts(GOOD_CMAKE, GOOD_TESTS, "build/\n", GOOD_MAIN, GOOD_WORKFLOW)
        self.assertFalse(result["ok"])
        self.assertTrue(any("*.asi" in item for item in result["errors"]))

    def test_game_path_in_cmake_fails(self) -> None:
        result = audit_texts(
            GOOD_CMAKE
            + '\nfile(COPY "${src}" DESTINATION "C:/Games/AC Black Flag Resynced")\n',
            GOOD_TESTS,
            GOOD_GITIGNORE,
            GOOD_MAIN,
            GOOD_WORKFLOW,
        )
        self.assertFalse(result["ok"])

    def test_this_checkout_passes(self) -> None:
        result = audit_repo(ROOT)
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["projectVersion"], "0.5.1")
        self.assertEqual(result["pluginVersion"], "0.5.1")
        self.assertIn("NetDiagSelfTest", result["ctestNames"])
        self.assertIn("NetSelfTest", result["ctestNames"])


class LogParserTests(unittest.TestCase):
    def test_successful_configure_marks_the_compiler(self) -> None:
        from build_validation.offline_validation import compiler_from_configure_log

        text = (
            "-- The CXX compiler identification is MSVC 19.50.35717.0\n"
            "-- Configuring done\n"
            "-- Generating done\n"
        )
        parsed = parse_configure_log(text)
        self.assertEqual(parsed["result"], "pass")
        identified = compiler_from_configure_log(text)
        self.assertEqual(identified["id"], "MSVC")
        self.assertEqual(identified["version"], "19.50.35717.0")

    def test_missing_vs_generator(self) -> None:
        parsed = parse_configure_log(
            "CMake Error: Could not create named generator Visual Studio 18 2026\n"
        )
        self.assertEqual(parsed["result"], "fail")

    def test_empty_logs_are_not_run(self) -> None:
        self.assertEqual(parse_configure_log("")["result"], "not_run")
        self.assertEqual(parse_build_log("")["result"], "not_run")
        self.assertEqual(parse_ctest_log("")["result"], "not_run")

    def test_build_without_directory(self) -> None:
        parsed = parse_build_log("Error: /tmp/bfc-vs-build is not a directory\n")
        self.assertEqual(parsed["result"], "fail")

    def test_ctest_summary(self) -> None:
        passed = parse_ctest_log("100% tests passed, 0 tests failed out of 2\n")
        self.assertEqual(passed["result"], "pass")
        self.assertEqual(passed["passed"], 2)
        failed = parse_ctest_log("50% tests passed, 1 tests failed out of 2\n")
        self.assertEqual(failed["result"], "fail")
        self.assertEqual(failed["failed"], 1)


class RecorderTests(unittest.TestCase):
    def test_candidate_outside_build_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build").mkdir()
            game = root / "Games" / "AC Black Flag Resynced"
            game.mkdir(parents=True)
            installed = game / "BlackFlagCoop.asi"
            installed.write_bytes(b"installed")
            with self.assertRaises(UnsafePathError):
                classify_candidate_asi(installed, root)

    def test_missing_candidate_is_not_a_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build").mkdir()
            record = classify_candidate_asi(root / "build" / "bin" / "Release" / "BlackFlagCoop.asi", root)
        self.assertFalse(record["present"])
        self.assertIsNone(record["sha256"])
        self.assertFalse(record["deployed"])

    def test_candidate_under_build_is_hashed_and_not_deployed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asi = root / "build" / "bin" / "Release" / "BlackFlagCoop.asi"
            asi.parent.mkdir(parents=True)
            asi.write_bytes(b"candidate-bytes")
            record = classify_candidate_asi(asi, root)
        self.assertTrue(record["present"])
        self.assertEqual(record["bytes"], len(b"candidate-bytes"))
        self.assertEqual(len(record["sha256"]), 64)
        self.assertFalse(record["deployed"])
        self.assertTrue(record["path"].startswith("build/"))

    def test_report_keeps_deployment_off_and_stays_in_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            (root / ".git").mkdir()
            report = build_report(
                repo_root=root,
                audit={
                    "ok": True,
                    "projectVersion": "0.5.1",
                    "pluginVersion": "0.5.1",
                    "ctestNames": ["NetDiagSelfTest"],
                    "errors": [],
                    "warnings": [],
                },
                configure_log="",
                build_log="",
                ctest_log="",
                configure_command="cmake -S . -B build",
                build_command="cmake --build build --config Release",
                ctest_command="ctest --test-dir build -C Release --output-on-failure",
                generator="Visual Studio 18 2026",
                config="Release",
                architecture="x64",
                candidate={"present": False, "sha256": None, "bytes": None, "deployed": True},
                branch_survey=[],
                python_tests={"result": "pass", "detail": "ok"},
            )
            report["deployed"] = True
            report["deploymentStatus"] = "deployed"
            dest = root / "reports" / "v0.8.0-build-validation.json"
            write_report(report, dest, root)
            saved = json.loads(dest.read_text(encoding="utf-8"))
            self.assertEqual(saved["deploymentStatus"], DEPLOYMENT_STATUS)
            self.assertFalse(saved["deployed"])
            self.assertFalse(saved["candidateAsi"]["deployed"])
            self.assertFalse(saved["installedAsi"]["modifiedByThisRun"])
            self.assertEqual(saved["installedAsi"]["sha256"], INSTALLED_ASI_SHA256)
            self.assertFalse(saved["gameLaunched"])
            self.assertEqual(saved["compiler"]["generatorRequested"], "Visual Studio 18 2026")
            self.assertEqual(saved["compiler"]["configRequested"], "Release")
            with self.assertRaises(UnsafePathError):
                write_report(report, root / "build" / "out.json", root)
            self.assertEqual(report_exit_code(saved), 1)
            saved["staticAudit"]["ok"] = True
            saved["configure"] = {"result": "pass"}
            saved["build"] = {"result": "pass"}
            saved["tests"] = {"ctest": {"result": "pass"}}
            self.assertEqual(report_exit_code(saved), 0)


if __name__ == "__main__":
    unittest.main()
