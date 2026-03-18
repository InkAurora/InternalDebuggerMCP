from __future__ import annotations

import csv
import math
import re
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path


if sys.platform != "win32":
    raise unittest.SkipTest("Windows-only integration test")


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))

from mcp_server.session_manager import SessionManager  # noqa: E402
from mcp_server.pipe_client import NativeRequestError, PipeClient  # noqa: E402
from mcp_server.tools import _send_native_request  # noqa: E402


DEBUGGER_DLL_NAME = "InternalDebuggerDLL.dll"
TARGET_PROCESS_NAME = "TestTarget.exe"


def _read_target_startup(process: subprocess.Popen[str]) -> dict[str, str]:
    symbols: dict[str, str] = {}
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                raise AssertionError("TestTarget exited before reporting startup addresses")
            time.sleep(0.05)
            continue

        text = line.strip()
        if text == "READY":
            required = {
                "g_write_target",
                "g_read_watch_target",
                "g_write_watch_target",
                "g_aob_data_anchor",
                "g_aob_code_anchor",
                "SampleFunction",
                "AobPatternAnchor",
                "ExportedStoreValue",
                "ExportedAddFloat",
                "ExportedAddDouble",
                "ExportedMixedMath",
                "ExportedFillBuffer",
            }
            missing = required.difference(symbols)
            if missing:
                raise AssertionError(f"Missing startup symbols: {', '.join(sorted(missing))}")
            return symbols

        if ": 0x" in text:
            label, value = text.split(": 0x", 1)
            symbols[label.strip()] = f"0x{value.strip()}"

    raise AssertionError("Timed out waiting for TestTarget startup banner")


def _start_target_process(target_path: Path) -> tuple[subprocess.Popen[str], dict[str, str]]:
    process = subprocess.Popen(
        [str(target_path)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    return process, _read_target_startup(process)


def _stop_target_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stdout is not None:
        process.stdout.close()


def _is_module_loaded(pid: int, module_name: str) -> bool:
    completed = subprocess.run(
        ["tasklist", "/fo", "csv", "/nh", "/fi", f"PID eq {pid}", "/m", module_name],
        capture_output=True,
        text=True,
        check=True,
    )

    for row in csv.reader(completed.stdout.splitlines()):
        if len(row) < 3:
            continue
        if row[0].startswith("INFO:"):
            continue
        if row[1].strip() != str(pid):
            continue
        modules = row[-1].strip().lower()
        if module_name.lower() in modules:
            return True
    return False


def _wait_for_module_state(pid: int, module_name: str, *, loaded: bool, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _is_module_loaded(pid, module_name) == loaded:
            return True
        time.sleep(0.1)
    return False


class AutoInjectionRequestsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "TestTarget" / "TestTarget.exe"
        cls.injector_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "Injector" / "Injector.exe"
        cls.dll_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "InternalDebuggerDLL" / "InternalDebuggerDLL.dll"

        missing = [path for path in (cls.target_path, cls.injector_path, cls.dll_path) if not path.exists()]
        if missing:
            raise unittest.SkipTest(f"Missing build artifacts: {', '.join(str(path) for path in missing)}")

        cls.target_process, cls.target_symbols = _start_target_process(cls.target_path)
        cls.target_pid = cls.target_process.pid
        cls.session_manager = SessionManager()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "target_process"):
            _stop_target_process(cls.target_process)

    def test_first_request_auto_injects_and_returns_modules(self) -> None:
        ping_fields = _send_native_request(self.session_manager, self.target_pid, "ping", process_name=TARGET_PROCESS_NAME)
        modules_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "list_modules",
            process_name=TARGET_PROCESS_NAME,
        )

        self.assertEqual(ping_fields["pid"][0], str(self.target_pid))
        self.assertEqual(modules_fields["module_count"][0].isdigit(), True)
        self.assertEqual(modules_fields["enumeration_method"][0], "toolhelp_snapshot")
        self.assertTrue(any("InternalDebuggerDLL.dll" in module for module in modules_fields.get("module", [])))

        for _ in range(5):
            repeated = _send_native_request(
                self.session_manager,
                self.target_pid,
                "list_modules",
                process_name=TARGET_PROCESS_NAME,
            )
            self.assertEqual(int(repeated["module_count"][0]), len(repeated.get("module", [])))
            self.assertTrue(any(module.startswith("TestTarget.exe|") for module in repeated.get("module", [])))

    def test_write_memory_round_trip(self) -> None:
        payload = "88 77 66 55 44 33 22 11"
        write_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "write_memory",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["g_write_target"],
            bytes=payload,
            read_back=1,
        )
        read_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "read_memory",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["g_write_target"],
            size=8,
        )

        self.assertEqual(write_fields["bytes_written"][0], "8")
        self.assertEqual(write_fields["read_back"][0], payload)
        self.assertEqual(read_fields["bytes"][0], payload)

    def test_memory_read_failures_return_descriptive_native_fields(self) -> None:
        _send_native_request(self.session_manager, self.target_pid, "ping", process_name=TARGET_PROCESS_NAME)

        response = PipeClient(self.target_pid, timeout_ms=5000).request("read_memory", address="0x1", size=16)

        with self.assertRaises(NativeRequestError) as context:
            response.raise_for_error()

        self.assertEqual(context.exception.code, "memory_read_failed")
        self.assertEqual(context.exception.one("address"), "0x1")
        self.assertEqual(context.exception.one("requested_size"), "16")
        self.assertEqual(context.exception.one("memory_reason"), "region_not_committed")
        self.assertEqual(context.exception.one("region_state"), "MEM_FREE")

    def test_memory_read_failures_include_descriptive_runtime_error_context(self) -> None:
        with self.assertRaises(RuntimeError) as context:
            _send_native_request(
                self.session_manager,
                self.target_pid,
                "disassemble",
                process_name=TARGET_PROCESS_NAME,
                address="0x1",
                size=16,
                max_instructions=4,
            )

        message = str(context.exception)
        self.assertIn("memory_read_failed", message)
        self.assertIn("address=0x1", message)
        self.assertIn("requested_size=16", message)
        self.assertIn("reason=region_not_committed", message)

    def test_invoke_function_supports_raw_addresses_exports_and_output_buffers(self) -> None:
        raw_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["SampleFunction"],
            arg_count=1,
            arg0_kind="u64",
            arg0_value=5,
        )
        export_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            process_name=TARGET_PROCESS_NAME,
            module="TestTarget.exe",
            export="ExportedStoreValue",
            arg_count=1,
            arg0_kind="u64",
            arg0_value=0x8877665544332211,
        )
        read_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "read_memory",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["g_write_target"],
            size=8,
        )
        buffer_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            process_name=TARGET_PROCESS_NAME,
            module="TestTarget.exe",
            export="ExportedFillBuffer",
            arg_count=3,
            arg0_kind="out_buffer",
            arg0_size=8,
            arg1_kind="u64",
            arg1_value=8,
            arg2_kind="u64",
            arg2_value=0x20,
        )
        float_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["ExportedAddFloat"],
            arg_count=1,
            arg0_kind="f32",
            arg0_value=" ".join(f"{byte:02X}" for byte in struct.pack("<f", 2.5)),
            return_kind="f32",
        )
        double_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            process_name=TARGET_PROCESS_NAME,
            module="TestTarget.exe",
            export="ExportedAddDouble",
            arg_count=1,
            arg0_kind="f64",
            arg0_value=" ".join(f"{byte:02X}" for byte in struct.pack("<d", 4.5)),
            return_kind="f64",
        )
        mixed_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            process_name=TARGET_PROCESS_NAME,
            module="TestTarget.exe",
            export="ExportedMixedMath",
            arg_count=4,
            arg0_kind="u64",
            arg0_value=2,
            arg1_kind="f64",
            arg1_value=" ".join(f"{byte:02X}" for byte in struct.pack("<d", 1.5)),
            arg2_kind="u64",
            arg2_value=4,
            arg3_kind="f32",
            arg3_value=" ".join(f"{byte:02X}" for byte in struct.pack("<f", 0.25)),
            return_kind="f64",
        )

        self.assertEqual(raw_fields["return_value"][0], "12")
        self.assertTrue(raw_fields["resolved_address"][0].startswith("0x"))
        self.assertEqual(export_fields["return_value"][0], str(0x8877665544332211))
        self.assertEqual(read_fields["bytes"][0], "11 22 33 44 55 66 77 88")
        self.assertEqual(buffer_fields["return_value"][0], "8")
        self.assertEqual(buffer_fields["last_error"][0], "0")

        output_index, output_kind, output_address, output_size, output_bytes = buffer_fields["output"][0].split("|", 4)
        self.assertEqual(output_index, "0")
        self.assertEqual(output_kind, "out_buffer")
        self.assertTrue(output_address.startswith("0x"))
        self.assertEqual(output_size, "8")
        self.assertEqual(output_bytes, "20 21 22 23 24 25 26 27")

        self.assertEqual(float_fields["return_kind"][0], "f32")
        self.assertTrue(
            math.isclose(
                struct.unpack("<f", struct.pack("<I", int(float_fields["return_bits"][0])))[0],
                3.75,
                rel_tol=1e-6,
            )
        )
        self.assertEqual(double_fields["return_kind"][0], "f64")
        self.assertTrue(
            math.isclose(
                struct.unpack("<d", struct.pack("<Q", int(double_fields["return_bits"][0])))[0],
                7.0,
                rel_tol=1e-12,
            )
        )
        self.assertEqual(mixed_fields["return_kind"][0], "f64")
        self.assertTrue(
            math.isclose(
                struct.unpack("<d", struct.pack("<Q", int(mixed_fields["return_bits"][0])))[0],
                9.25,
                rel_tol=1e-12,
            )
        )

    def test_eject_command_removes_debugger_and_allows_reinject(self) -> None:
        ping_fields = _send_native_request(self.session_manager, self.target_pid, "ping", process_name=TARGET_PROCESS_NAME)
        self.assertEqual(ping_fields["pid"][0], str(self.target_pid))
        self.assertTrue(_wait_for_module_state(self.target_pid, DEBUGGER_DLL_NAME, loaded=True))

        eject_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "eject",
            process_name=TARGET_PROCESS_NAME,
        )
        self.assertIn(eject_fields["eject_status"][0], {"scheduled", "already_requested"})
        self.assertTrue(_wait_for_module_state(self.target_pid, DEBUGGER_DLL_NAME, loaded=False))

        reinjected_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "ping",
            process_name=TARGET_PROCESS_NAME,
        )
        self.assertEqual(reinjected_fields["pid"][0], str(self.target_pid))
        self.assertTrue(_wait_for_module_state(self.target_pid, DEBUGGER_DLL_NAME, loaded=True))

    def test_access_watch_commands_aggregate_read_and_write_hits(self) -> None:
        read_watch = _send_native_request(
            self.session_manager,
            self.target_pid,
            "watch_memory_reads",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["g_read_watch_target"],
            size=8,
            watch_id="read_watch_test",
        )
        write_watch = _send_native_request(
            self.session_manager,
            self.target_pid,
            "watch_memory_writes",
            process_name=TARGET_PROCESS_NAME,
            address=self.target_symbols["g_write_watch_target"],
            size=8,
            watch_id="write_watch_test",
        )

        try:
            time.sleep(0.5)

            read_results = _send_native_request(
                self.session_manager,
                self.target_pid,
                "poll_access_watch_results",
                process_name=TARGET_PROCESS_NAME,
                watch_id=read_watch["watch_id"][0],
            )
            write_results = _send_native_request(
                self.session_manager,
                self.target_pid,
                "poll_access_watch_results",
                process_name=TARGET_PROCESS_NAME,
                watch_id=write_watch["watch_id"][0],
            )
        finally:
            _send_native_request(
                self.session_manager,
                self.target_pid,
                "unwatch_access_watch",
                process_name=TARGET_PROCESS_NAME,
                watch_id="read_watch_test",
            )
            _send_native_request(
                self.session_manager,
                self.target_pid,
                "unwatch_access_watch",
                process_name=TARGET_PROCESS_NAME,
                watch_id="write_watch_test",
            )

        self.assertEqual(read_results["mode"][0], "read")
        self.assertEqual(read_results["state"][0], "active")
        self.assertEqual(read_results["timed_out"][0], "false")
        self.assertGreater(int(read_results["total_hit_count"][0]), 0)
        self.assertGreaterEqual(int(read_results["source_count"][0]), 1)

        self.assertEqual(write_results["mode"][0], "write")
        self.assertEqual(write_results["state"][0], "active")
        self.assertEqual(write_results["timed_out"][0], "false")
        self.assertGreater(int(write_results["total_hit_count"][0]), 0)
        self.assertGreaterEqual(int(write_results["source_count"][0]), 1)

        read_source = read_results["source"][0].split("|", 5)
        write_source = write_results["source"][0].split("|", 5)
        self.assertEqual(read_source[-1].lower(), self.target_symbols["g_read_watch_target"].lower())
        self.assertEqual(write_source[-1].lower(), self.target_symbols["g_write_watch_target"].lower())
        self.assertIn("mov", read_source[2].lower())
        self.assertIn("mov", write_source[2].lower())

    def test_access_watch_unwatch_does_not_crash_target(self) -> None:
        for attempt in range(10):
            watch_id = f"write_unwatch_{attempt}"
            watch = _send_native_request(
                self.session_manager,
                self.target_pid,
                "watch_memory_writes",
                process_name=TARGET_PROCESS_NAME,
                address=self.target_symbols["g_write_watch_target"],
                size=8,
                watch_id=watch_id,
            )

            self.assertEqual(watch["watch_id"][0], watch_id)
            time.sleep(0.05)

            removed = _send_native_request(
                self.session_manager,
                self.target_pid,
                "unwatch_access_watch",
                process_name=TARGET_PROCESS_NAME,
                watch_id=watch_id,
            )

            self.assertEqual(removed["watch_id"][0], watch_id)
            self.assertEqual(removed["removed"][0], "true")
            self.assertIsNone(self.target_process.poll())

            ping = _send_native_request(
                self.session_manager,
                self.target_pid,
                "ping",
                process_name=TARGET_PROCESS_NAME,
            )
            self.assertEqual(ping["pid"][0], str(self.target_pid))

    def test_create_aob_pattern_round_trips_for_code_and_data(self) -> None:
        code_address = f"0x{int(self.target_symbols['g_aob_code_anchor'], 16) + 1:X}"
        data_address = f"0x{int(self.target_symbols['g_aob_data_anchor'], 16) + 4:X}"

        code_pattern = _send_native_request(
            self.session_manager,
            self.target_pid,
            "create_aob_pattern",
            process_name=TARGET_PROCESS_NAME,
            address=code_address,
            max_bytes=64,
            include_mask=1,
            include_offset=1,
        )
        data_pattern = _send_native_request(
            self.session_manager,
            self.target_pid,
            "create_aob_pattern",
            process_name=TARGET_PROCESS_NAME,
            address=data_address,
            max_bytes=64,
            include_mask=1,
            include_offset=1,
        )

        code_matches = _send_native_request(
            self.session_manager,
            self.target_pid,
            "pattern_scan",
            process_name=TARGET_PROCESS_NAME,
            pattern=code_pattern["pattern"][0],
            mask=code_pattern["mask"][0],
            target_offset=code_pattern["target_offset"][0],
            limit=2,
        )
        data_matches = _send_native_request(
            self.session_manager,
            self.target_pid,
            "pattern_scan",
            process_name=TARGET_PROCESS_NAME,
            pattern=data_pattern["pattern"][0],
            mask=data_pattern["mask"][0],
            target_offset=data_pattern["target_offset"][0],
            limit=2,
        )

        self.assertEqual(code_pattern["match_count"][0], "1")
        self.assertEqual(data_pattern["match_count"][0], "1")
        self.assertEqual(code_matches["match_count"][0], "1")
        self.assertEqual(data_matches["match_count"][0], "1")
        self.assertEqual(code_matches["match"][0].lower(), code_address.lower())
        self.assertEqual(data_matches["match"][0].lower(), data_address.lower())
        self.assertEqual(code_matches["match_start"][0].lower(), code_pattern["pattern_start"][0].lower())
        self.assertEqual(data_matches["match_start"][0].lower(), data_pattern["pattern_start"][0].lower())

        self.assertEqual(
            int(code_pattern["pattern_start"][0], 16) + int(code_pattern["target_offset"][0]),
            int(code_address, 16),
        )
        self.assertEqual(
            int(data_pattern["pattern_start"][0], 16) + int(data_pattern["target_offset"][0]),
            int(data_address, 16),
        )
        self.assertEqual(len(code_pattern["mask"][0]), int(code_pattern["byte_count"][0]))
        self.assertEqual(len(data_pattern["mask"][0]), int(data_pattern["byte_count"][0]))

    def test_pattern_scan_supports_separate_mask_and_offset(self) -> None:
        marker_pattern = "49 4E 54 45 52 4E 41 4C 5F 44 45 42 55 47 47 45 52 5F 4D 43 50 5F 50 41 54 54 45 52 4E"
        marker_mask = "xxxx?xxxxxxxxxxxxxxxxxxxxxxxx"
        marker_target = f"0x{int(self.target_symbols['g_pattern'], 16) + 4:X}"

        results = _send_native_request(
            self.session_manager,
            self.target_pid,
            "pattern_scan",
            process_name=TARGET_PROCESS_NAME,
            pattern=marker_pattern,
            mask=marker_mask,
            target_offset=4,
            limit=2,
        )

        self.assertEqual(results["match_count"][0], "1")
        self.assertEqual(results["match"][0].lower(), marker_target.lower())
        self.assertEqual(results["match_start"][0].lower(), self.target_symbols["g_pattern"].lower())

    def test_pattern_scan_rejects_invalid_mask_requests(self) -> None:
        cases = [
            ({"pattern": "AA BB", "mask": "x"}, "mask length must match the pattern byte count"),
            ({"pattern": "AA BB", "mask": "xz"}, "mask must contain only x and ? characters"),
            ({"pattern": "AA ??", "mask": "xx"}, "mask marks an exact byte where the pattern uses ??"),
            ({"pattern": "AA BB", "target_offset": "abc"}, "target_offset must be an unsigned integer"),
        ]

        for fields, message in cases:
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(RuntimeError, re.escape(message)):
                    _send_native_request(
                        self.session_manager,
                        self.target_pid,
                        "pattern_scan",
                        process_name=TARGET_PROCESS_NAME,
                        limit=1,
                        **fields,
                    )

    def test_create_aob_pattern_fails_when_search_budget_is_too_small(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "pattern_generation_failed"):
            _send_native_request(
                self.session_manager,
                self.target_pid,
                "create_aob_pattern",
                process_name=TARGET_PROCESS_NAME,
                address=self.target_symbols["g_bytes"],
                max_bytes=1,
            )


class NameFallbackAutoInjectionRequestsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "TestTarget" / "TestTarget.exe"
        cls.injector_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "Injector" / "Injector.exe"
        cls.dll_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "InternalDebuggerDLL" / "InternalDebuggerDLL.dll"

        missing = [path for path in (cls.target_path, cls.injector_path, cls.dll_path) if not path.exists()]
        if missing:
            raise unittest.SkipTest(f"Missing build artifacts: {', '.join(str(path) for path in missing)}")

    def test_stale_pid_falls_back_to_exact_process_name(self) -> None:
        stale_target, _ = _start_target_process(self.target_path)
        stale_pid = stale_target.pid
        _stop_target_process(stale_target)

        replacement_target, _ = _start_target_process(self.target_path)
        session_manager = SessionManager()

        try:
            fields = _send_native_request(
                session_manager,
                stale_pid,
                "ping",
                process_name=TARGET_PROCESS_NAME,
            )
            self.assertEqual(fields["pid"][0], str(replacement_target.pid))
            self.assertTrue(_wait_for_module_state(replacement_target.pid, DEBUGGER_DLL_NAME, loaded=True))
        finally:
            _stop_target_process(replacement_target)


if __name__ == "__main__":
    unittest.main()