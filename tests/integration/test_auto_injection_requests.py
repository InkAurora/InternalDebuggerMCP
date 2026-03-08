from __future__ import annotations

import csv
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
from mcp_server.tools import _send_native_request  # noqa: E402


DEBUGGER_DLL_NAME = "InternalDebuggerDLL.dll"


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
            required = {"g_write_target", "SampleFunction", "ExportedStoreValue", "ExportedFillBuffer"}
            missing = required.difference(symbols)
            if missing:
                raise AssertionError(f"Missing startup symbols: {', '.join(sorted(missing))}")
            return symbols

        if ": 0x" in text:
            label, value = text.split(": 0x", 1)
            symbols[label.strip()] = f"0x{value.strip()}"

    raise AssertionError("Timed out waiting for TestTarget startup banner")


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

        cls.target_process = subprocess.Popen(
            [str(cls.target_path)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        cls.target_pid = cls.target_process.pid
        assert cls.target_process.stdout is not None
        cls.target_symbols = _read_target_startup(cls.target_process)
        cls.session_manager = SessionManager()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "target_process") and cls.target_process.poll() is None:
            cls.target_process.terminate()
            try:
                cls.target_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.target_process.kill()
                cls.target_process.wait(timeout=5)
        if hasattr(cls, "target_process") and cls.target_process.stdout is not None:
            cls.target_process.stdout.close()

    def test_first_request_auto_injects_and_returns_modules(self) -> None:
        ping_fields = _send_native_request(self.session_manager, self.target_pid, "ping")
        modules_fields = _send_native_request(self.session_manager, self.target_pid, "list_modules")

        self.assertEqual(ping_fields["pid"][0], str(self.target_pid))
        self.assertEqual(modules_fields["module_count"][0].isdigit(), True)
        self.assertEqual(modules_fields["enumeration_method"][0], "toolhelp_snapshot")
        self.assertTrue(any("InternalDebuggerDLL.dll" in module for module in modules_fields.get("module", [])))

        for _ in range(5):
            repeated = _send_native_request(self.session_manager, self.target_pid, "list_modules")
            self.assertEqual(int(repeated["module_count"][0]), len(repeated.get("module", [])))
            self.assertTrue(any(module.startswith("TestTarget.exe|") for module in repeated.get("module", [])))

    def test_write_memory_round_trip(self) -> None:
        payload = "88 77 66 55 44 33 22 11"
        write_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "write_memory",
            address=self.target_symbols["g_write_target"],
            bytes=payload,
            read_back=1,
        )
        read_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "read_memory",
            address=self.target_symbols["g_write_target"],
            size=8,
        )

        self.assertEqual(write_fields["bytes_written"][0], "8")
        self.assertEqual(write_fields["read_back"][0], payload)
        self.assertEqual(read_fields["bytes"][0], payload)

    def test_invoke_function_supports_raw_addresses_exports_and_output_buffers(self) -> None:
        raw_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
            address=self.target_symbols["SampleFunction"],
            arg_count=1,
            arg0_kind="u64",
            arg0_value=5,
        )
        export_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
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
            address=self.target_symbols["g_write_target"],
            size=8,
        )
        buffer_fields = _send_native_request(
            self.session_manager,
            self.target_pid,
            "invoke_function",
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

    def test_eject_command_removes_debugger_and_allows_reinject(self) -> None:
        ping_fields = _send_native_request(self.session_manager, self.target_pid, "ping")
        self.assertEqual(ping_fields["pid"][0], str(self.target_pid))
        self.assertTrue(_wait_for_module_state(self.target_pid, DEBUGGER_DLL_NAME, loaded=True))

        eject_fields = _send_native_request(self.session_manager, self.target_pid, "eject")
        self.assertIn(eject_fields["eject_status"][0], {"scheduled", "already_requested"})
        self.assertTrue(_wait_for_module_state(self.target_pid, DEBUGGER_DLL_NAME, loaded=False))

        reinjected_fields = _send_native_request(self.session_manager, self.target_pid, "ping")
        self.assertEqual(reinjected_fields["pid"][0], str(self.target_pid))
        self.assertTrue(_wait_for_module_state(self.target_pid, DEBUGGER_DLL_NAME, loaded=True))


if __name__ == "__main__":
    unittest.main()