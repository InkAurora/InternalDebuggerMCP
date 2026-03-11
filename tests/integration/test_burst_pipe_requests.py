from __future__ import annotations

import concurrent.futures
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

from mcp_server.pipe_client import NativeRequestError, PipeClient  # noqa: E402


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
            required = {"g_write_target", "SampleFunction"}
            missing = required.difference(symbols)
            if missing:
                raise AssertionError(f"Missing startup symbols: {', '.join(sorted(missing))}")
            return symbols

        if ": 0x" in text:
            label, value = text.split(": 0x", 1)
            symbols[label.strip()] = f"0x{value.strip()}"

    raise AssertionError("Timed out waiting for TestTarget startup banner")


class BurstPipeRequestsTest(unittest.TestCase):
    marker_pattern = "49 4E 54 45 52 4E 41 4C 5F 44 45 42 55 47 47 45 52 5F 4D 43 50 5F 50 41 54 54 45 52 4E"
    function_pattern = "55 48 89 E5 90 C3"

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

        subprocess.run(
            [str(cls.injector_path), str(cls.target_pid), str(cls.dll_path.resolve())],
            cwd=REPO_ROOT,
            check=True,
            timeout=15,
        )

        cls._wait_for_pipe()

        client = PipeClient(cls.target_pid, timeout_ms=5000)

        marker_response = client.request("pattern_scan", pattern=cls.marker_pattern, limit=1)
        marker_response.raise_for_error()
        cls.marker_address = marker_response.one("match")
        if cls.marker_address is None:
            raise AssertionError("Failed to locate marker string in target process")

        function_response = client.request("pattern_scan", pattern=cls.function_pattern, limit=1)
        function_response.raise_for_error()
        cls.function_address = function_response.one("match")
        if cls.function_address is None:
            raise AssertionError("Failed to locate sample function bytes in target process")

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

    @classmethod
    def _wait_for_pipe(cls) -> None:
        deadline = time.time() + 10.0
        while time.time() < deadline:
            try:
                response = PipeClient(cls.target_pid, timeout_ms=250).request("ping")
                response.raise_for_error()
                return
            except (OSError, NativeRequestError):
                time.sleep(0.1)
        raise AssertionError("Timed out waiting for injected pipe server to become reachable")

    def test_parallel_requests_succeed(self) -> None:
        request_specs = [
            ("ping", {}),
            ("list_modules", {}),
            ("pattern_scan", {"pattern": self.marker_pattern, "limit": 1}),
            ("pattern_scan", {"pattern": self.marker_pattern, "mask": "xxxx?xxxxxxxxxxxxxxxxxxxxxxxx", "target_offset": 4, "limit": 1}),
            ("read_memory", {"address": self.marker_address, "size": 29}),
            ("disassemble", {"address": self.function_address, "size": 6, "max_instructions": 6}),
            ("list_modules", {}),
            ("pattern_scan", {"pattern": self.marker_pattern, "limit": 1}),
            ("ping", {}),
        ]

        def execute_request(spec: tuple[str, dict[str, str | int]]) -> dict[str, list[str]]:
            command, fields = spec
            client = PipeClient(self.target_pid, timeout_ms=5000)
            response = client.request(command, **fields)
            response.raise_for_error()
            return response.fields

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(request_specs)) as executor:
            results = list(executor.map(execute_request, request_specs))

        self.assertEqual(len(results), len(request_specs))
        self.assertEqual(results[0]["status"][0], "ok")
        self.assertEqual(results[1]["status"][0], "ok")
        self.assertEqual(results[2]["match_count"][0], "1")
        self.assertEqual(results[3]["match_count"][0], "1")
        self.assertEqual(int(results[3]["match_start"][0], 16), int(self.marker_address, 16))
        self.assertEqual(int(results[3]["match"][0], 16), int(self.marker_address, 16) + 4)
        self.assertEqual(results[4]["bytes"][0], self.marker_pattern)
        self.assertEqual(results[5]["instruction_count"][0], "4")
        self.assertTrue(any(module.startswith("TestTarget.exe|") for module in results[6].get("module", [])))
        self.assertEqual(results[7]["match_count"][0], "1")
        self.assertEqual(results[8]["status"][0], "ok")


if __name__ == "__main__":
    unittest.main()