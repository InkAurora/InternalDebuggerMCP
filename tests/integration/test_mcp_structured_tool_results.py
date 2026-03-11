from __future__ import annotations

import asyncio
import csv
import subprocess
import sys
import time
import unittest
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))


DEBUGGER_DLL_NAME = "InternalDebuggerDLL.dll"
TARGET_PROCESS_NAME = "TestTarget.exe"


def _read_target_startup(process) -> dict[str, str]:
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
            required = {"g_write_target", "g_read_watch_target", "g_write_watch_target"}
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
        if module_name.lower() in row[-1].strip().lower():
            return True
    return False


def _wait_for_module_state(pid: int, module_name: str, *, loaded: bool, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _is_module_loaded(pid, module_name) == loaded:
            return True
        time.sleep(0.1)
    return False


class McpStructuredToolResultsTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_injection_setup_returns_structured_content_without_text_mirror(self) -> None:
        server = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SRC / "launch.py")],
            cwd=str(MCP_SRC),
            env={"PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"},
        )

        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("get_injection_setup")

        self.assertFalse(result.isError)
        self.assertEqual(result.content, [])
        self.assertIsNotNone(result.structuredContent)
        assert result.structuredContent is not None
        self.assertIn("layout_mode", result.structuredContent)
        self.assertIn("injector_path", result.structuredContent)

    async def test_write_memory_and_invoke_function_return_structured_content(self) -> None:
        target_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "TestTarget" / "TestTarget.exe"
        if not target_path.exists():
            raise unittest.SkipTest(f"Missing build artifact: {target_path}")

        target = subprocess.Popen(
            [str(target_path)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        assert target.stdout is not None
        symbols = _read_target_startup(target)

        server = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SRC / "launch.py")],
            cwd=str(MCP_SRC),
            env={"PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"},
        )

        try:
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    write_result = await session.call_tool(
                        "write_memory",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "address": symbols["g_write_target"],
                            "bytes_hex": "AA BB CC DD EE FF 00 11",
                        },
                    )
                    invoke_result = await session.call_tool(
                        "invoke_function",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "module": "TestTarget.exe",
                            "export": "ExportedFillBuffer",
                            "args": [
                                {"kind": "out_buffer", "size": 4},
                                {"kind": "u64", "value": 4},
                                {"kind": "u64", "value": 0x30},
                            ],
                        },
                    )
        finally:
            if target.poll() is None:
                target.terminate()
                try:
                    target.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    target.kill()
                    target.wait(timeout=5)
            if target.stdout is not None:
                target.stdout.close()

        self.assertFalse(write_result.isError)
        self.assertEqual(write_result.content, [])
        self.assertIsNotNone(write_result.structuredContent)
        assert write_result.structuredContent is not None
        self.assertEqual(write_result.structuredContent["bytes_written"], 8)
        self.assertEqual(write_result.structuredContent["read_back"], "AA BB CC DD EE FF 00 11")

        self.assertFalse(invoke_result.isError)
        self.assertEqual(invoke_result.content, [])
        self.assertIsNotNone(invoke_result.structuredContent)
        assert invoke_result.structuredContent is not None
        self.assertEqual(invoke_result.structuredContent["return_value"], 4)
        self.assertEqual(invoke_result.structuredContent["outputs"][0]["bytes"], "30 31 32 33")

    async def test_eject_debugger_tool_and_server_shutdown_remove_the_debugger_dll(self) -> None:
        target_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "TestTarget" / "TestTarget.exe"
        if not target_path.exists():
            raise unittest.SkipTest(f"Missing build artifact: {target_path}")

        target = subprocess.Popen(
            [str(target_path)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        assert target.stdout is not None
        _read_target_startup(target)

        server = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SRC / "launch.py")],
            cwd=str(MCP_SRC),
            env={"PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"},
        )

        try:
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()

                    ping_result = await session.call_tool(
                        "ping",
                        {"pid": target.pid, "process_name": TARGET_PROCESS_NAME},
                    )
                    self.assertFalse(ping_result.isError)
                    self.assertTrue(await asyncio.to_thread(_wait_for_module_state, target.pid, DEBUGGER_DLL_NAME, loaded=True))

                    eject_result = await session.call_tool("eject_debugger", {"pid": target.pid})
                    self.assertFalse(eject_result.isError)
                    self.assertEqual(eject_result.content, [])
                    self.assertIsNotNone(eject_result.structuredContent)
                    assert eject_result.structuredContent is not None
                    self.assertEqual(eject_result.structuredContent["status"], "ejected")
                    self.assertIn(eject_result.structuredContent["method"], {"pipe", "injector"})
                    self.assertTrue(eject_result.structuredContent["cleared_session"])
                    self.assertTrue(await asyncio.to_thread(_wait_for_module_state, target.pid, DEBUGGER_DLL_NAME, loaded=False))

                    reinject_result = await session.call_tool(
                        "ping",
                        {"pid": target.pid, "process_name": TARGET_PROCESS_NAME},
                    )
                    self.assertFalse(reinject_result.isError)
                    self.assertTrue(await asyncio.to_thread(_wait_for_module_state, target.pid, DEBUGGER_DLL_NAME, loaded=True))

            self.assertTrue(await asyncio.to_thread(_wait_for_module_state, target.pid, DEBUGGER_DLL_NAME, loaded=False))
        finally:
            if target.poll() is None:
                target.terminate()
                try:
                    target.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    target.kill()
                    target.wait(timeout=5)
            if target.stdout is not None:
                target.stdout.close()

    async def test_access_watch_tools_return_structured_source_aggregates(self) -> None:
        target_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "TestTarget" / "TestTarget.exe"
        if not target_path.exists():
            raise unittest.SkipTest(f"Missing build artifact: {target_path}")

        target = subprocess.Popen(
            [str(target_path)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        assert target.stdout is not None
        symbols = _read_target_startup(target)

        server = StdioServerParameters(
            command=sys.executable,
            args=[str(MCP_SRC / "launch.py")],
            cwd=str(MCP_SRC),
            env={"PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"},
        )

        try:
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    read_watch = await session.call_tool(
                        "watch_memory_reads",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "address": symbols["g_read_watch_target"],
                            "size": 8,
                            "watch_id": "structured_read_watch",
                        },
                    )
                    write_watch = await session.call_tool(
                        "watch_memory_writes",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "address": symbols["g_write_watch_target"],
                            "size": 8,
                            "watch_id": "structured_write_watch",
                        },
                    )

                    await asyncio.sleep(0.5)

                    read_results = await session.call_tool(
                        "poll_access_watch_results",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "watch_id": "structured_read_watch",
                        },
                    )
                    write_results = await session.call_tool(
                        "poll_access_watch_results",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "watch_id": "structured_write_watch",
                        },
                    )

                    await session.call_tool(
                        "unwatch_access_watch",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "watch_id": "structured_read_watch",
                        },
                    )
                    await session.call_tool(
                        "unwatch_access_watch",
                        {
                            "pid": target.pid,
                            "process_name": TARGET_PROCESS_NAME,
                            "watch_id": "structured_write_watch",
                        },
                    )
        finally:
            if target.poll() is None:
                target.terminate()
                try:
                    target.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    target.kill()
                    target.wait(timeout=5)
            if target.stdout is not None:
                target.stdout.close()

        self.assertFalse(read_watch.isError)
        self.assertFalse(write_watch.isError)
        self.assertFalse(read_results.isError)
        self.assertFalse(write_results.isError)

        assert read_results.structuredContent is not None
        assert write_results.structuredContent is not None
        self.assertEqual(read_results.structuredContent["mode"], "read")
        self.assertEqual(write_results.structuredContent["mode"], "write")
        self.assertEqual(read_results.structuredContent["state"], "active")
        self.assertEqual(write_results.structuredContent["state"], "active")
        self.assertFalse(read_results.structuredContent["timed_out"])
        self.assertFalse(write_results.structuredContent["timed_out"])
        self.assertGreater(read_results.structuredContent["total_hit_count"], 0)
        self.assertGreater(write_results.structuredContent["total_hit_count"], 0)
        self.assertGreaterEqual(read_results.structuredContent["source_count"], 1)
        self.assertGreaterEqual(write_results.structuredContent["source_count"], 1)
        self.assertEqual(read_results.structuredContent["sources"][0]["last_access_address"].lower(), symbols["g_read_watch_target"].lower())
        self.assertEqual(write_results.structuredContent["sources"][0]["last_access_address"].lower(), symbols["g_write_watch_target"].lower())
        self.assertIn("mov", read_results.structuredContent["sources"][0]["instruction"].lower())
        self.assertIn("mov", write_results.structuredContent["sources"][0]["instruction"].lower())


if __name__ == "__main__":
    unittest.main()