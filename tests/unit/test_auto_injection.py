from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Lock
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))

from mcp_server.injection import InjectionError, inject_debugger  # noqa: E402
from mcp_server.package_layout import RuntimeLayout  # noqa: E402
from mcp_server.pipe_client import PipeResponse  # noqa: E402
from mcp_server.tools import _send_native_request  # noqa: E402


def _make_layout(package_root: Path) -> RuntimeLayout:
    server_root = package_root / "mcp-server"
    server_root.mkdir(parents=True, exist_ok=True)
    (server_root / "launch.py").write_text("", encoding="ascii")
    (server_root / "mcp.json.example").write_text("{}", encoding="ascii")

    return RuntimeLayout(
        mode="package",
        layout_root_label="package root",
        package_root=package_root,
        server_root=server_root,
        launcher_path=server_root / "launch.py",
        injector_path=package_root / "Injector.exe",
        dll_path=package_root / "InternalDebuggerDLL.dll",
        vscode_example_path=server_root / "mcp.json.example",
    )


class _FakeClient:
    def __init__(self, failures_before_success: int = 0) -> None:
        self.failures_before_success = failures_before_success
        self.calls = 0

    def request(self, command: str, **fields: str | int) -> PipeResponse:
        self.calls += 1
        if self.calls <= self.failures_before_success:
            raise OSError(2, "The system cannot find the file specified")
        return PipeResponse(raw="status=ok\npid=4242\n\n", fields={"status": ["ok"], "pid": ["4242"]})


class _FakeSession:
    def __init__(self, client: _FakeClient) -> None:
        self.client = client


class _FakeSessionManager:
    def __init__(self, client: _FakeClient) -> None:
        self._client = client
        self._bootstrap_lock = Lock()
        self.reset_pids: list[int] = []

    def get(self, pid: int) -> _FakeSession:
        return _FakeSession(self._client)

    def reset(self, pid: int) -> None:
        self.reset_pids.append(pid)

    def bootstrap_lock(self, pid: int) -> Lock:
        return self._bootstrap_lock


class TestAutoInjection(unittest.TestCase):
    def test_inject_debugger_uses_override_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir)
            layout = _make_layout(package_root)
            layout.injector_path.write_text("", encoding="ascii")
            layout.dll_path.write_text("default", encoding="ascii")
            custom_dll_path = package_root / "custom.dll"
            custom_dll_path.write_text("custom", encoding="ascii")

            with patch("mcp_server.injection.resolve_runtime_layout", return_value=layout):
                with patch("mcp_server.injection.wait_for_debugger_pipe", side_effect=[False, True]):
                    with patch(
                        "mcp_server.injection.subprocess.run",
                        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                    ) as run_mock:
                        result = inject_debugger(4242, dll_path=custom_dll_path)

        self.assertTrue(result.injected)
        self.assertEqual(result.dll_path, str(custom_dll_path.resolve()))
        self.assertEqual(run_mock.call_args.args[0], [str(layout.injector_path.resolve()), "4242", str(custom_dll_path.resolve())])

    def test_inject_debugger_rejects_missing_override_dll(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir)
            layout = _make_layout(package_root)
            layout.injector_path.write_text("", encoding="ascii")
            layout.dll_path.write_text("default", encoding="ascii")
            missing_dll_path = package_root / "missing.dll"

            with patch("mcp_server.injection.resolve_runtime_layout", return_value=layout):
                with self.assertRaises(InjectionError) as context:
                    inject_debugger(4242, dll_path=missing_dll_path, startup_grace_ms=0)

        self.assertEqual(context.exception.code, "missing_dll")

    def test_send_native_request_injects_after_transport_failure(self) -> None:
        manager = _FakeSessionManager(_FakeClient(failures_before_success=2))

        with patch("mcp_server.tools.inject_debugger") as inject_mock:
            fields = _send_native_request(manager, 4242, "ping", dll_path="C:/debug/custom.dll")

        self.assertEqual(fields["pid"][0], "4242")
        inject_mock.assert_called_once_with(4242, dll_path="C:/debug/custom.dll")
        self.assertEqual(manager.reset_pids, [4242])

    def test_send_native_request_skips_injection_when_pipe_is_already_live(self) -> None:
        manager = _FakeSessionManager(_FakeClient(failures_before_success=0))

        with patch("mcp_server.tools.inject_debugger") as inject_mock:
            fields = _send_native_request(manager, 4242, "ping")

        self.assertEqual(fields["pid"][0], "4242")
        inject_mock.assert_not_called()
        self.assertEqual(manager.reset_pids, [])


if __name__ == "__main__":
    unittest.main()