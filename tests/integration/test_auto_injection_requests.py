from __future__ import annotations

import subprocess
import sys
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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.target_pid = cls.target_process.pid
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

    def test_first_request_auto_injects_and_returns_modules(self) -> None:
        ping_fields = _send_native_request(self.session_manager, self.target_pid, "ping")
        modules_fields = _send_native_request(self.session_manager, self.target_pid, "list_modules")

        self.assertEqual(ping_fields["pid"][0], str(self.target_pid))
        self.assertEqual(modules_fields["module_count"][0].isdigit(), True)
        self.assertTrue(any("InternalDebuggerDLL.dll" in module for module in modules_fields.get("module", [])))


if __name__ == "__main__":
    unittest.main()