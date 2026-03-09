from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))

from mcp_server.package_layout import build_injection_setup, resolve_runtime_layout  # noqa: E402


class TestInjectionSetup(unittest.TestCase):
    def test_repo_layout_points_at_release_artifacts(self) -> None:
        layout = resolve_runtime_layout()

        self.assertEqual(layout.mode, "repo")
        self.assertEqual(layout.package_root, REPO_ROOT)
        self.assertEqual(layout.injector_path, REPO_ROOT / "artifacts" / "Release" / "x64" / "Injector" / "Injector.exe")
        self.assertEqual(
            layout.dll_path,
            REPO_ROOT / "artifacts" / "Release" / "x64" / "InternalDebuggerDLL" / "InternalDebuggerDLL.dll",
        )

    def test_package_layout_points_at_extracted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir) / "InternalDebuggerMCP"
            module_path = package_root / "mcp-server" / "mcp_server" / "package_layout.py"
            module_path.parent.mkdir(parents=True)
            (package_root / "mcp-server" / "launch.py").write_text("", encoding="ascii")

            layout = resolve_runtime_layout(module_path)

            self.assertEqual(layout.mode, "package")
            self.assertEqual(layout.package_root, package_root)
            self.assertEqual(layout.injector_path, package_root / "Injector.exe")
            self.assertEqual(layout.dll_path, package_root / "InternalDebuggerDLL.dll")

    def test_injection_setup_contains_command_templates(self) -> None:
        setup = build_injection_setup()

        self.assertEqual(setup["layout_mode"], "repo")
        self.assertIn("injector_command", setup)
        self.assertIn("powershell", setup["injector_command"])
        self.assertIn("<PID>", setup["injector_command"]["powershell"])
        self.assertEqual(setup["vscode_mcp_setup"]["python_command"], "python")
        self.assertEqual(setup["pipe_name_pattern"], r"\\.\pipe\InternalDebuggerMCP_<pid>")
        self.assertIn("ping(pid, process_name)", setup["recommended_workflow"][1])
        self.assertIn("omit it or use null", setup["recommended_workflow"][2])
        self.assertIn("Empty-string dll_path values are treated the same as omitting dll_path", setup["notes"][3])