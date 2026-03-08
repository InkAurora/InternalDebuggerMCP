from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    mode: str
    layout_root_label: str
    package_root: Path
    server_root: Path
    launcher_path: Path
    injector_path: Path
    dll_path: Path
    vscode_example_path: Path


def resolve_runtime_layout(module_file: str | Path | None = None) -> RuntimeLayout:
    module_path = Path(module_file or __file__).resolve()
    module_root = module_path.parent
    server_root = module_root.parent

    if server_root.name == "McpServer":
        package_root = server_root.parent.parent
        return RuntimeLayout(
            mode="repo",
            layout_root_label="repository root",
            package_root=package_root,
            server_root=server_root,
            launcher_path=server_root / "launch.py",
            injector_path=package_root / "artifacts" / "Release" / "x64" / "Injector" / "Injector.exe",
            dll_path=package_root / "artifacts" / "Release" / "x64" / "InternalDebuggerDLL" / "InternalDebuggerDLL.dll",
            vscode_example_path=server_root / "mcp.json.example",
        )

    if server_root.name == "mcp-server":
        package_root = server_root.parent
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

    package_root = server_root.parent
    return RuntimeLayout(
        mode="custom",
        layout_root_label="layout root",
        package_root=package_root,
        server_root=server_root,
        launcher_path=server_root / "launch.py",
        injector_path=package_root / "Injector.exe",
        dll_path=package_root / "InternalDebuggerDLL.dll",
        vscode_example_path=server_root / "mcp.json.example",
    )


def build_injection_setup(module_file: str | Path | None = None) -> dict[str, Any]:
    layout = resolve_runtime_layout(module_file)
    package_root = layout.package_root.resolve()
    launcher_path = layout.launcher_path.resolve()
    injector_path = layout.injector_path.resolve()
    dll_path = layout.dll_path.resolve()
    example_path = layout.vscode_example_path.resolve()

    layout_root_command = (
        '& ".\\Injector.exe" <PID> ".\\InternalDebuggerDLL.dll"'
        if layout.mode == "package"
        else f'& ".\\{layout.injector_path.relative_to(layout.package_root)}" <PID> ".\\{layout.dll_path.relative_to(layout.package_root)}"'
    )

    return {
        "layout_mode": layout.mode,
        "layout_root_label": layout.layout_root_label,
        "package_root": str(package_root),
        "server_root": str(layout.server_root.resolve()),
        "launcher_path": str(launcher_path),
        "injector_path": str(injector_path),
        "injector_exists": injector_path.exists(),
        "dll_path": str(dll_path),
        "dll_exists": dll_path.exists(),
        "pipe_name_pattern": r"\\.\pipe\InternalDebuggerMCP_<pid>",
        "supported_target_architecture": "x64",
        "requires_administrator_for_some_targets": True,
        "injector_command": {
            "executable": str(injector_path),
            "arguments": ["<PID>", str(dll_path)],
            "powershell": f'& "{injector_path}" <PID> "{dll_path}"',
            "layout_root_powershell": layout_root_command,
        },
        "recommended_workflow": [
            "Call find_process_pid(process_name) to resolve the target PID.",
            "Call ping(pid) or any PID-based debugger tool and let the MCP server inject automatically when needed.",
            "Optionally pass dll_path to a PID-based debugger tool when you need a non-default DLL build.",
            "Use the manual Injector.exe command returned here only as a troubleshooting or fallback path.",
            "Use read_memory, pattern_scan, list_modules, disassemble, or watch tools against the injected PID.",
        ],
        "vscode_mcp_setup": {
            "python_command": "python",
            "launcher_path": str(launcher_path),
            "example_config_path": str(example_path),
            "args": [str(launcher_path)],
        },
        "notes": [
            "Injector.exe expects exactly: Injector.exe <pid> <full-dll-path>.",
            "The target process must be x64 for the current DLL build.",
            "PID-based debugger tools now auto-inject by default before the first native request when the pipe is not already reachable.",
            "If OpenProcess or CreateRemoteThread fails, retry from an elevated shell when appropriate.",
        ],
    }