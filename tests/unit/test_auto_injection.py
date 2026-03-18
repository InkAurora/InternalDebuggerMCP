from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))

from mcp_server.injection import InjectionError, eject_debugger, inject_debugger  # noqa: E402
from mcp_server.package_layout import RuntimeLayout  # noqa: E402
from mcp_server.pipe_client import PipeResponse  # noqa: E402
from mcp_server.tools import (  # noqa: E402
    _coerce_address,
    _prepare_invoke_fields,
    _prepare_write_payload,
    _rebase_address_payload,
    _resolve_module_record,
    _send_native_request,
)


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
    def __init__(self, failures_before_success: int = 0, *, response_pid: int = 4242) -> None:
        self.failures_before_success = failures_before_success
        self.calls = 0
        self.response_pid = response_pid

    def request(self, command: str, **fields: str | int) -> PipeResponse:
        self.calls += 1
        if self.calls <= self.failures_before_success:
            raise OSError(2, "The system cannot find the file specified")
        pid_text = str(self.response_pid)
        return PipeResponse(raw=f"status=ok\npid={pid_text}\n\n", fields={"status": ["ok"], "pid": [pid_text]})


class _FakeSession:
    def __init__(self, client: _FakeClient) -> None:
        self.client = client


class _FakeSessionManager:
    def __init__(self, clients: dict[int, _FakeClient] | None = None) -> None:
        self._clients = clients or {}
        self._bootstrap_lock = Lock()
        self.cleanup_calls: list[tuple[int, str | None]] = []
        self.remembered_targets: list[tuple[int, str | None, str | None]] = []
        self.reset_pids: list[int] = []

    def get(self, pid: int) -> _FakeSession:
        client = self._clients.setdefault(pid, _FakeClient(response_pid=pid))
        return _FakeSession(client)

    def remember_target(self, pid: int, *, dll_path: str | None = None, process_name: str | None = None) -> None:
        self.remembered_targets.append((pid, dll_path, process_name))

    def remember_dll_path(self, pid: int, dll_path: str | None) -> None:
        self.remember_target(pid, dll_path=dll_path)

    def cleanup_pid(self, pid: int, dll_path: str | None = None) -> None:
        self.cleanup_calls.append((pid, dll_path))

    def reset(self, pid: int) -> None:
        self.reset_pids.append(pid)

    def bootstrap_lock(self, pid: int) -> Lock:
        return self._bootstrap_lock


class TestAutoInjection(unittest.TestCase):
    def test_resolve_module_record_supports_name_path_and_basename_matching(self) -> None:
        modules = [
            {
                "name": "TestTarget.exe",
                "base": "0x140000000",
                "size": 4096,
                "path": r"C:\Temp\TestTarget.exe",
            },
            {
                "name": "FriendlyAlias.dll",
                "base": "0x180000000",
                "size": 8192,
                "path": r"C:\Temp\BasenameOnly.dll",
            },
        ]

        by_name = _resolve_module_record(modules, "testtarget.exe")
        by_path = _resolve_module_record(modules, r"c:\temp\testtarget.exe")
        by_basename = _resolve_module_record(modules, "basenameonly.dll")

        self.assertEqual(by_name["module_name"], "TestTarget.exe")
        self.assertEqual(by_name["match_method"], "name")
        self.assertEqual(by_path["match_method"], "path")
        self.assertEqual(by_basename["module_name"], "FriendlyAlias.dll")
        self.assertEqual(by_basename["match_method"], "basename")

    def test_resolve_module_record_rejects_missing_and_ambiguous_matches(self) -> None:
        with self.assertRaises(RuntimeError) as missing_error:
            _resolve_module_record([], "missing.dll")
        self.assertIn("module_not_found", str(missing_error.exception))

        modules = [
            {"name": "Dup.dll", "base": "0x1000", "size": 16, "path": r"C:\One\Dup.dll"},
            {"name": "Dup.dll", "base": "0x2000", "size": 16, "path": r"C:\Two\Dup.dll"},
        ]
        with self.assertRaises(RuntimeError) as ambiguous_error:
            _resolve_module_record(modules, "dup.dll")
        self.assertIn("module_ambiguous", str(ambiguous_error.exception))

    def test_coerce_address_accepts_decimal_and_hex_inputs(self) -> None:
        self.assertEqual(_coerce_address(4096, field_name="address"), 4096)
        self.assertEqual(_coerce_address("4096", field_name="address"), 4096)
        self.assertEqual(_coerce_address("0x1000", field_name="address"), 4096)

        with self.assertRaises(ValueError):
            _coerce_address("", field_name="address")
        with self.assertRaises(ValueError):
            _coerce_address(-1, field_name="address")

    def test_rebase_address_payload_supports_both_directions(self) -> None:
        module_record = {
            "module_query": "TestTarget.exe",
            "module_name": "TestTarget.exe",
            "base_address": "0x140000000",
            "image_size": 4096,
            "module_path": r"C:\Temp\TestTarget.exe",
            "match_method": "name",
        }

        va_payload = _rebase_address_payload(module_record, direction="rva_to_va", offset="0x1234")
        rva_payload = _rebase_address_payload(module_record, direction="va_to_rva", address="0x140001234")

        self.assertEqual(va_payload["offset"], "0x1234")
        self.assertEqual(va_payload["address"], "0x140001234")
        self.assertEqual(rva_payload["offset"], "0x1234")
        self.assertEqual(rva_payload["address"], "0x140001234")

    def test_rebase_address_payload_rejects_invalid_direction_and_underflow(self) -> None:
        module_record = {
            "module_query": "TestTarget.exe",
            "module_name": "TestTarget.exe",
            "base_address": "0x140000000",
            "image_size": 4096,
            "module_path": r"C:\Temp\TestTarget.exe",
            "match_method": "name",
        }

        with self.assertRaises(ValueError):
            _rebase_address_payload(module_record, direction="sideways", offset=1)
        with self.assertRaises(ValueError):
            _rebase_address_payload(module_record, direction="rva_to_va", address="0x140000000")
        with self.assertRaises(ValueError):
            _rebase_address_payload(module_record, direction="va_to_rva", address="0x13FFFFFFF")

    def test_prepare_write_payload_encodes_text_and_hex(self) -> None:
        self.assertEqual(
            _prepare_write_payload(bytes_hex=None, text="AB", encoding="utf-8", zero_terminate=True),
            "41 42 00",
        )
        self.assertEqual(
            _prepare_write_payload(bytes_hex="aa bb cc", text=None, encoding="utf-8", zero_terminate=False),
            "AA BB CC",
        )

    def test_prepare_invoke_fields_encodes_strings_and_buffers(self) -> None:
        fields = _prepare_invoke_fields(
            [
                {"kind": "u64", "value": 7},
                {"kind": "f32", "value": 1.25},
                {"kind": "f64", "value": 2.5},
                {"kind": "pointer", "value": "0x1234"},
                {"kind": "string", "value": "Hi", "encoding": "utf-16-le"},
                {"kind": "out_buffer", "size": 8},
            ]
        )

        self.assertEqual(fields["arg_count"], 6)
        self.assertEqual(fields["arg0_kind"], "u64")
        self.assertEqual(fields["arg0_value"], 7)
        self.assertEqual(fields["arg1_kind"], "f32")
        self.assertEqual(fields["arg1_value"], " ".join(f"{byte:02X}" for byte in struct.pack("<f", 1.25)))
        self.assertEqual(fields["arg2_kind"], "f64")
        self.assertEqual(fields["arg2_value"], " ".join(f"{byte:02X}" for byte in struct.pack("<d", 2.5)))
        self.assertEqual(fields["arg3_kind"], "pointer")
        self.assertEqual(fields["arg3_value"], "0x1234")
        self.assertEqual(fields["arg4_kind"], "utf16")
        self.assertEqual(fields["arg4_value"], "48 00 69 00 00 00")
        self.assertEqual(fields["arg5_kind"], "out_buffer")
        self.assertEqual(fields["arg5_size"], 8)

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

    def test_inject_debugger_treats_blank_dll_override_as_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir)
            layout = _make_layout(package_root)
            layout.injector_path.write_text("", encoding="ascii")
            layout.dll_path.write_text("default", encoding="ascii")

            with patch("mcp_server.injection.resolve_runtime_layout", return_value=layout):
                with patch("mcp_server.injection.wait_for_debugger_pipe", side_effect=[False, True]):
                    with patch(
                        "mcp_server.injection.subprocess.run",
                        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                    ) as run_mock:
                        result = inject_debugger(4242, dll_path="")

        self.assertEqual(result.dll_path, str(layout.dll_path.resolve()))
        self.assertEqual(run_mock.call_args.args[0], [str(layout.injector_path.resolve()), "4242", str(layout.dll_path.resolve())])

    def test_send_native_request_injects_after_transport_failure(self) -> None:
        manager = _FakeSessionManager({4242: _FakeClient(failures_before_success=2, response_pid=4242)})

        with patch(
            "mcp_server.tools.inject_debugger",
            return_value=SimpleNamespace(dll_path="C:/debug/custom.dll"),
        ) as inject_mock:
            fields = _send_native_request(
                manager,
                4242,
                "ping",
                process_name="TestTarget.exe",
                dll_path="C:/debug/custom.dll",
            )

        self.assertEqual(fields["pid"][0], "4242")
        inject_mock.assert_called_once_with(4242, dll_path="C:/debug/custom.dll")
        self.assertEqual(manager.cleanup_calls, [(4242, "C:/debug/custom.dll"), (4242, "C:/debug/custom.dll")])
        self.assertIn((4242, "C:/debug/custom.dll", "TestTarget.exe"), manager.remembered_targets)
        self.assertEqual(manager.reset_pids, [])

    def test_send_native_request_skips_injection_when_pipe_is_already_live(self) -> None:
        manager = _FakeSessionManager({4242: _FakeClient(failures_before_success=0, response_pid=4242)})

        with patch("mcp_server.tools.inject_debugger") as inject_mock:
            fields = _send_native_request(manager, 4242, "ping", process_name="TestTarget.exe")

        self.assertEqual(fields["pid"][0], "4242")
        inject_mock.assert_not_called()
        self.assertEqual(manager.reset_pids, [])

    def test_send_native_request_falls_back_to_process_name_when_original_pid_attach_fails(self) -> None:
        original_pid = 4242
        fallback_pid = 5252
        manager = _FakeSessionManager(
            {
                original_pid: _FakeClient(failures_before_success=99, response_pid=original_pid),
                fallback_pid: _FakeClient(failures_before_success=2, response_pid=fallback_pid),
            }
        )

        with patch(
            "mcp_server.tools.inject_debugger",
            side_effect=[
                InjectionError("pipe_timeout", "Timed out waiting for debugger pipe after injection"),
                SimpleNamespace(dll_path="C:/debug/custom.dll"),
            ],
        ) as inject_mock:
            with patch(
                "mcp_server.tools._list_process_matches",
                return_value=[{"name": "TestTarget.exe", "pid": fallback_pid}],
            ):
                fields = _send_native_request(
                    manager,
                    original_pid,
                    "ping",
                    process_name="TestTarget.exe",
                    dll_path="C:/debug/custom.dll",
                )

        self.assertEqual(fields["pid"][0], str(fallback_pid))
        self.assertEqual(
            [call.args for call in inject_mock.call_args_list],
            [(original_pid,), (fallback_pid,)],
        )
        self.assertEqual(
            [call.kwargs for call in inject_mock.call_args_list],
            [{"dll_path": "C:/debug/custom.dll"}, {"dll_path": "C:/debug/custom.dll"}],
        )
        self.assertIn((fallback_pid, "C:/debug/custom.dll", "TestTarget.exe"), manager.remembered_targets)

    def test_send_native_request_reports_missing_process_name_match_after_pid_failure(self) -> None:
        manager = _FakeSessionManager({4242: _FakeClient(failures_before_success=99, response_pid=4242)})

        with patch(
            "mcp_server.tools.inject_debugger",
            side_effect=InjectionError("pipe_timeout", "Timed out waiting for debugger pipe after injection"),
        ):
            with patch("mcp_server.tools._list_process_matches", return_value=[]):
                with self.assertRaises(RuntimeError) as context:
                    _send_native_request(manager, 4242, "ping", process_name="TestTarget.exe")

        self.assertIn("process_name_not_found", str(context.exception))

    def test_send_native_request_reports_ambiguous_process_name_matches(self) -> None:
        manager = _FakeSessionManager({4242: _FakeClient(failures_before_success=99, response_pid=4242)})

        with patch(
            "mcp_server.tools.inject_debugger",
            side_effect=InjectionError("pipe_timeout", "Timed out waiting for debugger pipe after injection"),
        ):
            with patch(
                "mcp_server.tools._list_process_matches",
                return_value=[
                    {"name": "TestTarget.exe", "pid": 5001},
                    {"name": "TestTarget.exe", "pid": 5002},
                ],
            ):
                with self.assertRaises(RuntimeError) as context:
                    _send_native_request(manager, 4242, "ping", process_name="TestTarget.exe")

        self.assertIn("process_name_ambiguous", str(context.exception))

    def test_send_native_request_does_not_fallback_for_missing_injector_or_dll(self) -> None:
        manager = _FakeSessionManager({4242: _FakeClient(failures_before_success=99, response_pid=4242)})

        with patch(
            "mcp_server.tools.inject_debugger",
            side_effect=InjectionError("missing_dll", "Debugger DLL not found"),
        ):
            with patch("mcp_server.tools._list_process_matches") as lookup_mock:
                with self.assertRaises(RuntimeError) as context:
                    _send_native_request(manager, 4242, "ping", process_name="TestTarget.exe")

        lookup_mock.assert_not_called()
        self.assertIn("missing_dll", str(context.exception))

    def test_eject_debugger_reports_pipe_success_when_module_is_already_gone(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = Path(temp_dir)
            layout = _make_layout(package_root)
            layout.injector_path.write_text("", encoding="ascii")
            layout.dll_path.write_text("default", encoding="ascii")

            with patch("mcp_server.injection.resolve_runtime_layout", return_value=layout):
                with patch("mcp_server.injection.request_debugger_eject", return_value="scheduled"):
                    with patch(
                        "mcp_server.injection.subprocess.run",
                        return_value=subprocess.CompletedProcess(
                            args=[],
                            returncode=3,
                            stdout="",
                            stderr="Debugger DLL not loaded in PID 4242",
                        ),
                    ) as run_mock:
                        result = eject_debugger(4242)

        self.assertEqual(result.method, "pipe")
        self.assertEqual(result.status, "ejected")
        self.assertEqual(result.detail, "scheduled")
        self.assertEqual(
            run_mock.call_args.args[0],
            [str(layout.injector_path.resolve()), "--eject", "4242", str(layout.dll_path.resolve())],
        )


if __name__ == "__main__":
    unittest.main()