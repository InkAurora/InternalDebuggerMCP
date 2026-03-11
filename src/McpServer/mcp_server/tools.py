from __future__ import annotations

import asyncio
import csv
import struct
import subprocess
from typing import Annotated, Any

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError
except ImportError:  # pragma: no cover - exercised through native fallback when dependency is absent
    CS_ARCH_X86 = 0
    CS_MODE_64 = 0
    Cs = None

    class CsError(Exception):
        pass

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult

from .injection import EjectionResult, InjectionError, inject_debugger
from .package_layout import build_injection_setup
from .pipe_client import NativeRequestError
from .session_manager import SessionManager


StructuredToolResult = Annotated[CallToolResult, dict[str, Any]]


class _NativeRequestFailure(RuntimeError):
    def __init__(self, code: str, detail: str, *, allow_name_fallback: bool = False) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.allow_name_fallback = allow_name_fallback


def _hex_encode(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def _normalize_hex_bytes(value: str) -> str:
    try:
        return _hex_encode(bytes.fromhex(value))
    except ValueError as error:
        raise ValueError("bytes must be a valid space-separated hex string") from error


def _normalize_text_encoding(encoding: str) -> str:
    normalized = encoding.strip().lower().replace("_", "-")
    if normalized in {"utf8", "utf-8", "ascii"}:
        return "utf-8" if normalized != "ascii" else "ascii"
    if normalized in {"utf16", "utf-16", "utf-16le", "utf-16-le"}:
        return "utf-16-le"
    raise ValueError("encoding must be one of: ascii, utf-8, utf-16-le")


def _encode_text_payload(text: str, encoding: str, zero_terminate: bool) -> str:
    codec = _normalize_text_encoding(encoding)
    payload = text.encode(codec)
    if zero_terminate:
        payload += b"\x00\x00" if codec == "utf-16-le" else b"\x00"
    if not payload:
        raise ValueError("text payload must not be empty")
    return _hex_encode(payload)


def _prepare_write_payload(
    *, bytes_hex: str | None, text: str | None, encoding: str, zero_terminate: bool
) -> str:
    if (bytes_hex is None) == (text is None):
        raise ValueError("provide exactly one of bytes_hex or text")
    if bytes_hex is not None:
        return _normalize_hex_bytes(bytes_hex)
    return _encode_text_payload(text or "", encoding, zero_terminate)


def _coerce_unsigned(value: Any, *, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name} must be an integer") from error
    if parsed < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return parsed


def _encode_float_payload(value: Any, *, field_name: str, kind: str) -> str:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a floating-point number")

    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name} must be a floating-point number") from error

    format_code = "<f" if kind == "f32" else "<d"
    try:
        return _hex_encode(struct.pack(format_code, parsed))
    except OverflowError as error:
        raise ValueError(f"{field_name} is out of range for {kind}") from error


def _normalize_invoke_return_kind(value: str | None) -> str:
    normalized = str(value or "u64").strip().lower()
    if normalized not in {"u64", "f32", "f64"}:
        raise ValueError("return_kind must be one of: u64, f32, f64")
    return normalized


def _decode_invoke_return(return_kind: str, return_bits: int) -> int | float:
    if return_kind == "u64":
        return return_bits
    if return_kind == "f32":
        payload = struct.pack("<I", return_bits & 0xFFFFFFFF)
        return struct.unpack("<f", payload)[0]
    payload = struct.pack("<Q", return_bits & 0xFFFFFFFFFFFFFFFF)
    return struct.unpack("<d", payload)[0]


def _prepare_invoke_fields(args: list[dict[str, Any]] | None) -> dict[str, Any]:
    native_fields: dict[str, Any] = {"arg_count": 0}
    if not args:
        return native_fields
    if len(args) > 6:
        raise ValueError("invoke_function currently supports at most 6 arguments")

    native_fields["arg_count"] = len(args)
    for index, arg in enumerate(args):
        if not isinstance(arg, dict):
            raise ValueError(f"argument {index} must be an object")
        raw_kind = str(arg.get("kind", "")).strip().lower()
        if not raw_kind:
            raise ValueError(f"argument {index} is missing kind")

        kind_key = f"arg{index}_kind"
        value_key = f"arg{index}_value"
        size_key = f"arg{index}_size"

        if raw_kind == "u64":
            native_fields[kind_key] = "u64"
            native_fields[value_key] = _coerce_unsigned(arg.get("value"), field_name=f"args[{index}].value")
        elif raw_kind in {"f32", "f64"}:
            native_fields[kind_key] = raw_kind
            native_fields[value_key] = _encode_float_payload(
                arg.get("value"), field_name=f"args[{index}].value", kind=raw_kind
            )
        elif raw_kind == "pointer":
            value = arg.get("value")
            if isinstance(value, int):
                native_fields[value_key] = hex(value)
            elif isinstance(value, str) and value.strip():
                native_fields[value_key] = value.strip()
            else:
                raise ValueError(f"args[{index}].value must be a pointer string or integer")
            native_fields[kind_key] = "pointer"
        elif raw_kind in {"bytes", "inout_buffer"}:
            native_fields[kind_key] = raw_kind
            native_fields[value_key] = _normalize_hex_bytes(str(arg.get("value", "")))
        elif raw_kind in {"utf8", "utf16", "string"}:
            encoding = arg.get("encoding", "utf-8")
            zero_terminate = bool(arg.get("zero_terminate", True))
            encoded = _encode_text_payload(str(arg.get("value", "")), str(encoding), zero_terminate)
            native_fields[kind_key] = "utf16" if _normalize_text_encoding(str(encoding)) == "utf-16-le" else "utf8"
            native_fields[value_key] = encoded
        elif raw_kind == "out_buffer":
            native_fields[kind_key] = "out_buffer"
            native_fields[size_key] = _coerce_unsigned(arg.get("size"), field_name=f"args[{index}].size")
        else:
            raise ValueError(
                f"unsupported argument kind {raw_kind!r}; expected u64, f32, f64, pointer, bytes, string, utf8, utf16, inout_buffer, or out_buffer"
            )

    return native_fields


def _parse_invoke_outputs(fields: dict[str, list[str]]) -> list[dict[str, Any]]:
    outputs = []
    for output in _split_records(fields.get("output", []), 5):
        if len(output) != 5:
            continue
        index, kind, address, size, bytes_hex = output
        outputs.append(
            {
                "index": int(index),
                "kind": kind,
                "address": address,
                "size": int(size),
                "bytes": bytes_hex,
            }
        )
    return outputs


def _capstone_disassemble(address: str, bytes_hex: str, max_instructions: int) -> list[dict[str, Any]] | None:
    if Cs is None:
        return None

    try:
        address_value = int(address, 16)
        data = bytes.fromhex(bytes_hex)
        engine = Cs(CS_ARCH_X86, CS_MODE_64)
        return [
            {
                "address": f"0x{instruction.address:X}",
                "bytes": _hex_encode(bytes(instruction.bytes)),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
            for instruction in engine.disasm(data, address_value, count=max_instructions)
        ]
    except (ValueError, CsError):
        return None


def _split_records(records: list[str], expected_parts: int) -> list[list[str]]:
    parsed: list[list[str]] = []
    for record in records:
        parts = record.split("|", expected_parts - 1)
        parsed.append(parts)
    return parsed


def _list_process_matches(process_name: str, exact_match: bool) -> list[dict[str, int | str]]:
    normalized = process_name.strip()
    if not normalized:
        raise ValueError("process_name must not be empty")

    exact_candidates = {normalized.lower()}
    if "." not in normalized:
        exact_candidates.add(f"{normalized}.exe".lower())

    completed = subprocess.run(
        ["tasklist", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        check=True,
    )

    matches: list[dict[str, int | str]] = []
    for row in csv.reader(completed.stdout.splitlines()):
        if len(row) < 2:
            continue

        name = row[0].strip()
        pid_text = row[1].strip()
        try:
            pid = int(pid_text)
        except ValueError:
            continue

        lowered_name = name.lower()
        if exact_match:
            matched = lowered_name in exact_candidates
        else:
            matched = normalized.lower() in lowered_name

        if matched:
            matches.append({"name": name, "pid": pid})

    return matches


def _structured_result(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(content=[], structuredContent=payload, isError=False)


def _ejection_payload(result: EjectionResult, *, cleared_session: bool) -> dict[str, Any]:
    return {
        "pid": result.pid,
        "dll_path": result.dll_path,
        "method": result.method,
        "status": result.status,
        "detail": result.detail,
        "cleared_session": cleared_session,
    }


def _format_native_failure(error: _NativeRequestFailure) -> str:
    return f"{error.code}: {error.detail}"


def _raise_native_failure(code: str, detail: str, *, allow_name_fallback: bool = False) -> None:
    raise _NativeRequestFailure(code, detail, allow_name_fallback=allow_name_fallback)


def _raise_runtime_for_native_error(session_manager: SessionManager, pid: int, error: NativeRequestError) -> None:
    if error.code == "server_busy":
        _raise_native_failure("server_busy", "native request queue is full; retry the request")
    if error.code == "server_stopping":
        session_manager.reset(pid)
        _raise_native_failure("server_stopping", "the target debugger is restarting or shutting down; retry after the pipe recovers")
    _raise_native_failure(error.code, error.detail)


def _request_once(session_manager: SessionManager, pid: int, command: str, **fields: Any) -> dict[str, list[str]]:
    response = session_manager.get(pid).client.request(command, **fields)
    response.raise_for_error()
    return response.fields


def _cleanup_stale_session(session_manager: SessionManager, pid: int, dll_path: str | None = None) -> None:
    try:
        session_manager.cleanup_pid(pid, dll_path=dll_path)
    except InjectionError as error:
        session_manager.reset(pid)
        _raise_native_failure(
            error.code,
            error.detail,
            allow_name_fallback=error.code not in {"missing_injector", "missing_dll"},
        )


def _resolve_exact_process_pid(process_name: str, *, failed_pid: int) -> int:
    try:
        matches = _list_process_matches(process_name, exact_match=True)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or "tasklist exited with a non-zero status"
        _raise_native_failure("process_lookup_failed", detail)
    except ValueError as error:
        _raise_native_failure("invalid_process_name", str(error))

    if not matches:
        _raise_native_failure(
            "process_name_not_found",
            f"exact process lookup for {process_name!r} returned no running processes after PID {failed_pid} attach failed",
        )

    if len(matches) > 1:
        match_list = ", ".join(f"{match['name']}({match['pid']})" for match in matches)
        _raise_native_failure(
            "process_name_ambiguous",
            f"exact process lookup for {process_name!r} returned multiple matches after PID {failed_pid} attach failed: {match_list}",
        )

    return int(matches[0]["pid"])


def _send_native_request_for_pid(
    session_manager: SessionManager,
    pid: int,
    command: str,
    *,
    process_name: str,
    dll_path: str | None = None,
    **fields: Any,
) -> dict[str, list[str]]:
    session_manager.remember_target(pid, dll_path=dll_path, process_name=process_name)

    try:
        return _request_once(session_manager, pid, command, **fields)
    except NativeRequestError as error:
        _raise_runtime_for_native_error(session_manager, pid, error)
    except OSError:
        _cleanup_stale_session(session_manager, pid, dll_path=dll_path)

    with session_manager.bootstrap_lock(pid):
        try:
            return _request_once(session_manager, pid, command, **fields)
        except NativeRequestError as error:
            _raise_runtime_for_native_error(session_manager, pid, error)
        except OSError:
            _cleanup_stale_session(session_manager, pid, dll_path=dll_path)
            try:
                injection_result = inject_debugger(pid, dll_path=dll_path)
            except InjectionError as error:
                session_manager.reset(pid)
                _raise_native_failure(
                    error.code,
                    error.detail,
                    allow_name_fallback=error.code not in {"missing_injector", "missing_dll"},
                )

            session_manager.remember_target(pid, dll_path=injection_result.dll_path, process_name=process_name)

            try:
                return _request_once(session_manager, pid, command, **fields)
            except NativeRequestError as error:
                _raise_runtime_for_native_error(session_manager, pid, error)
            except OSError as error:
                _cleanup_stale_session(session_manager, pid, dll_path=dll_path)
                _raise_native_failure("transport_error", str(error), allow_name_fallback=True)


def _send_native_request(
    session_manager: SessionManager,
    pid: int,
    command: str,
    *,
    process_name: str,
    dll_path: str | None = None,
    **fields: Any,
) -> dict[str, list[str]]:
    try:
        return _send_native_request_for_pid(
            session_manager,
            pid,
            command,
            process_name=process_name,
            dll_path=dll_path,
            **fields,
        )
    except _NativeRequestFailure as error:
        if not error.allow_name_fallback:
            raise RuntimeError(_format_native_failure(error)) from error
        initial_error = error

    fallback_pid = _resolve_exact_process_pid(process_name, failed_pid=pid)
    if fallback_pid == pid:
        raise RuntimeError(_format_native_failure(initial_error)) from initial_error

    try:
        return _send_native_request_for_pid(
            session_manager,
            fallback_pid,
            command,
            process_name=process_name,
            dll_path=dll_path,
            **fields,
        )
    except _NativeRequestFailure as error:
        raise RuntimeError(_format_native_failure(error)) from error


def create_mcp(session_manager: SessionManager) -> FastMCP:
    mcp = FastMCP("InternalDebuggerMCP", log_level="WARNING")

    async def request(
        pid: int,
        process_name: str,
        command: str,
        *,
        dll_path: str | None = None,
        **fields: Any,
    ) -> dict[str, list[str]]:
        return await asyncio.to_thread(
            _send_native_request,
            session_manager,
            pid,
            command,
            process_name=process_name,
            dll_path=dll_path,
            **fields,
        )

    @mcp.tool(description="Find already running local Windows processes by name and return matching PIDs.")
    async def find_process_pid(process_name: str, exact_match: bool = True) -> StructuredToolResult:
        matches = await asyncio.to_thread(_list_process_matches, process_name, exact_match)
        return _structured_result(
            {
                "query": process_name,
                "exact_match": exact_match,
                "match_count": len(matches),
                "matches": matches,
            }
        )

    @mcp.tool(description="Return injector and DLL path diagnostics plus manual fallback command templates for the current runtime layout.")
    async def get_injection_setup() -> StructuredToolResult:
        return _structured_result(await asyncio.to_thread(build_injection_setup))

    @mcp.tool(description="Check whether the debugger pipe for a target process is reachable. Requires both pid and process_name so stale PIDs can fall back to exact process-name resolution.")
    async def ping(pid: int, process_name: str, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, process_name, "ping", dll_path=dll_path)
        return _structured_result(
            {
                "pid": int(fields["pid"][0]),
                "pipe_name": fields["pipe_name"][0],
                "watch_count": int(fields["watch_count"][0]),
            }
        )

    @mcp.tool(description="Eject the debugger DLL from the target process and clear any tracked MCP session state for that PID.")
    async def eject_debugger(pid: int, dll_path: str | None = None) -> StructuredToolResult:
        cleared_session = await asyncio.to_thread(session_manager.has_session, pid)
        try:
            result = await asyncio.to_thread(session_manager.cleanup_pid, pid, dll_path)
        except InjectionError as error:
            raise RuntimeError(f"{error.code}: {error.detail}") from error

        return _structured_result(_ejection_payload(result, cleared_session=cleared_session))

    @mcp.tool(description="Read a raw byte range from the memory of the target process at the supplied address. Requires both pid and process_name for stale-PID recovery.")
    async def read_memory(pid: int, process_name: str, address: str, size: int, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, process_name, "read_memory", dll_path=dll_path, address=address, size=size)
        return _structured_result(
            {
                "address": fields["address"][0],
                "size": int(fields["size"][0]),
                "bytes": fields["bytes"][0],
            }
        )

    @mcp.tool(description="Write bytes or encoded text into a writable memory range inside the target process. Requires both pid and process_name for stale-PID recovery.")
    async def write_memory(
        pid: int,
        process_name: str,
        address: str,
        bytes_hex: str | None = None,
        text: str | None = None,
        encoding: str = "utf-8",
        zero_terminate: bool = False,
        verify: bool = True,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        payload = _prepare_write_payload(
            bytes_hex=bytes_hex,
            text=text,
            encoding=encoding,
            zero_terminate=zero_terminate,
        )
        fields = await request(
            pid,
            process_name,
            "write_memory",
            dll_path=dll_path,
            address=address,
            bytes=payload,
            read_back=int(verify),
        )
        result: dict[str, Any] = {
            "address": fields["address"][0],
            "requested_size": int(fields["requested_size"][0]),
            "bytes_written": int(fields["bytes_written"][0]),
            "bytes": fields["bytes"][0],
        }
        if "read_back" in fields:
            result["read_back"] = fields["read_back"][0]
        return _structured_result(result)

    @mcp.tool(description="Follow a pointer chain in the target process and return each dereference step. Requires both pid and process_name for stale-PID recovery.")
    async def dereference(
        pid: int,
        process_name: str,
        address: str,
        depth: int = 3,
        pointer_size: int = 8,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "dereference",
            dll_path=dll_path,
            address=address,
            depth=depth,
            pointer_size=pointer_size,
        )
        steps = []
        for step in fields.get("step", []):
            current, value, status = step.split("|", 2)
            steps.append({"address": current, "value": value, "status": status})
        return _structured_result({"start_address": fields["start_address"][0], "steps": steps})

    @mcp.tool(description="Enumerate loaded modules in the target process with base addresses, image sizes, and paths. Requires both pid and process_name for stale-PID recovery.")
    async def list_modules(pid: int, process_name: str, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, process_name, "list_modules", dll_path=dll_path)
        modules = []
        for module in _split_records(fields.get("module", []), 4):
            if len(module) != 4:
                continue
            name, base, size, path = module
            modules.append({"name": name, "base": base, "size": int(size), "path": path})
        payload = {"module_count": int(fields["module_count"][0]), "modules": modules}
        if "enumeration_method" in fields:
            payload["enumeration_method"] = fields["enumeration_method"][0]
        return _structured_result(payload)

    @mcp.tool(description="Scan readable committed memory in the target process for a byte pattern with optional wildcards. Requires both pid and process_name for stale-PID recovery.")
    async def pattern_scan(
        pid: int,
        process_name: str,
        pattern: str,
        mask: str | None = None,
        target_offset: int | None = None,
        start_address: str | None = None,
        region_size: int | None = None,
        limit: int = 32,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        native_fields: dict[str, Any] = {"pattern": pattern, "limit": limit}
        if mask is not None:
            native_fields["mask"] = mask
        if target_offset is not None:
            native_fields["target_offset"] = target_offset
        if start_address is not None:
            native_fields["start"] = start_address
        if region_size is not None:
            native_fields["size"] = region_size
        fields = await request(pid, process_name, "pattern_scan", dll_path=dll_path, **native_fields)
        payload: dict[str, Any] = {
            "match_count": int(fields["match_count"][0]),
            "matches": fields.get("match", []),
        }
        if "match_start" in fields:
            payload["match_starts"] = fields["match_start"]
        return _structured_result(payload)

    @mcp.tool(description="Generate a process-wide unique x64dbg-style AOB pattern for a readable target address. The generated pattern may begin before the requested address and can optionally include a mask and target offset. Requires both pid and process_name for stale-PID recovery.")
    async def create_aob_pattern(
        pid: int,
        process_name: str,
        address: str,
        max_bytes: int = 64,
        include_mask: bool = False,
        include_offset: bool = False,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "create_aob_pattern",
            dll_path=dll_path,
            address=address,
            max_bytes=max_bytes,
            include_mask=int(include_mask),
            include_offset=int(include_offset),
        )
        payload: dict[str, Any] = {
            "address": fields["address"][0],
            "pattern": fields["pattern"][0],
            "pattern_start": fields["pattern_start"][0],
            "match_count": int(fields["match_count"][0]),
            "byte_count": int(fields["byte_count"][0]),
            "wildcard_count": int(fields["wildcard_count"][0]),
        }
        if "mask" in fields:
            payload["mask"] = fields["mask"][0]
        if "target_offset" in fields:
            payload["target_offset"] = int(fields["target_offset"][0])
        return _structured_result(payload)

    @mcp.tool(description="Start polling a target address for changes and create a watch that can be queried for change events. Requires both pid and process_name for stale-PID recovery.")
    async def watch_address(
        pid: int,
        process_name: str,
        address: str,
        size: int,
        interval_ms: int = 250,
        watch_id: str | None = None,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "watch_address",
            dll_path=dll_path,
            address=address,
            size=size,
            interval_ms=interval_ms,
            watch_id=watch_id,
        )
        return _structured_result(
            {
                "watch_id": fields["watch_id"][0],
                "address": fields["address"][0],
                "size": int(fields["size"][0]),
            }
        )

    @mcp.tool(description="Remove an existing memory watch from the target process by watch identifier. Requires both pid and process_name for stale-PID recovery.")
    async def unwatch_address(pid: int, process_name: str, watch_id: str, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, process_name, "unwatch_address", dll_path=dll_path, watch_id=watch_id)
        return _structured_result({"watch_id": fields["watch_id"][0], "removed": True})

    @mcp.tool(description="Fetch pending change events for active memory watches in the target process. Requires both pid and process_name for stale-PID recovery.")
    async def poll_watch_events(pid: int, process_name: str, limit: int = 16, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, process_name, "poll_watch_events", dll_path=dll_path, limit=limit)
        events = []
        for event in _split_records(fields.get("event", []), 5):
            if len(event) != 5:
                continue
            watch_id, address, old_value, new_value, timestamp_ms = event
            events.append(
                {
                    "watch_id": watch_id,
                    "address": address,
                    "old_value": old_value,
                    "new_value": new_value,
                    "timestamp_ms": int(timestamp_ms),
                }
            )
        return _structured_result({"event_count": int(fields["event_count"][0]), "events": events})

    @mcp.tool(description="Install a breakpoint-backed read watch for a small memory range and aggregate hits by source instruction. Requires both pid and process_name for stale-PID recovery.")
    async def watch_memory_reads(
        pid: int,
        process_name: str,
        address: str,
        size: int,
        watch_id: str | None = None,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "watch_memory_reads",
            dll_path=dll_path,
            address=address,
            size=size,
            watch_id=watch_id,
        )
        return _structured_result(
            {
                "watch_id": fields["watch_id"][0],
                "address": fields["address"][0],
                "size": int(fields["size"][0]),
                "mode": fields["mode"][0],
                "idle_timeout_s": int(fields["idle_timeout_s"][0]),
                "state": fields["state"][0],
            }
        )

    @mcp.tool(description="Install a breakpoint-backed write watch for a small memory range and aggregate hits by source instruction. Requires both pid and process_name for stale-PID recovery.")
    async def watch_memory_writes(
        pid: int,
        process_name: str,
        address: str,
        size: int,
        watch_id: str | None = None,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "watch_memory_writes",
            dll_path=dll_path,
            address=address,
            size=size,
            watch_id=watch_id,
        )
        return _structured_result(
            {
                "watch_id": fields["watch_id"][0],
                "address": fields["address"][0],
                "size": int(fields["size"][0]),
                "mode": fields["mode"][0],
                "idle_timeout_s": int(fields["idle_timeout_s"][0]),
                "state": fields["state"][0],
            }
        )

    @mcp.tool(description="Poll aggregated source hits for a breakpoint-backed access watch. If the watch idled for more than 60 seconds, the native layer detaches it and returns the retained snapshot once. Requires both pid and process_name for stale-PID recovery.")
    async def poll_access_watch_results(
        pid: int,
        process_name: str,
        watch_id: str,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "poll_access_watch_results",
            dll_path=dll_path,
            watch_id=watch_id,
        )
        sources = []
        for source in _split_records(fields.get("source", []), 6):
            if len(source) != 6:
                continue
            instruction_address, instruction_bytes, instruction, hit_count, last_thread_id, last_access_address = source
            sources.append(
                {
                    "instruction_address": instruction_address,
                    "instruction_bytes": instruction_bytes,
                    "instruction": instruction,
                    "hit_count": int(hit_count),
                    "last_thread_id": int(last_thread_id),
                    "last_access_address": last_access_address,
                }
            )
        return _structured_result(
            {
                "watch_id": fields["watch_id"][0],
                "mode": fields["mode"][0],
                "address": fields["address"][0],
                "size": int(fields["size"][0]),
                "state": fields["state"][0],
                "timed_out": fields["timed_out"][0].lower() == "true",
                "total_hit_count": int(fields["total_hit_count"][0]),
                "source_count": int(fields["source_count"][0]),
                "sources": sources,
            }
        )

    @mcp.tool(description="Detach a breakpoint-backed access watch or clear its retained timeout snapshot by watch identifier. Requires both pid and process_name for stale-PID recovery.")
    async def unwatch_access_watch(
        pid: int,
        process_name: str,
        watch_id: str,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
            process_name,
            "unwatch_access_watch",
            dll_path=dll_path,
            watch_id=watch_id,
        )
        return _structured_result(
            {
                "watch_id": fields["watch_id"][0],
                "removed": fields["removed"][0].lower() == "true",
            }
        )

    @mcp.tool(description="Disassemble a byte range from the target process into lightweight native instruction records. Requires both pid and process_name for stale-PID recovery.")
    async def disassemble(
        pid: int,
        process_name: str,
        address: str,
        size: int = 64,
        max_instructions: int = 16,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        read_fields = await request(pid, process_name, "read_memory", dll_path=dll_path, address=address, size=size)
        instructions = _capstone_disassemble(address, read_fields["bytes"][0], max_instructions)
        if instructions is None:
            fields = await request(
                pid,
                process_name,
                "disassemble",
                dll_path=dll_path,
                address=address,
                size=size,
                max_instructions=max_instructions,
            )
            instructions = []
            for instruction in _split_records(fields.get("instruction", []), 4):
                if len(instruction) != 4:
                    continue
                instr_address, bytes_hex, mnemonic, operands = instruction
                instructions.append(
                    {
                        "address": instr_address,
                        "bytes": bytes_hex,
                        "mnemonic": mnemonic,
                        "operands": operands,
                    }
                )
        return _structured_result(
            {
                "instruction_count": len(instructions),
                "instructions": instructions,
                "engine": "capstone" if Cs is not None else "native_fallback",
            }
        )

    @mcp.tool(description="Invoke an in-process function by raw address or loaded module export and return the result plus any output buffers. Requires both pid and process_name for stale-PID recovery.")
    async def invoke_function(
        pid: int,
        process_name: str,
        address: str | None = None,
        module: str | None = None,
        export: str | None = None,
        args: list[dict[str, Any]] | None = None,
        return_kind: str = "u64",
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        if address is None and (module is None or export is None):
            raise ValueError("provide either address or module plus export")
        native_fields = _prepare_invoke_fields(args)
        native_fields["return_kind"] = _normalize_invoke_return_kind(return_kind)
        if address is not None:
            native_fields["address"] = address
        else:
            native_fields["module"] = module
            native_fields["export"] = export
        fields = await request(pid, process_name, "invoke_function", dll_path=dll_path, **native_fields)
        response_return_kind = _normalize_invoke_return_kind(fields.get("return_kind", [return_kind])[0])
        return_bits = int(fields.get("return_bits", fields["return_value"])[0])
        return _structured_result(
            {
                "resolved_address": fields["resolved_address"][0],
                "return_kind": response_return_kind,
                "return_bits": return_bits,
                "return_value": _decode_invoke_return(response_return_kind, return_bits),
                "last_error": int(fields["last_error"][0]),
                "outputs": _parse_invoke_outputs(fields),
            }
        )

    @mcp.tool(description="Capture the current thread register snapshot exposed by the debugger for the target process. Requires both pid and process_name for stale-PID recovery.")
    async def registers(pid: int, process_name: str, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, process_name, "registers", dll_path=dll_path)
        registers_data: dict[str, str] = {}
        for item in fields.get("register", []):
            name, value = item.split("|", 1)
            registers_data[name] = value
        return _structured_result({"mode": fields["mode"][0], "registers": registers_data})

    return mcp
