from __future__ import annotations

import asyncio
import csv
import subprocess
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult

from .injection import InjectionError, inject_debugger
from .package_layout import build_injection_setup
from .pipe_client import NativeRequestError
from .session_manager import SessionManager


StructuredToolResult = Annotated[CallToolResult, dict[str, Any]]


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


def _raise_runtime_for_native_error(session_manager: SessionManager, pid: int, error: NativeRequestError) -> None:
    if error.code == "server_busy":
        raise RuntimeError("server_busy: native request queue is full; retry the request") from error
    if error.code == "server_stopping":
        session_manager.reset(pid)
        raise RuntimeError(
            "server_stopping: the target debugger is restarting or shutting down; retry after the pipe recovers"
        ) from error
    raise RuntimeError(f"{error.code}: {error.detail}") from error


def _request_once(session_manager: SessionManager, pid: int, command: str, **fields: Any) -> dict[str, list[str]]:
    response = session_manager.get(pid).client.request(command, **fields)
    response.raise_for_error()
    return response.fields


def _send_native_request(
    session_manager: SessionManager,
    pid: int,
    command: str,
    *,
    dll_path: str | None = None,
    **fields: Any,
) -> dict[str, list[str]]:
    try:
        return _request_once(session_manager, pid, command, **fields)
    except NativeRequestError as error:
        _raise_runtime_for_native_error(session_manager, pid, error)
    except OSError:
        session_manager.reset(pid)

    with session_manager.bootstrap_lock(pid):
        try:
            return _request_once(session_manager, pid, command, **fields)
        except NativeRequestError as error:
            _raise_runtime_for_native_error(session_manager, pid, error)
        except OSError:
            try:
                inject_debugger(pid, dll_path=dll_path)
            except InjectionError as error:
                session_manager.reset(pid)
                raise RuntimeError(f"{error.code}: {error.detail}") from error

            try:
                return _request_once(session_manager, pid, command, **fields)
            except NativeRequestError as error:
                _raise_runtime_for_native_error(session_manager, pid, error)
            except OSError as error:
                session_manager.reset(pid)
                raise RuntimeError(f"transport_error: {error}") from error


def create_mcp(session_manager: SessionManager) -> FastMCP:
    mcp = FastMCP("InternalDebuggerMCP", log_level="WARNING")

    async def request(pid: int, command: str, *, dll_path: str | None = None, **fields: Any) -> dict[str, list[str]]:
        return await asyncio.to_thread(
            _send_native_request,
            session_manager,
            pid,
            command,
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

    @mcp.tool(description="Check whether the debugger pipe for a target PID is reachable and report basic server state.")
    async def ping(pid: int, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, "ping", dll_path=dll_path)
        return _structured_result(
            {
                "pid": int(fields["pid"][0]),
                "pipe_name": fields["pipe_name"][0],
                "watch_count": int(fields["watch_count"][0]),
            }
        )

    @mcp.tool(description="Read a raw byte range from the memory of the target process at the supplied address.")
    async def read_memory(pid: int, address: str, size: int, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, "read_memory", dll_path=dll_path, address=address, size=size)
        return _structured_result(
            {
                "address": fields["address"][0],
                "size": int(fields["size"][0]),
                "bytes": fields["bytes"][0],
            }
        )

    @mcp.tool(description="Follow a pointer chain in the target process and return each dereference step.")
    async def dereference(
        pid: int,
        address: str,
        depth: int = 3,
        pointer_size: int = 8,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
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

    @mcp.tool(description="Enumerate loaded modules in the target process with base addresses, image sizes, and paths.")
    async def list_modules(pid: int, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, "list_modules", dll_path=dll_path)
        modules = []
        for module in _split_records(fields.get("module", []), 4):
            if len(module) != 4:
                continue
            name, base, size, path = module
            modules.append({"name": name, "base": base, "size": int(size), "path": path})
        return _structured_result({"module_count": int(fields["module_count"][0]), "modules": modules})

    @mcp.tool(description="Scan readable committed memory in the target process for a byte pattern with optional wildcards.")
    async def pattern_scan(
        pid: int,
        pattern: str,
        start_address: str | None = None,
        region_size: int | None = None,
        limit: int = 32,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        native_fields: dict[str, Any] = {"pattern": pattern, "limit": limit}
        if start_address is not None:
            native_fields["start"] = start_address
        if region_size is not None:
            native_fields["size"] = region_size
        fields = await request(pid, "pattern_scan", dll_path=dll_path, **native_fields)
        return _structured_result(
            {
                "match_count": int(fields["match_count"][0]),
                "matches": fields.get("match", []),
            }
        )

    @mcp.tool(description="Start polling a target address for changes and create a watch that can be queried for change events.")
    async def watch_address(
        pid: int,
        address: str,
        size: int,
        interval_ms: int = 250,
        watch_id: str | None = None,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
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

    @mcp.tool(description="Remove an existing memory watch from the target process by watch identifier.")
    async def unwatch_address(pid: int, watch_id: str, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, "unwatch_address", dll_path=dll_path, watch_id=watch_id)
        return _structured_result({"watch_id": fields["watch_id"][0], "removed": True})

    @mcp.tool(description="Fetch pending change events for active memory watches in the target process.")
    async def poll_watch_events(pid: int, limit: int = 16, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, "poll_watch_events", dll_path=dll_path, limit=limit)
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

    @mcp.tool(description="Disassemble a byte range from the target process into lightweight native instruction records.")
    async def disassemble(
        pid: int,
        address: str,
        size: int = 64,
        max_instructions: int = 16,
        dll_path: str | None = None,
    ) -> StructuredToolResult:
        fields = await request(
            pid,
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
                "instruction_count": int(fields["instruction_count"][0]),
                "instructions": instructions,
            }
        )

    @mcp.tool(description="Capture the current thread register snapshot exposed by the debugger for the target process.")
    async def registers(pid: int, dll_path: str | None = None) -> StructuredToolResult:
        fields = await request(pid, "registers", dll_path=dll_path)
        registers_data: dict[str, str] = {}
        for item in fields.get("register", []):
            name, value = item.split("|", 1)
            registers_data[name] = value
        return _structured_result({"mode": fields["mode"][0], "registers": registers_data})

    return mcp
