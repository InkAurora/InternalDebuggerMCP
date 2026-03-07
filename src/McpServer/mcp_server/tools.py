from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from .session_manager import SessionManager


def _split_records(records: list[str], expected_parts: int) -> list[list[str]]:
    parsed: list[list[str]] = []
    for record in records:
        parts = record.split("|", expected_parts - 1)
        parsed.append(parts)
    return parsed


def create_mcp(session_manager: SessionManager) -> FastMCP:
    mcp = FastMCP("InternalDebuggerMCP")

    async def request(pid: int, command: str, **fields: Any) -> dict[str, list[str]]:
        response = await asyncio.to_thread(session_manager.get(pid).client.request, command, **fields)
        if response.status != "ok":
            code = response.one("code", "unknown_error")
            detail = response.one("detail", "native request failed")
            raise RuntimeError(f"{code}: {detail}")
        return response.fields

    @mcp.tool()
    async def ping(pid: int) -> dict[str, Any]:
        fields = await request(pid, "ping")
        return {
            "pid": int(fields["pid"][0]),
            "pipe_name": fields["pipe_name"][0],
            "watch_count": int(fields["watch_count"][0]),
        }

    @mcp.tool()
    async def read_memory(pid: int, address: str, size: int) -> dict[str, Any]:
        fields = await request(pid, "read_memory", address=address, size=size)
        return {
            "address": fields["address"][0],
            "size": int(fields["size"][0]),
            "bytes": fields["bytes"][0],
        }

    @mcp.tool()
    async def dereference(pid: int, address: str, depth: int = 3, pointer_size: int = 8) -> dict[str, Any]:
        fields = await request(
            pid,
            "dereference",
            address=address,
            depth=depth,
            pointer_size=pointer_size,
        )
        steps = []
        for step in fields.get("step", []):
            current, value, status = step.split("|", 2)
            steps.append({"address": current, "value": value, "status": status})
        return {"start_address": fields["start_address"][0], "steps": steps}

    @mcp.tool()
    async def list_modules(pid: int) -> dict[str, Any]:
        fields = await request(pid, "list_modules")
        modules = []
        for module in _split_records(fields.get("module", []), 4):
            if len(module) != 4:
                continue
            name, base, size, path = module
            modules.append({"name": name, "base": base, "size": int(size), "path": path})
        return {"module_count": int(fields["module_count"][0]), "modules": modules}

    @mcp.tool()
    async def pattern_scan(
        pid: int,
        pattern: str,
        start_address: str | None = None,
        region_size: int | None = None,
        limit: int = 32,
    ) -> dict[str, Any]:
        native_fields: dict[str, Any] = {"pattern": pattern, "limit": limit}
        if start_address is not None:
            native_fields["start"] = start_address
        if region_size is not None:
            native_fields["size"] = region_size
        fields = await request(pid, "pattern_scan", **native_fields)
        return {
            "match_count": int(fields["match_count"][0]),
            "matches": fields.get("match", []),
        }

    @mcp.tool()
    async def watch_address(
        pid: int,
        address: str,
        size: int,
        interval_ms: int = 250,
        watch_id: str | None = None,
    ) -> dict[str, Any]:
        fields = await request(
            pid,
            "watch_address",
            address=address,
            size=size,
            interval_ms=interval_ms,
            watch_id=watch_id,
        )
        return {
            "watch_id": fields["watch_id"][0],
            "address": fields["address"][0],
            "size": int(fields["size"][0]),
        }

    @mcp.tool()
    async def unwatch_address(pid: int, watch_id: str) -> dict[str, Any]:
        fields = await request(pid, "unwatch_address", watch_id=watch_id)
        return {"watch_id": fields["watch_id"][0], "removed": True}

    @mcp.tool()
    async def poll_watch_events(pid: int, limit: int = 16) -> dict[str, Any]:
        fields = await request(pid, "poll_watch_events", limit=limit)
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
        return {"event_count": int(fields["event_count"][0]), "events": events}

    @mcp.tool()
    async def disassemble(
        pid: int,
        address: str,
        size: int = 64,
        max_instructions: int = 16,
    ) -> dict[str, Any]:
        fields = await request(
            pid,
            "disassemble",
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
        return {
            "instruction_count": int(fields["instruction_count"][0]),
            "instructions": instructions,
        }

    @mcp.tool()
    async def registers(pid: int) -> dict[str, Any]:
        fields = await request(pid, "registers")
        registers_data: dict[str, str] = {}
        for item in fields.get("register", []):
            name, value = item.split("|", 1)
            registers_data[name] = value
        return {"mode": fields["mode"][0], "registers": registers_data}

    return mcp
