# MCP Tool Spec

The Python MCP server maps MCP tools to the native pipe commands below.

If a PID-based tool targets a process whose debugger pipe is not yet reachable, the server first runs `Injector.exe` against that PID and waits for the pipe to come online before sending the native request.

## Tools

- `find_process_pid(process_name, exact_match=True)`
- `get_injection_setup()`
- `ping(pid, dll_path=None)`
- `eject_debugger(pid, dll_path=None)`
- `read_memory(pid, address, size, dll_path=None)`
- `write_memory(pid, address, bytes_hex=None, text=None, encoding="utf-8", zero_terminate=False, verify=True, dll_path=None)`
- `dereference(pid, address, depth=3, pointer_size=8, dll_path=None)`
- `list_modules(pid, dll_path=None)`
- `pattern_scan(pid, pattern, start_address=None, region_size=None, limit=32, dll_path=None)`
- `watch_address(pid, address, size, interval_ms=250, watch_id=None, dll_path=None)`
- `unwatch_address(pid, watch_id, dll_path=None)`
- `poll_watch_events(pid, limit=16, dll_path=None)`
- `disassemble(pid, address, size=64, max_instructions=16, dll_path=None)`
- `invoke_function(pid, address=None, module=None, export=None, args=None, dll_path=None)`
- `registers(pid, dll_path=None)`

## Notes

- Addresses are provided as hex strings.
- Memory bytes are returned as space-separated hex.
- `write_memory` accepts either `bytes_hex` or `text`; text payloads are encoded as `ascii`, `utf-8`, or `utf-16-le` before the native write.
- Pattern strings accept wildcard bytes as `??`.
- `dll_path` is optional and lets the caller override the default debugger DLL for that request.
- `eject_debugger` does not auto-inject. It clears any tracked MCP session state for the PID and best-effort ejects the debugger DLL, preferring the live pipe path and falling back to `Injector.exe --eject` when the pipe is stale or already gone.
- `list_modules` returns `enumeration_method="toolhelp_snapshot"` in addition to the module list.
- `disassemble` reads bytes through the native transport and prefers Capstone in the Python MCP layer, falling back to the native decoder only when Capstone is unavailable.
- `invoke_function` supports either a raw `address` or a loaded `module` plus `export`. The current implementation is Win64-only and supports up to 6 arguments.
- `invoke_function` argument objects support the kinds `u64`, `pointer`, `bytes`, `string`, `utf8`, `utf16`, `inout_buffer`, and `out_buffer`.
- `registers` currently captures the server thread context inside the injected process and is intentionally limited.
- Watch notifications are exposed as a polling tool in the first implementation batch; MCP push notifications can be added later.

## Native unload command

- The native pipe now supports `eject`, which schedules DLL unload from a dedicated worker thread and returns an `eject_status` field.
- The MCP server also performs best-effort eject cleanup for tracked PIDs when the stdio server shuts down.
