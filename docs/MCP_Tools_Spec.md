# MCP Tool Spec

The Python MCP server maps MCP tools to the native pipe commands below.

If a PID-based tool targets a process whose debugger pipe is not yet reachable, the server first runs `Injector.exe` against that PID and waits for the pipe to come online before sending the native request.

## Tools

- `find_process_pid(process_name, exact_match=True)`
- `get_injection_setup()`
- `ping(pid, dll_path=None)`
- `read_memory(pid, address, size, dll_path=None)`
- `dereference(pid, address, depth=3, pointer_size=8, dll_path=None)`
- `list_modules(pid, dll_path=None)`
- `pattern_scan(pid, pattern, start_address=None, region_size=None, limit=32, dll_path=None)`
- `watch_address(pid, address, size, interval_ms=250, watch_id=None, dll_path=None)`
- `unwatch_address(pid, watch_id, dll_path=None)`
- `poll_watch_events(pid, limit=16, dll_path=None)`
- `disassemble(pid, address, size=64, max_instructions=16, dll_path=None)`
- `registers(pid, dll_path=None)`

## Notes

- Addresses are provided as hex strings.
- Memory bytes are returned as space-separated hex.
- Pattern strings accept wildcard bytes as `??`.
- `dll_path` is optional and lets the caller override the default debugger DLL for that request.
- `registers` currently captures the server thread context inside the injected process and is intentionally limited.
- Watch notifications are exposed as a polling tool in the first implementation batch; MCP push notifications can be added later.
