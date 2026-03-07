# MCP Tool Spec

The Python MCP server maps MCP tools to the native pipe commands below.

## Tools

- `read_memory(pid, address, size)`
- `dereference(pid, address, depth=3, pointer_size=8)`
- `list_modules(pid)`
- `pattern_scan(pid, pattern, start_address=None, region_size=None, limit=32)`
- `watch_address(pid, address, size, interval_ms=250, watch_id=None)`
- `unwatch_address(pid, watch_id)`
- `poll_watch_events(pid, limit=16)`
- `disassemble(pid, address, size=64, max_instructions=16)`
- `registers(pid)`

## Notes

- Addresses are provided as hex strings.
- Memory bytes are returned as space-separated hex.
- Pattern strings accept wildcard bytes as `??`.
- `registers` currently captures the server thread context inside the injected process and is intentionally limited.
- Watch notifications are exposed as a polling tool in the first implementation batch; MCP push notifications can be added later.
