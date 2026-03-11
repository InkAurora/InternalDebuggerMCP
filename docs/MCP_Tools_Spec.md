# MCP Tool Spec

The Python MCP server maps MCP tools to the native pipe commands below.

If an auto-injecting tool targets a process whose debugger pipe is not yet reachable, the server first tries the supplied PID. If that PID can no longer be attached cleanly, the server falls back to an exact `process_name` lookup, resolves the current PID for that process, and retries the attach flow against the resolved PID.

## Tools

- `find_process_pid(process_name, exact_match=True)`
- `get_injection_setup()`
- `ping(pid, process_name, dll_path=None)`
- `eject_debugger(pid, dll_path=None)`
- `read_memory(pid, process_name, address, size, dll_path=None)`
- `write_memory(pid, process_name, address, bytes_hex=None, text=None, encoding="utf-8", zero_terminate=False, verify=True, dll_path=None)`
- `dereference(pid, process_name, address, depth=3, pointer_size=8, dll_path=None)`
- `list_modules(pid, process_name, dll_path=None)`
- `pattern_scan(pid, process_name, pattern, start_address=None, region_size=None, limit=32, dll_path=None)`
- `create_aob_pattern(pid, process_name, address, max_bytes=64, include_mask=False, include_offset=False, dll_path=None)`
- `watch_address(pid, process_name, address, size, interval_ms=250, watch_id=None, dll_path=None)`
- `unwatch_address(pid, process_name, watch_id, dll_path=None)`
- `poll_watch_events(pid, process_name, limit=16, dll_path=None)`
- `watch_memory_reads(pid, process_name, address, size, watch_id=None, dll_path=None)`
- `watch_memory_writes(pid, process_name, address, size, watch_id=None, dll_path=None)`
- `poll_access_watch_results(pid, process_name, watch_id, dll_path=None)`
- `unwatch_access_watch(pid, process_name, watch_id, dll_path=None)`
- `disassemble(pid, process_name, address, size=64, max_instructions=16, dll_path=None)`
- `invoke_function(pid, process_name, address=None, module=None, export=None, args=None, dll_path=None)`
- `registers(pid, process_name, dll_path=None)`

## Notes

- Addresses are provided as hex strings.
- Memory bytes are returned as space-separated hex.
- Auto-injecting tools now require both `pid` and `process_name`. The pipe protocol remains PID-based; `process_name` is used only as an exact-match fallback when the supplied PID no longer attaches cleanly.
- Exact process-name fallback fails if zero or multiple matching processes are found.
- `write_memory` accepts either `bytes_hex` or `text`; text payloads are encoded as `ascii`, `utf-8`, or `utf-16-le` before the native write.
- Pattern strings accept wildcard bytes as `??`.
- `create_aob_pattern` generates the shortest unique process-wide pattern it can find for the requested readable address, returning an x64dbg-style AOB string.
- `create_aob_pattern` may start the pattern before the requested address. `pattern_start` identifies the scan anchor, and `target_offset` can be requested to point back to the original address.
- `create_aob_pattern` optionally returns a per-byte mask string alongside the AOB when `include_mask=True`.
- `create_aob_pattern` currently searches up to `128` bytes and defaults to `64` bytes when `max_bytes` is omitted.
- `dll_path` is optional and lets the caller override the default debugger DLL for that request.
- `eject_debugger` does not auto-inject. It clears any tracked MCP session state for the PID and best-effort ejects the debugger DLL, preferring the live pipe path and falling back to `Injector.exe --eject` when the pipe is stale or already gone.
- `list_modules` returns `enumeration_method="toolhelp_snapshot"` in addition to the module list.
- `watch_memory_reads` and `watch_memory_writes` are separate access-watch tools that aggregate hits by source instruction rather than returning a raw event stream.
- Access watches currently support at most 4 concurrent active watched addresses per process and only sizes `1`, `2`, `4`, or `8` bytes.
- Access watches use guarded pages in the injected process. The native exception record provides the accessed address plus the read or write access type used for tool-specific filtering.
- `poll_access_watch_results` returns cumulative source summaries for the specified watch id. Each source record includes the instruction address, instruction bytes, formatted instruction text, hit count, last thread id, and last accessed address.
- If a breakpoint-backed watch is not polled for more than 60 seconds, the native layer detaches it, keeps one retained snapshot in memory, and returns that retained snapshot on the next `poll_access_watch_results` call before clearing it.
- `disassemble` reads bytes through the native transport and prefers Capstone in the Python MCP layer, falling back to the native decoder only when Capstone is unavailable.
- `invoke_function` supports either a raw `address` or a loaded `module` plus `export`. The current implementation is Win64-only and supports up to 6 arguments.
- `invoke_function` argument objects support the kinds `u64`, `pointer`, `bytes`, `string`, `utf8`, `utf16`, `inout_buffer`, and `out_buffer`.
- `registers` currently captures the server thread context inside the injected process and is intentionally limited.
- Watch notifications are exposed as a polling tool in the first implementation batch; MCP push notifications can be added later.

## Native unload command

- The native pipe now supports `eject`, which schedules DLL unload from a dedicated worker thread and returns an `eject_status` field.
- The MCP server also performs best-effort eject cleanup for tracked PIDs when the stdio server shuts down.
