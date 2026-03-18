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
- `get_module_base(pid, process_name, module, dll_path=None)`
- `rebase_address(pid, process_name, module, direction, offset=None, address=None, dll_path=None)`
- `pattern_scan(pid, process_name, pattern, mask=None, target_offset=None, start_address=None, region_size=None, limit=32, dll_path=None)`
- `create_aob_pattern(pid, process_name, address, max_bytes=64, include_mask=False, include_offset=False, dll_path=None)`
- `create_signature(pid, process_name, address, max_bytes=64, dll_path=None)`
- `watch_address(pid, process_name, address, size, interval_ms=250, watch_id=None, dll_path=None)`
- `unwatch_address(pid, process_name, watch_id, dll_path=None)`
- `poll_watch_events(pid, process_name, limit=16, dll_path=None)`
- `watch_memory_reads(pid, process_name, address, size, watch_id=None, dll_path=None)`
- `watch_memory_writes(pid, process_name, address, size, watch_id=None, dll_path=None)`
- `poll_access_watch_results(pid, process_name, watch_id, dll_path=None)`
- `unwatch_access_watch(pid, process_name, watch_id, dll_path=None)`
- `disassemble(pid, process_name, address, size=64, max_instructions=16, dll_path=None)`
- `invoke_function(pid, process_name, address=None, module=None, export=None, args=None, return_kind="u64", dll_path=None)`
- `registers(pid, process_name, dll_path=None)`

## Notes

- Addresses are provided as hex strings.
- Memory bytes are returned as space-separated hex.
- `read_memory`, `write_memory`, `memory_verify_failed`, `disassemble`, and unreadable-address `create_aob_pattern` failures may include extra native diagnostic fields such as `address`, `requested_size`, `requested_max_bytes`, `memory_reason`, `region_base`, `region_size`, `region_state`, `region_protect`, `win32_error_detail`, and `copy_exception_code`.
- Auto-injecting tools now require both `pid` and `process_name`. The pipe protocol remains PID-based; `process_name` is used only as an exact-match fallback when the supplied PID no longer attaches cleanly.
- Exact process-name fallback fails if zero or multiple matching processes are found.
- `write_memory` accepts either `bytes_hex` or `text`; text payloads are encoded as `ascii`, `utf-8`, or `utf-16-le` before the native write.
- `get_module_base` resolves one loaded module and returns `module_name`, `base_address`, `image_size`, `module_path`, and `match_method`.
- `get_module_base` and `rebase_address` match modules case-insensitively by module name, full path, or basename. Ambiguous matches fail instead of choosing an arbitrary module.
- `rebase_address` accepts `direction="rva_to_va"` or `direction="va_to_rva"`.
- `rebase_address(direction="rva_to_va", ...)` requires `offset` and returns the computed absolute `address` together with the normalized `offset`.
- `rebase_address(direction="va_to_rva", ...)` requires `address` and returns the computed module-relative `offset` together with the normalized `address`.
- Pattern strings accept wildcard bytes as `??`.
- `pattern_scan` also accepts an optional `mask` string of `x` and `?` characters. The mask length must match the pattern byte count after tokenization.
- `pattern_scan` may be called with both a wildcard AOB string and a `mask`, but the request is only valid if every `??` byte also maps to a `?` mask position.
- When `target_offset` is supplied to `pattern_scan`, the returned `matches` point at the adjusted target address and the raw pattern-start anchors are returned separately as `match_starts`.
- `create_aob_pattern` generates the shortest unique process-wide pattern it can find for the requested readable address, returning an x64dbg-style AOB string.
- `create_aob_pattern` may start the pattern before the requested address. `pattern_start` identifies the scan anchor, and `target_offset` can be requested to point back to the original address.
- `create_aob_pattern` optionally returns a per-byte mask string alongside the AOB when `include_mask=True`.
- `create_aob_pattern` currently searches up to `128` bytes and defaults to `64` bytes when `max_bytes` is omitted.
- `create_aob_pattern(..., include_mask=True, include_offset=True)` can be round-tripped directly into `pattern_scan` by passing the returned `pattern`, `mask`, and `target_offset` back to the scanner.
- `create_signature` generates a module-scoped unique signature that always begins at the requested address and returns inline `??` wildcards directly in the pattern text.
- `create_signature` also returns `base_address` and `image_size` for the containing module so callers can re-run `pattern_scan` inside the same scope.
- `create_signature` fails with `address_not_in_module` when the requested readable address is outside every loaded module, such as heap memory.
- `dll_path` is optional and lets the caller override the default debugger DLL for that request.
- `eject_debugger` does not auto-inject. It clears any tracked MCP session state for the PID and best-effort ejects the debugger DLL, preferring the live pipe path and falling back to `Injector.exe --eject` when the pipe is stale or already gone.
- `list_modules` returns `enumeration_method="toolhelp_snapshot"` in addition to the module list.
- `watch_memory_reads` and `watch_memory_writes` are separate access-watch tools that aggregate hits by source instruction rather than returning a raw event stream.
- Watch-arm failures now include the requested address and size in the native error payload, even when the underlying failure is a stable command-specific code like `unsupported_watch_alignment` or `watch_limit_exceeded`.
- Polling-watch and access-watch setup failures caused by unreadable or unwritable target memory may also include the same native memory diagnostic fields used by `read_memory` and `write_memory`.
- Access watches currently support at most 4 concurrent active watched addresses per process and only sizes `1`, `2`, `4`, or `8` bytes.
- Access reads use guarded pages in the injected process. The native exception record provides the accessed address plus the read access type used for filtering.
- Access writes use hardware breakpoints on the watched address across the target's threads and therefore avoid page-wide faulting overhead.
- `poll_access_watch_results` returns cumulative source summaries for the specified watch id. Each source record includes the instruction address, instruction bytes, formatted instruction text, hit count, last thread id, and last accessed address.
- If an access watch is not polled for more than 60 seconds, the native layer detaches it, keeps one retained snapshot in memory, and returns that retained snapshot on the next `poll_access_watch_results` call before clearing it.
- `disassemble` reads bytes through the native transport and prefers Capstone in the Python MCP layer, falling back to the native decoder only when Capstone is unavailable.
- `invoke_function` supports either a raw `address` or a loaded `module` plus `export`. The current implementation is Win64-only and supports up to 6 arguments.
- `invoke_function` argument objects support the kinds `u64`, `f32`, `f64`, `pointer`, `bytes`, `string`, `utf8`, `utf16`, `inout_buffer`, and `out_buffer`.
- `invoke_function` accepts `return_kind="u64" | "f32" | "f64"`. The native response always includes raw `return_bits`, and the MCP layer also exposes a decoded `return_value` using the requested return kind.
- `registers` currently captures the server thread context inside the injected process and is intentionally limited.
- Watch notifications are exposed as a polling tool in the first implementation batch; MCP push notifications can be added later.

## Native unload command

- The native pipe now supports `eject`, which schedules DLL unload from a dedicated worker thread and returns an `eject_status` field.
- The MCP server also performs best-effort eject cleanup for tracked PIDs when the stdio server shuts down.
