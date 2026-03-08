# Architecture

## Components

1. `InternalDebuggerDLL.dll`
   - injected into the target process;
   - starts a worker thread outside `DllMain`;
   - hosts a named-pipe server at `\\.\pipe\InternalDebuggerMCP_<pid>`;
   - exposes bounded inspection and mutation commands.

2. Python MCP server
   - runs over stdio using the MCP Python SDK;
   - converts MCP tool invocations into pipe requests;
   - injects `InternalDebuggerDLL.dll` with `Injector.exe` on first PID-based use when the pipe is not already reachable;
   - maintains target PID session state;
   - best-effort ejects tracked debugger DLL instances on server shutdown.

3. Supporting tools
   - `Injector.exe` uses `CreateRemoteThread + LoadLibraryW`;
   - `Injector.exe --eject <pid> <dll-path-or-name>` invokes the DLL's exported unload entrypoint and waits for the module to disappear;
   - `TestTarget.exe` provides stable globals and changing values for validation.

## Native request format

Requests and responses are framed as UTF-8 text blocks ending in a blank line.

Example request:

```text
command=read_memory
address=0x7ff612340000
size=32

```

Example response:

```text
status=ok
address=0x7ff612340000
bytes=48 8B 05 00 00 00 00

```

Repeated fields are allowed and used for list-like data such as modules, instructions, or watch events.

## Implemented native commands

- `ping`
- `eject`
- `read_memory`
- `write_memory`
- `dereference`
- `list_modules`
- `pattern_scan`
- `watch_address`
- `unwatch_address`
- `poll_watch_events`
- `disassemble`
- `invoke_function`
- `registers`

## Safety boundaries

- reads and writes are bounded by maximum sizes;
- writes are limited to committed writable pages and do not auto-change page protections;
- dereference depth is limited;
- pattern scans only walk committed readable regions;
- function invocation is limited to the in-process x64 ABI and a bounded argument count;
- watch count is capped;
- explicit unload is scheduled from a dedicated worker thread so the DLL does not tear itself down from the pipe handler thread;
- address validation relies on `VirtualQuery` before dereference.
