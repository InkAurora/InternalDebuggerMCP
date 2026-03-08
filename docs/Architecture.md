# Architecture

## Components

1. `InternalDebuggerDLL.dll`
   - injected into the target process;
   - starts a worker thread outside `DllMain`;
   - hosts a named-pipe server at `\\.\pipe\InternalDebuggerMCP_<pid>`;
   - exposes read-oriented debugging commands.

2. Python MCP server
   - runs over stdio using the MCP Python SDK;
   - converts MCP tool invocations into pipe requests;
   - injects `InternalDebuggerDLL.dll` with `Injector.exe` on first PID-based use when the pipe is not already reachable;
   - maintains target PID session state.

3. Supporting tools
   - `Injector.exe` uses `CreateRemoteThread + LoadLibraryW`;
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
- `read_memory`
- `dereference`
- `list_modules`
- `pattern_scan`
- `watch_address`
- `unwatch_address`
- `poll_watch_events`
- `disassemble`
- `registers`

## Safety boundaries

- reads are bounded by maximum sizes;
- dereference depth is limited;
- pattern scans only walk committed readable regions;
- watch count is capped;
- address validation relies on `VirtualQuery` before dereference.
