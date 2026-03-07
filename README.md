# InternalDebuggerMCP

InternalDebuggerMCP is a Windows-first debugging bridge built around two components:

- an injected x64 C++ DLL that exposes in-process inspection capabilities over a named pipe;
- a Python MCP server that translates MCP tool calls into pipe requests.

The current implementation focuses on a safe read-oriented MVP:

- memory reads;
- pointer-chain dereferencing;
- committed-memory pattern scanning;
- module enumeration;
- polling-based address watching;
- lightweight native disassembly.

## Repository layout

- `src/DebuggerDLL`: injected DLL and native inspection services.
- `src/McpServer`: Python MCP server and pipe client.
- `tools/Injector`: helper utility that injects the DLL into a target process.
- `tools/TestTarget`: deterministic process used for integration testing.
- `docs`: architecture and tool contract notes.

## Build

The native components target Windows x64 and can now be built directly with Visual Studio Build Tools 2026 through MSBuild.

```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" ".\InternalDebuggerMCP.sln" /m "/p:Configuration=Release;Platform=x64"
```

The repository still includes CMake files if you prefer that route.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

The Python MCP server expects Python 3.10+.

The MCP server also exposes a local process lookup tool so you can resolve a PID before calling the PID-based debugger tools.

## Release Package

Build a distributable zip with the native binaries at the package root and a ready-to-launch MCP server under `mcp-server`.

```powershell
.\scripts\package_release.ps1
```

By default the script:

- builds `Release|x64` with MSBuild;
- stages a package under `dist\staging\InternalDebuggerMCP`;
- copies `Injector.exe` and `InternalDebuggerDLL.dll` to the package root;
- copies the MCP server into `mcp-server` and vendors its Python dependencies into `mcp-server\vendor`;
- creates `dist\InternalDebuggerMCP-<version>-win-x64.zip`.

Recommended package layout:

- `InternalDebuggerMCP\Injector.exe`
- `InternalDebuggerMCP\InternalDebuggerDLL.dll`
- `InternalDebuggerMCP\README.md`
- `InternalDebuggerMCP\QUICKSTART.txt`
- `InternalDebuggerMCP\package-manifest.json`
- `InternalDebuggerMCP\mcp-server\launch.py`
- `InternalDebuggerMCP\mcp-server\mcp_server\...`
- `InternalDebuggerMCP\mcp-server\vendor\...`
- `InternalDebuggerMCP\mcp-server\mcp.json.example`

The packaged MCP server is ready after extraction as long as the end user already has Python 3.10+ installed locally. No additional `pip install` step is required because the package vendors the server dependencies into `mcp-server\vendor`.

## Smoke Test

Use this workflow to verify that the native DLL, injector, and VS Code MCP server are working together.

1. Build the solution.

```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" ".\InternalDebuggerMCP.sln" /m "/p:Configuration=Release;Platform=x64"
```

2. Start the deterministic target process.

```powershell
.\artifacts\Release\x64\TestTarget\TestTarget.exe
```

Expected result:

- the console prints the PID;
- the console prints addresses for `g_counter`, `g_pattern`, `g_bytes`, `g_head`, and `SampleFunction`;
- `g_counter` changes every second.

3. Inject the debugger DLL into the target process using the printed PID.

```powershell
.\artifacts\Release\x64\Injector\Injector.exe <PID> C:\Users\INK\InternalDebuggerMCP\artifacts\Release\x64\InternalDebuggerDLL\InternalDebuggerDLL.dll
```

Expected result:

- the injector reports a non-zero `LoadLibraryW` thread exit code;
- the target process keeps running.

4. Ensure the workspace MCP server is running in VS Code.

Expected result:

- the `internalDebugger` server is listed under MCP servers in VS Code;
- the server starts without stderr spam for routine requests.

5. Verify core MCP tools from VS Code chat or the MCP tools surface.

Recommended checks:

- `find_process_pid("TestTarget.exe")` returns the live PID before any PID-based debugger call.
- `get_injection_setup()` returns the injector path, DLL path, PowerShell command template, and VS Code launcher path for the current layout.
- `ping(pid)` returns the target PID, the pipe name `\\.\pipe\InternalDebuggerMCP_<pid>`, and a watch count.
- `list_modules(pid)` includes `TestTarget.exe` and `InternalDebuggerDLL.dll`.
- `pattern_scan(pid, "49 4E 54 45 52 4E 41 4C 5F 44 45 42 55 47 47 45 52 5F 4D 43 50 5F 50 41 54 54 45 52 4E")` finds the known marker string.
- `read_memory(pid, <match_address>, 29)` returns the bytes for `INTERNAL_DEBUGGER_MCP_PATTERN`.
- `disassemble(pid, <g_bytes_or_function_address>, 6)` returns `push rbp`, `mov rbp, rsp`, `nop`, and `ret` for the test bytes.
- `watch_address(pid, <g_counter_address>, 4)` followed by `poll_watch_events(pid)` shows changes while the target runs.

6. Stop the target process when finished.

## Integration Test

Run the Windows burst-request regression test after building the solution.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```

## Notes

- Use the addresses printed by `TestTarget.exe` for each run; they change between launches.
- The injected DLL is x64-only in the current implementation.
- The native pipe server now accepts bursts of clients and serializes execution internally, which avoids the connection contention seen in the first implementation.

## Current status

This first implementation batch establishes the native protocol, pipe server, memory inspection primitives, watch manager, injector, and deterministic test target. The Python MCP surface is scaffolded separately and uses the same framed text protocol.
