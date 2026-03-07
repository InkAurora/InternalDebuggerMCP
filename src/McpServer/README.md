# Python MCP Server

This package exposes the injected debugger over MCP using the official Python MCP SDK.

The current implementation assumes the DLL is already injected into the target process and reachable over the named pipe `\\.\pipe\InternalDebuggerMCP_<pid>`.

The server also exposes `find_process_pid`, which queries Windows for already running processes and returns matching PIDs before you call the PID-based debugger tools.

## Install

```powershell
python -m pip install -e .
```

## Run

```powershell
python -m mcp_server.server
```

## Test

Run integration tests from the repository root after building the native artifacts.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```
