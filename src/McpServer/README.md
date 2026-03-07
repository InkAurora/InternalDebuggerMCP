# Python MCP Server

This package exposes the injected debugger over MCP using the official Python MCP SDK.

The current implementation assumes the DLL is already injected into the target process and reachable over the named pipe `\\.\pipe\InternalDebuggerMCP_<pid>`.

## Install

```powershell
python -m pip install -e .
```

## Run

```powershell
python -m mcp_server.server
```
