# Python MCP Server

This package exposes the injected debugger over MCP using the official Python MCP SDK.

The server now injects the debugger DLL automatically the first time an auto-injecting tool targets a process whose named pipe is not already reachable at `\\.\pipe\InternalDebuggerMCP_<pid>`.

Auto-injecting tools now require both `pid` and `process_name`. The server still targets PID-based named pipes internally, but if the supplied PID can no longer be attached cleanly it falls back to an exact `process_name` lookup and retries against the resolved PID.

The server also exposes `find_process_pid`, which queries Windows for already running processes and returns matching PIDs before you call the auto-injecting debugger tools.

The server exposes `get_injection_setup`, which returns the injector path, DLL path, manual fallback command templates, and MCP launcher path for the current runtime layout. When the server runs from the packaged release zip, these paths point into the extracted package instead of the repository.

Auto-injecting debugger tools accept an optional `dll_path` override. In the normal flow, provide both the current PID and the process name and let the server use its resolved default DLL path.

## Install

```powershell
python -m pip install -e .
```

## Run

```powershell
python -m mcp_server.server
```

You can also run the packaged launcher directly. The launcher adds `vendor` to `sys.path`, so a packaged `mcp-server` folder works without a separate `pip install` step.

```powershell
python .\mcp-server\launch.py
```

## VS Code MCP Config Example

Use `mcp.json.example` as the template for an extracted package. Replace the path with the actual extraction location.

```json
{
  "servers": {
    "internalDebugger": {
      "type": "stdio",
      "command": "python",
      "args": ["C:/Path/To/InternalDebuggerMCP/mcp-server/launch.py"],
      "env": {
        "PYTHONUTF8": "1",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

## Test

Run integration tests from the repository root after building the native artifacts.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```
