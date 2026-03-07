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

## Current status

This first implementation batch establishes the native protocol, pipe server, memory inspection primitives, watch manager, injector, and deterministic test target. The Python MCP surface is scaffolded separately and uses the same framed text protocol.
