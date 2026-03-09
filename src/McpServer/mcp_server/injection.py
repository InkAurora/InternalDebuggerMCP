from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .package_layout import resolve_runtime_layout
from .pipe_client import NativeRequestError, PipeClient


@dataclass(frozen=True, slots=True)
class InjectionPaths:
    injector_path: Path
    dll_path: Path


@dataclass(frozen=True, slots=True)
class InjectionResult:
    pid: int
    pipe_name: str
    injector_path: str
    dll_path: str
    injected: bool


@dataclass(frozen=True, slots=True)
class EjectionResult:
    pid: int
    dll_path: str
    method: str
    status: str
    detail: str


class InjectionError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def normalize_dll_path_override(dll_path: str | Path | None) -> str | Path | None:
    if isinstance(dll_path, str) and not dll_path.strip():
        return None
    return dll_path


def resolve_injection_paths(dll_path: str | Path | None = None, *, require_dll_exists: bool = True) -> InjectionPaths:
    layout = resolve_runtime_layout()
    injector_path = layout.injector_path.resolve()
    normalized_dll_path = normalize_dll_path_override(dll_path)
    resolved_dll_path = (
        Path(normalized_dll_path).expanduser().resolve() if normalized_dll_path is not None else layout.dll_path.resolve()
    )

    if not injector_path.exists():
        raise InjectionError("missing_injector", f"Injector executable not found: {injector_path}")
    if require_dll_exists and not resolved_dll_path.exists():
        raise InjectionError("missing_dll", f"Debugger DLL not found: {resolved_dll_path}")

    return InjectionPaths(injector_path=injector_path, dll_path=resolved_dll_path)


def wait_for_debugger_pipe(pid: int, timeout_ms: int) -> bool:
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    while time.monotonic() < deadline:
        remaining_ms = max(100, min(250, int((deadline - time.monotonic()) * 1000)))
        try:
            response = PipeClient(pid, timeout_ms=remaining_ms).request("ping")
            if response.status == "ok":
                return True
            if response.one("code") in {"server_busy", "server_stopping"}:
                return True
            return True
        except (NativeRequestError, OSError):
            time.sleep(0.1)
    return False


def inject_debugger(
    pid: int,
    dll_path: str | Path | None = None,
    *,
    startup_grace_ms: int = 750,
    pipe_timeout_ms: int = 10000,
    injector_timeout_s: int = 15,
) -> InjectionResult:
    pipe_name = rf"\\.\pipe\InternalDebuggerMCP_{pid}"
    if wait_for_debugger_pipe(pid, timeout_ms=startup_grace_ms):
        paths = resolve_injection_paths(dll_path)
        return InjectionResult(
            pid=pid,
            pipe_name=pipe_name,
            injector_path=str(paths.injector_path),
            dll_path=str(paths.dll_path),
            injected=False,
        )

    paths = resolve_injection_paths(dll_path)
    completed = subprocess.run(
        [str(paths.injector_path), str(pid), str(paths.dll_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=injector_timeout_s,
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"Injector.exe exited with code {completed.returncode}"
        raise InjectionError("injector_failed", detail)

    if not wait_for_debugger_pipe(pid, timeout_ms=pipe_timeout_ms):
        raise InjectionError(
            "pipe_timeout",
            f"Timed out waiting for debugger pipe after injection: {pipe_name}",
        )

    return InjectionResult(
        pid=pid,
        pipe_name=pipe_name,
        injector_path=str(paths.injector_path),
        dll_path=str(paths.dll_path),
        injected=True,
    )


def request_debugger_eject(pid: int, *, timeout_ms: int = 2000) -> str:
    response = PipeClient(pid, timeout_ms=timeout_ms).request("eject")
    response.raise_for_error(default_detail="native eject request failed")
    return response.one("eject_status", "scheduled") or "scheduled"


def force_eject_debugger(
    pid: int,
    dll_path: str | Path | None = None,
    *,
    injector_timeout_s: int = 15,
) -> EjectionResult:
    paths = resolve_injection_paths(dll_path, require_dll_exists=False)
    completed = subprocess.run(
        [str(paths.injector_path), "--eject", str(pid), str(paths.dll_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=injector_timeout_s,
    )

    detail = completed.stderr.strip() or completed.stdout.strip()
    if completed.returncode == 0:
        return EjectionResult(
            pid=pid,
            dll_path=str(paths.dll_path),
            method="injector",
            status="ejected",
            detail=detail or "Debugger DLL ejected",
        )
    if completed.returncode == 3:
        return EjectionResult(
            pid=pid,
            dll_path=str(paths.dll_path),
            method="injector",
            status="already_absent",
            detail=detail or "Debugger DLL was not loaded",
        )

    raise InjectionError(
        "ejector_failed",
        detail or f"Injector.exe --eject exited with code {completed.returncode}",
    )


def eject_debugger(
    pid: int,
    dll_path: str | Path | None = None,
    *,
    pipe_timeout_ms: int = 2000,
    injector_timeout_s: int = 15,
) -> EjectionResult:
    paths = resolve_injection_paths(dll_path, require_dll_exists=False)

    pipe_status: str | None = None
    try:
        pipe_status = request_debugger_eject(pid, timeout_ms=pipe_timeout_ms)
    except (NativeRequestError, OSError):
        pipe_status = None

    injector_result = force_eject_debugger(pid, dll_path=paths.dll_path, injector_timeout_s=injector_timeout_s)
    if pipe_status is not None and injector_result.status in {"ejected", "already_absent"}:
        return EjectionResult(
            pid=pid,
            dll_path=str(paths.dll_path),
            method="pipe",
            status="ejected",
            detail=pipe_status,
        )

    return injector_result