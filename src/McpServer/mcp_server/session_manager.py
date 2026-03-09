from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from .injection import EjectionResult, eject_debugger, normalize_dll_path_override
from .pipe_client import PipeClient


@dataclass(slots=True)
class DebuggerSession:
    pid: int
    client: PipeClient
    dll_path: str | None = None
    process_name: str | None = None


@dataclass(slots=True)
class SessionManager:
    _sessions: dict[int, DebuggerSession] = field(default_factory=dict)
    _bootstrap_locks: dict[int, Lock] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def _get_or_create_session_locked(self, pid: int) -> DebuggerSession:
        session = self._sessions.get(pid)
        if session is None:
            session = DebuggerSession(pid=pid, client=PipeClient(pid))
            self._sessions[pid] = session
        return session

    def get(self, pid: int) -> DebuggerSession:
        with self._lock:
            return self._get_or_create_session_locked(pid)

    def bootstrap_lock(self, pid: int) -> Lock:
        with self._lock:
            pid_lock = self._bootstrap_locks.get(pid)
            if pid_lock is None:
                pid_lock = Lock()
                self._bootstrap_locks[pid] = pid_lock
            return pid_lock

    def reset(self, pid: int) -> None:
        with self._lock:
            self._sessions.pop(pid, None)

    def has_session(self, pid: int) -> bool:
        with self._lock:
            return pid in self._sessions

    def remember_target(
        self,
        pid: int,
        *,
        dll_path: str | Path | None = None,
        process_name: str | None = None,
    ) -> None:
        normalized_dll_path = normalize_dll_path_override(dll_path)
        resolved_dll_path = str(Path(normalized_dll_path).expanduser().resolve()) if normalized_dll_path is not None else None
        with self._lock:
            session = self._get_or_create_session_locked(pid)
            if resolved_dll_path is not None:
                session.dll_path = resolved_dll_path
            if process_name is not None:
                session.process_name = process_name

    def remember_dll_path(self, pid: int, dll_path: str | Path | None) -> None:
        self.remember_target(pid, dll_path=dll_path)

    def cleanup_pid(self, pid: int, dll_path: str | Path | None = None) -> EjectionResult:
        with self._lock:
            session = self._sessions.get(pid)
            normalized_dll_path = normalize_dll_path_override(dll_path)
            effective_dll_path = (
                str(Path(normalized_dll_path).expanduser().resolve())
                if normalized_dll_path is not None
                else session.dll_path if session else None
            )

        try:
            return eject_debugger(pid, dll_path=effective_dll_path)
        finally:
            self.reset(pid)

    def cleanup_all(self) -> list[EjectionResult]:
        with self._lock:
            pending = [(session.pid, session.dll_path) for session in self._sessions.values()]
            self._sessions.clear()

        results: list[EjectionResult] = []
        for pid, dll_path in pending:
            try:
                results.append(eject_debugger(pid, dll_path=dll_path))
            except Exception:
                continue
        return results
