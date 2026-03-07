from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

from .pipe_client import PipeClient


@dataclass(slots=True)
class DebuggerSession:
    pid: int
    client: PipeClient


@dataclass(slots=True)
class SessionManager:
    _sessions: dict[int, DebuggerSession] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def get(self, pid: int) -> DebuggerSession:
        with self._lock:
            session = self._sessions.get(pid)
            if session is None:
                session = DebuggerSession(pid=pid, client=PipeClient(pid))
                self._sessions[pid] = session
            return session

    def reset(self, pid: int) -> None:
        with self._lock:
            self._sessions.pop(pid, None)
