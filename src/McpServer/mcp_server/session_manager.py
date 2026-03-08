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
    _bootstrap_locks: dict[int, Lock] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def get(self, pid: int) -> DebuggerSession:
        with self._lock:
            session = self._sessions.get(pid)
            if session is None:
                session = DebuggerSession(pid=pid, client=PipeClient(pid))
                self._sessions[pid] = session
            return session

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
