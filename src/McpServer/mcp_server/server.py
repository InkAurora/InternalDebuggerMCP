from __future__ import annotations

from .session_manager import SessionManager
from .tools import create_mcp


def main() -> None:
    session_manager = SessionManager()
    server = create_mcp(session_manager)
    try:
        server.run()
    finally:
        session_manager.cleanup_all()


if __name__ == "__main__":
    main()
