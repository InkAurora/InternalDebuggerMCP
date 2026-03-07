from __future__ import annotations

from .session_manager import SessionManager
from .tools import create_mcp


def main() -> None:
    session_manager = SessionManager()
    server = create_mcp(session_manager)
    server.run()


if __name__ == "__main__":
    main()
