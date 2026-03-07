from __future__ import annotations

import pathlib
import sys


def main() -> None:
    project_root = pathlib.Path(__file__).resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from mcp_server.server import main as run_server

    run_server()


if __name__ == "__main__":
    main()
