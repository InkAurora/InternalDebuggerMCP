from __future__ import annotations

import pathlib
import sys


def main() -> None:
    server_root = pathlib.Path(__file__).resolve().parent
    vendor_root = server_root / "vendor"

    if vendor_root.exists() and str(vendor_root) not in sys.path:
        sys.path.insert(0, str(vendor_root))

    if str(server_root) not in sys.path:
        sys.path.insert(0, str(server_root))

    from mcp_server.server import main as run_server

    run_server()


if __name__ == "__main__":
    main()
