from __future__ import annotations

import sys

from benchmark_signatures import main


if __name__ == "__main__":
    print(
        "benchmark_aob_pattern.py is deprecated; use scripts/benchmark_signatures.py instead.",
        file=sys.stderr,
    )
    raise SystemExit(main(default_mode="aob"))