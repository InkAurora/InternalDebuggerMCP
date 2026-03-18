from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MCP_SRC = REPO_ROOT / "src" / "McpServer"
if str(MCP_SRC) not in sys.path:
    sys.path.insert(0, str(MCP_SRC))

from mcp_server.session_manager import SessionManager  # noqa: E402
from mcp_server.tools import _send_native_request  # noqa: E402


TARGET_PROCESS_NAME = "TestTarget.exe"


def _read_target_startup(process: subprocess.Popen[str]) -> dict[str, str]:
    symbols: dict[str, str] = {}
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                raise RuntimeError("TestTarget exited before reporting startup addresses")
            time.sleep(0.05)
            continue

        text = line.strip()
        if text == "READY":
            required = {"g_aob_code_anchor", "g_aob_data_anchor"}
            missing = required.difference(symbols)
            if missing:
                raise RuntimeError(f"Missing startup symbols: {', '.join(sorted(missing))}")
            return symbols

        if ": 0x" in text:
            label, value = text.split(": 0x", 1)
            symbols[label.strip()] = f"0x{value.strip()}"

    raise RuntimeError("Timed out waiting for TestTarget startup banner")


def _start_target_process() -> tuple[subprocess.Popen[str], dict[str, str]]:
    target_path = REPO_ROOT / "artifacts" / "Release" / "x64" / "TestTarget" / "TestTarget.exe"
    if not target_path.exists():
        raise RuntimeError(f"Missing build artifact: {target_path}")

    process = subprocess.Popen(
        [str(target_path)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    return process, _read_target_startup(process)


def _stop_target_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stdout is not None:
        process.stdout.close()


def _summarize(samples_ms: list[float]) -> dict[str, object]:
    return {
        "mean_ms": round(statistics.fmean(samples_ms), 3),
        "median_ms": round(statistics.median(samples_ms), 3),
        "min_ms": round(min(samples_ms), 3),
        "max_ms": round(max(samples_ms), 3),
        "samples_ms": [round(value, 3) for value in samples_ms],
    }


def _capture_signature_case(
    session_manager: SessionManager,
    pid: int,
    address: str,
    max_bytes: int,
    iterations: int,
    warmup: int,
) -> dict[str, object]:
    samples_ms: list[float] = []
    reference_fields: dict[str, object] | None = None

    for index in range(iterations + warmup):
        started = time.perf_counter()
        fields = _send_native_request(
            session_manager,
            pid,
            "create_signature",
            process_name=TARGET_PROCESS_NAME,
            address=address,
            max_bytes=max_bytes,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        normalized: dict[str, object] = {
            "pattern": fields["pattern"][0],
            "module_name": fields["module_name"][0],
            "base_address": fields["base_address"][0],
            "image_size": int(fields["image_size"][0]),
            "byte_count": int(fields["byte_count"][0]),
            "wildcard_count": int(fields["wildcard_count"][0]),
            "match_count": int(fields["match_count"][0]),
        }
        if reference_fields is None:
            reference_fields = normalized
        elif normalized != reference_fields:
            raise RuntimeError(
                "create_signature returned different outputs across identical iterations: "
                f"expected {reference_fields}, got {normalized}"
            )

        if index >= warmup:
            samples_ms.append(elapsed_ms)

    assert reference_fields is not None
    return {
        **reference_fields,
        "iterations": iterations,
        "warmup": warmup,
        **_summarize(samples_ms),
    }


def _capture_aob_case(
    session_manager: SessionManager,
    pid: int,
    address: str,
    max_bytes: int,
    iterations: int,
    warmup: int,
) -> dict[str, object]:
    samples_ms: list[float] = []
    reference_fields: dict[str, object] | None = None

    for index in range(iterations + warmup):
        started = time.perf_counter()
        fields = _send_native_request(
            session_manager,
            pid,
            "create_aob_pattern",
            process_name=TARGET_PROCESS_NAME,
            address=address,
            max_bytes=max_bytes,
            include_mask=1,
            include_offset=1,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        normalized: dict[str, object] = {
            "pattern": fields["pattern"][0],
            "mask": fields["mask"][0],
            "pattern_start": fields["pattern_start"][0],
            "target_offset": int(fields["target_offset"][0]),
            "byte_count": int(fields["byte_count"][0]),
            "wildcard_count": int(fields["wildcard_count"][0]),
            "match_count": int(fields["match_count"][0]),
        }
        if reference_fields is None:
            reference_fields = normalized
        elif normalized != reference_fields:
            raise RuntimeError(
                "create_aob_pattern returned different outputs across identical iterations: "
                f"expected {reference_fields}, got {normalized}"
            )

        if index >= warmup:
            samples_ms.append(elapsed_ms)

    assert reference_fields is not None
    return {
        **reference_fields,
        "iterations": iterations,
        "warmup": warmup,
        **_summarize(samples_ms),
    }


def run_benchmark(mode: str, iterations: int, warmup: int, max_bytes_values: list[int]) -> dict[str, object]:
    process = None
    try:
        process, symbols = _start_target_process()
        session_manager = SessionManager()

        code_address = f"0x{int(symbols['g_aob_code_anchor'], 16) + 1:X}"
        data_address = f"0x{int(symbols['g_aob_data_anchor'], 16) + 4:X}"

        payload: dict[str, object] = {
            "pid": process.pid,
            "mode": mode,
            "preferred_tool": "create_signature",
            "legacy_tool": "create_aob_pattern",
            "cases": {
                "code": {},
                "data": {},
            },
        }
        for max_bytes in max_bytes_values:
            for label, address in (("code", code_address), ("data", data_address)):
                case_payload: dict[str, object] = {}
                if mode in {"signature", "compare"}:
                    case_payload["create_signature"] = _capture_signature_case(
                        session_manager,
                        process.pid,
                        address,
                        max_bytes,
                        iterations,
                        warmup,
                    )
                if mode in {"aob", "compare"}:
                    case_payload["create_aob_pattern"] = _capture_aob_case(
                        session_manager,
                        process.pid,
                        address,
                        max_bytes,
                        iterations,
                        warmup,
                    )
                if mode == "compare":
                    signature_mean = case_payload["create_signature"]["mean_ms"]
                    aob_mean = case_payload["create_aob_pattern"]["mean_ms"]
                    case_payload["comparison"] = {
                        "faster": "create_signature" if signature_mean < aob_mean else "create_aob_pattern",
                        "mean_delta_ms": round(aob_mean - signature_mean, 3),
                        "aob_over_signature_ratio": round(aob_mean / signature_mean, 3) if signature_mean else None,
                    }
                payload["cases"][label][str(max_bytes)] = case_payload

        return payload
    finally:
        _stop_target_process(process)


def build_parser(default_mode: str = "compare") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark signature generation with create_signature as the preferred path."
    )
    parser.add_argument(
        "--mode",
        choices=["signature", "aob", "compare"],
        default=default_mode,
        help="Select create_signature only, the deprecated create_aob_pattern only, or a side-by-side comparison",
    )
    parser.add_argument("--iterations", type=int, default=10, help="Calls per address/max_bytes case")
    parser.add_argument("--warmup", type=int, default=1, help="Unmeasured warmup calls per address/max_bytes case")
    parser.add_argument(
        "--max-bytes",
        type=int,
        nargs="+",
        default=[64, 128],
        help="One or more max_bytes values to benchmark",
    )
    return parser


def main(argv: list[str] | None = None, *, default_mode: str = "compare") -> int:
    parser = build_parser(default_mode=default_mode)
    args = parser.parse_args(argv)
    print(json.dumps(run_benchmark(args.mode, args.iterations, args.warmup, args.max_bytes), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())