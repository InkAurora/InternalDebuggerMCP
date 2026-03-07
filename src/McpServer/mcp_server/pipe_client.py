from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Iterable


INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
ERROR_PIPE_BUSY = 231

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
CreateFileW.restype = wintypes.HANDLE

WaitNamedPipeW = kernel32.WaitNamedPipeW
WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
WaitNamedPipeW.restype = wintypes.BOOL

ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
ReadFile.restype = wintypes.BOOL

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
WriteFile.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


def _raise_last_error(prefix: str) -> None:
    error = ctypes.get_last_error()
    raise OSError(error, f"{prefix}: {ctypes.FormatError(error).strip()}")


def _build_frame(fields: Iterable[tuple[str, str]]) -> bytes:
    text = "".join(f"{key}={value}\n" for key, value in fields) + "\n"
    return text.encode("utf-8")


def _parse_frame(frame: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for raw_line in frame.splitlines():
        if not raw_line or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        parsed.setdefault(key.strip(), []).append(value.strip())
    return parsed


class NativeRequestError(RuntimeError):
    def __init__(self, code: str, detail: str, response: "PipeResponse | None" = None) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.response = response


@dataclass(slots=True)
class PipeResponse:
    raw: str
    fields: dict[str, list[str]]

    @property
    def status(self) -> str:
        return self.fields.get("status", ["error"])[0]

    def one(self, key: str, default: str | None = None) -> str | None:
        values = self.fields.get(key)
        if not values:
            return default
        return values[0]

    def many(self, key: str) -> list[str]:
        return list(self.fields.get(key, []))

    def raise_for_error(self, default_detail: str = "native request failed") -> None:
        if self.status == "ok":
            return

        code = self.one("code", "unknown_error") or "unknown_error"
        detail = self.one("detail", default_detail) or default_detail
        raise NativeRequestError(code, detail, self)


class PipeClient:
    def __init__(self, pid: int, timeout_ms: int = 2000) -> None:
        self.pid = pid
        self.timeout_ms = timeout_ms
        self.pipe_name = rf"\\.\pipe\InternalDebuggerMCP_{pid}"

    def request(self, command: str, **fields: str | int) -> PipeResponse:
        deadline = time.monotonic() + (self.timeout_ms / 1000.0)
        handle = INVALID_HANDLE_VALUE
        while handle == INVALID_HANDLE_VALUE:
            remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
            if not WaitNamedPipeW(self.pipe_name, remaining_ms):
                _raise_last_error(f"WaitNamedPipe failed for {self.pipe_name}")

            handle = CreateFileW(
                self.pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if handle != INVALID_HANDLE_VALUE:
                break

            if ctypes.get_last_error() != ERROR_PIPE_BUSY or time.monotonic() >= deadline:
                _raise_last_error(f"CreateFile failed for {self.pipe_name}")

            time.sleep(0.05)

        try:
            frame = _build_frame(
                [("command", command), *[(key, str(value)) for key, value in fields.items() if value is not None]]
            )
            self._write_all(handle, frame)
            response_text = self._read_until_delimiter(handle)
        finally:
            CloseHandle(handle)

        return PipeResponse(raw=response_text, fields=_parse_frame(response_text))

    def _write_all(self, handle: wintypes.HANDLE, data: bytes) -> None:
        buffer = ctypes.create_string_buffer(data)
        written = wintypes.DWORD(0)
        if not WriteFile(handle, buffer, len(data), ctypes.byref(written), None):
            _raise_last_error("WriteFile failed")

    def _read_until_delimiter(self, handle: wintypes.HANDLE) -> str:
        chunks: list[bytes] = []
        delimiter = b"\n\n"
        while True:
            buffer = ctypes.create_string_buffer(2048)
            read = wintypes.DWORD(0)
            if not ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
                _raise_last_error("ReadFile failed")
            if read.value == 0:
                break
            chunks.append(buffer.raw[: read.value])
            if delimiter in chunks[-1] or delimiter in b"".join(chunks):
                break

        return b"".join(chunks).decode("utf-8", errors="replace")
