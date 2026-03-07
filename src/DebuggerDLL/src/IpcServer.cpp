#include "IpcServer.h"

#include <Windows.h>

#include <array>
#include <string>

namespace idmcp {

namespace {

[[nodiscard]] HANDLE AsHandle(void* value) {
    return static_cast<HANDLE>(value);
}

}  // namespace

IpcServer::IpcServer(std::string pipeName, RequestHandler handler)
    : pipeName_(std::move(pipeName)), handler_(std::move(handler)) {}

IpcServer::~IpcServer() {
    Stop();
}

void IpcServer::Start() {
    if (running_.exchange(true)) {
        return;
    }
    worker_ = std::thread(&IpcServer::Run, this);
}

void IpcServer::Stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (const HANDLE wakeHandle = CreateFileA(pipeName_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        wakeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(wakeHandle);
    }

    if (worker_.joinable()) {
        worker_.join();
    }
}

void IpcServer::Run() {
    while (running_.load()) {
        const HANDLE pipe = CreateNamedPipeA(
            pipeName_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            64 * 1024,
            64 * 1024,
            1000,
            nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }

        const BOOL connected = ConnectNamedPipe(pipe, nullptr)
            ? TRUE
            : (GetLastError() == ERROR_PIPE_CONNECTED ? TRUE : FALSE);
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }

        const bool served = ServeClient(pipe);
        (void)served;
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

bool IpcServer::ServeClient(void* pipeHandle) const {
    const auto request = ReadFrame(pipeHandle);
    if (request.empty()) {
        return false;
    }

    const auto response = handler_(request);
    return WriteFrame(pipeHandle, response);
}

std::string IpcServer::ReadFrame(void* pipeHandle) const {
    std::array<char, 1024> buffer{};
    std::string data;

    while (running_.load()) {
        DWORD bytesRead = 0;
        const BOOL result = ReadFile(AsHandle(pipeHandle), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
        if (!result || bytesRead == 0) {
            break;
        }

        data.append(buffer.data(), buffer.data() + bytesRead);
        if (data.find("\n\n") != std::string::npos) {
            break;
        }
    }
    return data;
}

bool IpcServer::WriteFrame(void* pipeHandle, const std::string& frame) const {
    DWORD bytesWritten = 0;
    return WriteFile(
        AsHandle(pipeHandle),
        frame.data(),
        static_cast<DWORD>(frame.size()),
        &bytesWritten,
        nullptr) == TRUE;
}

}  // namespace idmcp
