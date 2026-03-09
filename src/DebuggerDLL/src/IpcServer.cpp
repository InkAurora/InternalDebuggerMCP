#include "IpcServer.h"

#include <Windows.h>

#include <array>
#include <future>
#include <string>

#include "DebuggerProtocol.h"

namespace idmcp {

namespace {

inline constexpr DWORD kPipeInstanceCount = 8;
inline constexpr std::size_t kMaxQueuedRequests = 64;

[[nodiscard]] HANDLE AsHandle(void* value) {
    return static_cast<HANDLE>(value);
}

[[nodiscard]] std::string MakePipeError(const std::string& code, const std::string& detail) {
    return BuildMessage({
        {"status", "error"},
        {"code", code},
        {"detail", detail},
    });
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
    workerThread_ = std::thread(&IpcServer::ProcessQueue, this);
    acceptThread_ = std::thread(&IpcServer::Run, this);
}

void IpcServer::Stop() {
    if (!running_.exchange(false)) {
        return;
    }

    queueReady_.notify_all();

    if (const HANDLE wakeHandle = CreateFileA(pipeName_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        wakeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(wakeHandle);
    }

    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }

    FailPendingRequests();
    queueReady_.notify_all();

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    for (auto& clientThread : clientThreads_) {
        if (clientThread.joinable()) {
            clientThread.join();
        }
    }
    clientThreads_.clear();
}

void IpcServer::Run() {
    while (running_.load()) {
        const HANDLE pipe = CreateNamedPipeA(
            pipeName_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            kPipeInstanceCount,
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

        clientThreads_.emplace_back(&IpcServer::ServeClient, this, pipe);
    }
}

void IpcServer::ProcessQueue() {
    while (true) {
        WorkItem item;
        {
            std::unique_lock lock(queueMutex_);
            queueReady_.wait(lock, [this] {
                return !running_.load() || !workQueue_.empty();
            });

            if (workQueue_.empty()) {
                if (!running_.load()) {
                    break;
                }
                continue;
            }

            item = std::move(workQueue_.front());
            workQueue_.pop();
        }

        try {
            item.responsePromise.set_value(handler_(item.request));
        } catch (...) {
            item.responsePromise.set_value(MakePipeError("internal_error", "native request handler raised an exception"));
        }
    }
}

void IpcServer::ServeClient(void* pipeHandle) {
    const HANDLE pipe = AsHandle(pipeHandle);
    const auto request = ReadFrame(pipeHandle);
    if (request.empty()) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return;
    }

    if (!running_.load()) {
        const auto response = MakePipeError("server_stopping", "server is shutting down");
        const bool writeAttempted = WriteFrame(pipeHandle, response);
        (void)writeAttempted;
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return;
    }

    std::promise<std::string> responsePromise;
    auto responseFuture = responsePromise.get_future();

    {
        std::scoped_lock lock(queueMutex_);
        if (workQueue_.size() >= kMaxQueuedRequests) {
            const auto response = MakePipeError("server_busy", "request queue is full");
            const bool writeAttempted = WriteFrame(pipeHandle, response);
            (void)writeAttempted;
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            return;
        }

        workQueue_.push(WorkItem{
            .request = request,
            .responsePromise = std::move(responsePromise),
        });
    }
    queueReady_.notify_one();

    std::string response;
    try {
        response = responseFuture.get();
    } catch (...) {
        response = MakePipeError("internal_error", "response future failed");
    }

    const bool writeAttempted = WriteFrame(pipeHandle, response);
    (void)writeAttempted;
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

void IpcServer::FailPendingRequests() {
    std::queue<WorkItem> pending;
    {
        std::scoped_lock lock(queueMutex_);
        std::swap(pending, workQueue_);
    }

    while (!pending.empty()) {
        auto item = std::move(pending.front());
        pending.pop();
        item.responsePromise.set_value(MakePipeError("server_stopping", "server is shutting down"));
    }
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
    const HANDLE pipe = AsHandle(pipeHandle);
    std::size_t totalWritten = 0;
    while (totalWritten < frame.size()) {
        DWORD bytesWritten = 0;
        const auto remaining = frame.size() - totalWritten;
        const auto chunkSize = static_cast<DWORD>(std::min<std::size_t>(remaining, 64 * 1024));
        const BOOL ok = WriteFile(
            pipe,
            frame.data() + totalWritten,
            chunkSize,
            &bytesWritten,
            nullptr);
        if (!ok || bytesWritten == 0) {
            return false;
        }

        totalWritten += bytesWritten;
    }

    return FlushFileBuffers(pipe) == TRUE;
}

}  // namespace idmcp
