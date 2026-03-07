#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace idmcp {

class IpcServer {
public:
    using RequestHandler = std::function<std::string(const std::string&)>;

    IpcServer(std::string pipeName, RequestHandler handler);
    ~IpcServer();

    void Start();
    void Stop();

private:
    void Run();
    [[nodiscard]] bool ServeClient(void* pipeHandle) const;
    [[nodiscard]] std::string ReadFrame(void* pipeHandle) const;
    [[nodiscard]] bool WriteFrame(void* pipeHandle, const std::string& frame) const;

    std::string pipeName_;
    RequestHandler handler_;
    std::atomic<bool> running_{false};
    std::thread worker_;
};

}  // namespace idmcp
