#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace idmcp {

class IpcServer {
public:
    using RequestHandler = std::function<std::string(const std::string&)>;

    IpcServer(std::string pipeName, RequestHandler handler);
    ~IpcServer();

    void Start();
    void Stop();

private:
    struct WorkItem {
        std::string request;
        std::promise<std::string> responsePromise;
    };

    void Run();
    void ProcessQueue();
    void ServeClient(void* pipeHandle);
    void FailPendingRequests();
    [[nodiscard]] std::string ReadFrame(void* pipeHandle) const;
    [[nodiscard]] bool WriteFrame(void* pipeHandle, const std::string& frame) const;

    std::string pipeName_;
    RequestHandler handler_;
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    std::thread workerThread_;
    std::mutex queueMutex_;
    std::condition_variable queueReady_;
    std::queue<WorkItem> workQueue_;
    std::vector<std::thread> clientThreads_;
};

}  // namespace idmcp
