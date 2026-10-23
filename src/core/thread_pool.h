// thread_pool.h — minimal thread pool for parallel compression workers
#pragma once
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
#include <vector>

namespace wrc {

class ThreadPool {
public:
    explicit ThreadPool(unsigned n = std::thread::hardware_concurrency()) {
        if (n == 0) n = 4;
        threads_.reserve(n);
        for (unsigned i = 0; i < n; ++i)
            threads_.emplace_back([this] { worker(); });
    }
    ~ThreadPool() { shutdown(); }

    template <class F>
    auto submit(F&& f) -> std::future<decltype(f())> {
        using R = decltype(f());
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
        std::future<R> fut = task->get_future();
        {
            std::lock_guard<std::mutex> lk(m_);
            tasks_.emplace([task] { (*task)(); });
        }
        cv_.notify_one();
        return fut;
    }

    // Blocks until every submitted task finished executing.
    void waitIdle() {
        std::unique_lock<std::mutex> lk(m_);
        done_.wait(lk, [this] { return tasks_.empty() && active_ == 0; });
    }

    void shutdown() {
        {
            std::lock_guard<std::mutex> lk(m_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : threads_)
            if (t.joinable()) t.join();
        threads_.clear();
    }

private:
    void worker() {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lk(m_);
                cv_.wait(lk, [this] { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty()) return;
                job = std::move(tasks_.front());
                tasks_.pop();
                ++active_;
            }
            job();
            bool notify = false;
            {
                std::lock_guard<std::mutex> lk(m_);
                --active_;
                if (tasks_.empty() && active_ == 0) notify = true;
            }
            if (notify) done_.notify_all();
        }
    }

    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> tasks_;
    std::mutex m_;
    std::condition_variable cv_, done_;
    bool stop_ = false;
    int active_ = 0;
};

}  // namespace wrc
