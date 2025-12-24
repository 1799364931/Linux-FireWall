#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

class log_info_queue {
   public:
    log_info_queue() {}

    void put_log(const std::string& log) {
        std::unique_lock<std::mutex> lock(mtx_);
        if (queue_.size() >= MAX_QUEUE_SIZE) {
            queue_.pop();  // 丢弃最旧的
        }
        queue_.push(log);
        cond_.notify_one(); 
    }

    // 批量获取日志，最多取 FETCH_CNT 条
    int fetch_logs(std::vector<std::string>& logs) {
        std::unique_lock<std::mutex> lock(mtx_);
        cond_.wait(lock, [&] { return !queue_.empty(); }); 

        int actual = 0;
        logs.clear();
        while (!queue_.empty() && actual < FETCH_CNT) {
            logs.push_back(queue_.front());
            queue_.pop();
            actual++;
        }

        return actual; // 返回实际取出的数量
    }

   private:
    constexpr static int MAX_QUEUE_SIZE = 1024; // 队列最大容量
    constexpr static int FETCH_CNT = 32;        // 每次最多取多少条
    std::queue<std::string> queue_;
    std::mutex mtx_;
    std::condition_variable cond_;
};
