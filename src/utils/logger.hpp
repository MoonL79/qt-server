
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <string>
#include <sstream>

enum LOG_LEVEL {
	LEVEL_NONE,
	LEVEL_DEBUG,
	LEVEL_INFO,
	LEVEL_WARN,
	LEVEL_ERROR
};

enum LOG_TARGET {
	TARGET_NONE = 0x00,
	TAEGET_CONSOLE = 0x01,
	TARGET_FILE = 0x10
};

// 工具方法，获取当前时间
std::string static GetCurrentTime() {
	auto now = std::chrono::system_clock::now();
	std::time_t now_time = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");
	std::string s << ss;
	return s;
}

// 采用单例模式实现日志模块
class LOGGER {
public:
	
	void init(LOG_LEVEL log_level, LOG_TARGET log_target);

	void uninit();

	// 日志等级相关
	LOG_LEVEL GetLogLevel();
	void SetLogLevel(LOG_LEVEL log_level);

	// 日志目标相关
	LOG_TARGET GetLogTarget();
	void SetLogTarget();

	static write_log(LOG_LEVEL log_level,     // 日志等级
					 LOG_TARGET log_target,   // 目标日志文件
					 std::string current_time // 记录日志的时间
					 unsigned char* fileName, // 记录日志的文件名
					 unsigned char* function, // 记录日志的函数名
					 int lineNumber,          // 记录日志的行数
					 char* format		      // 日志条目格式化规则
	);

private:
	LOGGER();
	~LOGGER();
	static LOGGER* logger;

	// 互斥锁
	static mutex log_mutex;

	// 存储log的buffer
	static string log_buffer;

	// Log级别
	LOGLEVEL log_level;

	// Log输出位置
	LOGTARGET log_target;
};