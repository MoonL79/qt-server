
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include "server/echo_server.hpp"

// 全局服务器指针，用于信号处理
qt_server::server::echo_server* g_server = nullptr;

namespace {

void set_env_if_absent(const char* key, const char* value)
{
    const char* existing = std::getenv(key);
    if (existing != nullptr && *existing != '\0') {
        return;
    }
#if defined(_WIN32)
    _putenv_s(key, value);
#else
    setenv(key, value, 0);
#endif
    std::cout << "[env-init] " << key << " is empty, apply default value." << std::endl;
}

void init_runtime_mysql_env_defaults()
{
    // Fallbacks for remote-debug sessions where IDE does not inject env vars.
    // Production should still prefer explicit environment configuration.
    set_env_if_absent("QT_SERVER_MYSQL_HOST", "127.0.0.1");
    set_env_if_absent("QT_SERVER_MYSQL_PORT", "3306");
    set_env_if_absent("QT_SERVER_MYSQL_DB", "app_db");
    set_env_if_absent("QT_SERVER_MYSQL_USER", "app_user");
    set_env_if_absent("QT_SERVER_MYSQL_PASSWORD", "123456");
}

std::string default_static_root_path()
{
#if defined(_WIN32)
    const char* home = std::getenv("USERPROFILE");
    if (home != nullptr && *home != '\0') {
        return std::string(home) + "\\qt-server-data";
    }
    return ".\\qt-server-data";
#else
    const char* home = std::getenv("HOME");
    if (home != nullptr && *home != '\0') {
        return std::string(home) + "/qt-server-data";
    }
    return "./qt-server-data";
#endif
}

unsigned short read_port_env(const char* key, unsigned short fallback)
{
    const char* value = std::getenv(key);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    try {
        const int parsed = std::stoi(value);
        if (parsed > 0 && parsed < 65536) {
            return static_cast<unsigned short>(parsed);
        }
    } catch (const std::exception&) {
    }
    std::cerr << "Invalid " << key << " value: " << value
              << ", fallback to " << fallback << std::endl;
    return fallback;
}

std::string read_string_env(const char* key, const char* fallback)
{
    const char* value = std::getenv(key);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return value;
}

} // namespace

// 信号处理函数
void signal_handler(int signal)
{
    std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
    if (g_server) {
        g_server->stop();
    }
}

int main(int argc, char* argv[])
{
    init_runtime_mysql_env_defaults();
    const std::string default_static_root = default_static_root_path();
    set_env_if_absent("QT_SERVER_STATIC_PORT", "18080");
    set_env_if_absent("QT_SERVER_STATIC_ROOT", default_static_root.c_str());
    set_env_if_absent("QT_SERVER_STATIC_PUBLIC_HOST", "127.0.0.1");
    set_env_if_absent("QT_SERVER_STATIC_PUBLIC_SCHEME", "http");

    // 设置信号处理
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // 设置服务器端口
    unsigned short port = 12345;
    if (argc > 1) {
        try {
            int p = std::stoi(argv[1]);
            if (p > 0 && p < 65536) {
                port = static_cast<unsigned short>(p);
            } else {
                std::cerr << "Invalid port number: " << p << std::endl;
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse port: " << e.what() << std::endl;
            return 1;
        }
    }

    const unsigned short static_port = read_port_env("QT_SERVER_STATIC_PORT", 18080);
    const std::string static_root = read_string_env("QT_SERVER_STATIC_ROOT", default_static_root.c_str());
    const std::string public_host = read_string_env("QT_SERVER_STATIC_PUBLIC_HOST", "127.0.0.1");
    const std::string public_scheme = read_string_env("QT_SERVER_STATIC_PUBLIC_SCHEME", "http");

    std::cout << "Starting WebSocket server on port " << port << "..." << std::endl;
    std::cout << "Starting HTTP static server on port " << static_port
              << ", root=" << static_root << std::endl;
    std::cout << "HTTP public endpoint: " << public_scheme << "://" << public_host
              << ":" << static_port << std::endl;

    // 创建echo服务器实例
    qt_server::server::echo_server server(port,
                                          static_port,
                                          static_root,
                                          public_host,
                                          public_scheme);
    g_server = &server;

    // 启动服务器
    server.start();

    std::cout << "Server started. Press Enter to stop..." << std::endl;

    // 等待用户输入或信号
    std::cin.get();

    // 停止服务器
    server.stop();
    g_server = nullptr;

    // 给服务器一点时间关闭
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::cout << "Server stopped." << std::endl;
    return 0;
}
