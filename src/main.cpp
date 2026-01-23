
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include "server/echo_server.hpp"

// 全局服务器指针，用于信号处理
qt_server::server::echo_server* g_server = nullptr;

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

    std::cout << "Starting echo server on port " << port << "..." << std::endl;

    // 创建echo服务器实例
    qt_server::server::echo_server server(port);
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
