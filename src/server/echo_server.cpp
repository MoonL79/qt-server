#include "echo_server.hpp"
#include "websocket_session.hpp"
#include <iostream>
#include <thread>
#include <functional>

namespace qt_server {
namespace server {

echo_server::echo_server(unsigned short port)
    : io_context_()
    , acceptor_(io_context_, tcp::endpoint(tcp::v4(), port))
    , stopped_(false)
{
    std::cout << "Echo server initialized on port " << port << std::endl;
    do_accept();
}

echo_server::~echo_server()
{
    stop();
    std::cout << "Echo server destroyed." << std::endl;
}

void echo_server::start()
{
    // 在后台线程中运行io_context
    std::thread([this]() {
        std::cout << "IO context thread started." << std::endl;
        while (!stopped_) {
            try {
                io_context_.run();
                break; // run()返回意味着io_context已停止
            } catch (const std::exception& e) {
                std::cerr << "Exception in io_context: " << e.what() << std::endl;
            }
        }
        std::cout << "IO context thread finished." << std::endl;
    }).detach(); // 分离线程，让它在后台运行

    std::cout << "Echo server started. Listening for connections..." << std::endl;
}

void echo_server::stop()
{
    if (!stopped_) {
        stopped_ = true;
        io_context_.stop();
        std::cout << "Echo server stopping..." << std::endl;
    }
}

void echo_server::do_accept()
{
    acceptor_.async_accept(
        [this](boost::system::error_code error, tcp::socket socket)
        {
            if (!error)
            {
                // 创建新的websocket_session来处理连接
                std::make_shared<websocket_session>(std::move(socket))->run();
            }
            else
            {
                std::cerr << "Accept error: " << error.message() << std::endl;
            }

            // 继续接受下一个连接，除非服务器已停止
            if (!stopped_) {
                do_accept();
            }
        });
}

} // namespace server
} // namespace qt_server