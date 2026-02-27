#ifndef ECHO_SERVER_HPP
#define ECHO_SERVER_HPP

#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <atomic>

namespace qt_server {
namespace server {

using boost::asio::ip::tcp;

class echo_server
{
public:
    // 构造函数：指定监听端口
    explicit echo_server(unsigned short port);
    ~echo_server();

    // 启动服务器
    void start();

    // 停止服务器
    void stop();

private:
    // 异步接受连接
    void do_accept();

private:
    boost::asio::io_context io_context_;
    tcp::acceptor acceptor_;
    std::atomic<bool> stopped_;
};

} // namespace server
} // namespace qt_server

#endif // ECHO_SERVER_HPP