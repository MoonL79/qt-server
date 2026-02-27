#include "session.hpp"
#include <iostream>

namespace qt_server {
namespace server {

// 获取了一个socket的所有权，使这个类具有了处理网络通信的能力
session::session(tcp::socket socket)
    : socket_(std::move(socket))
{
    try {
        std::cout << "Session created for "
                  << socket_.remote_endpoint().address().to_string() << ":"
                  << socket_.remote_endpoint().port() << std::endl;
    } catch (const boost::system::system_error& e) {
        std::cout << "Session can't create with a unavailable remote endpoint: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Session can't get remote endpoint: " << e.what() << std::endl;
    }
}

session::~session() noexcept
{
    if (socket_.is_open()) {
        boost::system::error_code ec;
        std::cout << "Session closed for "
                  << socket_.remote_endpoint().address().to_string() << ":"
                  << socket_.remote_endpoint().port() << std::endl;
        socket_.shutdown(tcp::socket::shutdown_both, ec);
        socket_.close();
    }
}

void session::start()
{
    do_read();
}

void session::do_read()
{
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(buffer_),
        [this, self](boost::system::error_code error, std::size_t length)
        {
            if (!error)
            {
                std::cout << "Received " << length << " bytes: "
                          << std::string(buffer_.data(), length) << std::endl;
                // Echo模式：收到什么就回写什么
                std::cout << "Echoing " << length << " bytes back to client." << std::endl;
                do_write(length);
            }
            else
            {
                handle_error(error, "read");
            }
        });
}

void session::do_write(std::size_t length)
{
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(buffer_, length),
        [this, self](boost::system::error_code error, std::size_t /*length*/)
        {
            if (!error)
            {
                // 继续读取下一条消息
                do_read();
            }
            else
            {
                handle_error(error, "write");
            }
        });
}

void session::handle_error(const boost::system::error_code& error, const std::string& operation)
{
    if (error == boost::asio::error::eof)
    {
        std::cout << "Client disconnected gracefully." << std::endl;
    }
    else if (error == boost::asio::error::connection_reset)
    {
        std::cout << "Connection reset by peer." << std::endl;
    }
    else if (error)
    {
        std::cerr << "Error in " << operation << ": " << error.message() << std::endl;
    }

    // 关闭socket
    if (socket_.is_open())
    {
        socket_.close();
    }
}

} // namespace server
} // namespace qt_server
