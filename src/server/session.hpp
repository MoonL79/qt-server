#ifndef SESSION_HPP
#define SESSION_HPP

#include <boost/asio.hpp>
#include <memory>
#include <array>

namespace qt_server {
namespace server {

using boost::asio::ip::tcp;

class session : public std::enable_shared_from_this<session>
{
public:
    explicit session(tcp::socket socket);
    ~session();

    // 启动会话，开始异步读取
    void start();

private:
    // 异步读取数据
    void do_read();

    // 异步写入数据
    void do_write(std::size_t length);

    // 处理错误
    void handle_error(const boost::system::error_code& error, const std::string& operation);

private:
    tcp::socket socket_;
    std::array<char, 8192> buffer_; // 8KB缓冲区
};

} // namespace server
} // namespace qt_server

#endif // SESSION_HPP