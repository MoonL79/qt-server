#ifndef HTTP_STATIC_SERVER_HPP
#define HTTP_STATIC_SERVER_HPP

#include <boost/asio.hpp>
#include <string>

namespace qt_server {
namespace server {

using boost::asio::ip::tcp;

class http_static_server
{
public:
    http_static_server(boost::asio::io_context& io_context,
                       unsigned short port,
                       std::string static_root,
                       std::string public_host,
                       std::string public_scheme);

private:
    void do_accept();

private:
    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    std::string static_root_;
    unsigned short static_port_;
    std::string public_host_;
    std::string public_scheme_;
};

} // namespace server
} // namespace qt_server

#endif // HTTP_STATIC_SERVER_HPP
