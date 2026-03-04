#include "http_static_server.hpp"
#include "http_static_session.hpp"
#include <iostream>
#include <memory>
#include <utility>

namespace qt_server {
namespace server {

http_static_server::http_static_server(boost::asio::io_context& io_context,
                                       unsigned short port,
                                       std::string static_root,
                                       std::string public_host,
                                       std::string public_scheme)
    : io_context_(io_context)
    , acceptor_(io_context_, tcp::endpoint(tcp::v4(), port))
    , static_root_(std::move(static_root))
    , static_port_(port)
    , public_host_(std::move(public_host))
    , public_scheme_(std::move(public_scheme))
{
    std::cout << "HTTP static server initialized on port " << port
              << ", root=" << static_root_ << std::endl;
    do_accept();
}

void http_static_server::do_accept()
{
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            if (!ec) {
                std::make_shared<http_static_session>(
                    std::move(socket),
                    static_root_,
                    static_port_,
                    public_host_,
                    public_scheme_)->run();
            } else if (ec == boost::asio::error::operation_aborted) {
                return;
            } else {
                std::cerr << "HTTP accept error: " << ec.message() << std::endl;
            }
            do_accept();
        });
}

} // namespace server
} // namespace qt_server
