#ifndef HTTP_STATIC_SESSION_HPP
#define HTTP_STATIC_SESSION_HPP

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include "upload_token_store.hpp"
#include <memory>
#include <string>
#include <utility>

namespace qt_server {
namespace server {

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

class http_static_session : public std::enable_shared_from_this<http_static_session>
{
public:
    http_static_session(tcp::socket socket,
                        std::string static_root,
                        unsigned short static_port,
                        std::string public_host,
                        std::string public_scheme);
    void run();

private:
    struct multipart_file_part
    {
        std::string data;
        std::string content_type;
        std::string filename;
    };

    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);

    template <class Body, class Fields>
    void send_response(http::response<Body, Fields>&& response)
    {
        auto message = std::make_shared<http::response<Body, Fields>>(std::move(response));
        response_ = message;
        auto self = shared_from_this();
        http::async_write(socket_, *message,
            [self](beast::error_code write_ec, std::size_t) {
                self->on_write(write_ec);
            });
    }

    void on_write(beast::error_code ec);
    void handle_request();
    void handle_upload_avatar();
    void send_json_response(http::status status, bool ok, const std::string& message, const std::string& avatar_url = "");
    bool parse_authorization_bearer(std::string& token) const;
    bool parse_multipart_avatar(std::string& user_id,
                                multipart_file_part& file_part,
                                std::string& error_message) const;
    static bool parse_boundary_from_content_type(const std::string& content_type, std::string& boundary);
    static bool is_unsigned_integer_text(const std::string& value);
    static std::string trim_copy(const std::string& input);
    static std::string to_lower_copy(const std::string& input);
    static std::string json_escape(const std::string& input);
    static bool extract_disposition_param(const std::string& content_disposition,
                                          const std::string& key,
                                          std::string& value);
    static bool infer_extension(const std::string& content_type,
                                const std::string& filename,
                                std::string& extension);
    static bool ensure_directory_tree(const std::string& path);
    static bool cleanup_old_avatar_files(const std::string& avatar_dir, const std::string& user_id);
    std::string build_avatar_absolute_url(const std::string& filename) const;

private:
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    std::string static_root_;
    unsigned short static_port_;
    std::string public_host_;
    std::string public_scheme_;
    std::unique_ptr<http::request_parser<http::string_body>> parser_;
    http::request<http::string_body> request_;
    std::shared_ptr<void> response_;
};

} // namespace server
} // namespace qt_server

#endif // HTTP_STATIC_SESSION_HPP
