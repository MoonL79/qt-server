#ifndef WEBSOCKET_SESSION_HPP
#define WEBSOCKET_SESSION_HPP

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/json.hpp>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <iostream>
#include <vector>

namespace qt_server {
namespace server {

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace json = boost::json;           // from <boost/json.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

// Echoes back all received WebSocket messages
class websocket_session : public std::enable_shared_from_this<websocket_session>
{
    enum class protocol_code : int
    {
        OK = 0,
        INVALID_REQUEST = 1001,
        INVALID_ACTION = 1002,
        INVALID_PARAM = 1003,
        UNSUPPORTED_TYPE = 1004,
        REQUEST_ID_MISSING = 1005,
        INTERNAL_ERROR = 1099,
        AUTH_REQUIRED = 2001,
        TOKEN_INVALID = 2002,
        TOKEN_EXPIRED = 2003,
        LOGIN_FAILED = 2004,
        PERMISSION_DENIED = 2005,
        REGISTER_CONFLICT = 2006,
        REGISTER_FAILED = 2007,
        PROFILE_NOT_FOUND = 3001,
        PROFILE_UPDATE_CONFLICT = 3002,
        PROFILE_VALIDATION_FAILED = 3003,
        MESSAGE_INVALID = 4001,
        MESSAGE_TOO_LARGE = 4002,
        MESSAGE_TARGET_OFFLINE = 4003,
        MESSAGE_RATE_LIMITED = 4004,
        MESSAGE_NOT_FOUND = 4005
    };

    struct envelope
    {
        std::string type;
        std::string action;
        std::string request_id;
        json::object data;
    };

    websocket::stream<tcp::socket> ws_;
    beast::flat_buffer buffer_;
    std::string remote_endpoint_;
    std::deque<std::string> pending_writes_;
    bool write_in_progress_ = false;
    std::uint64_t authenticated_user_id_ = 0;
    std::uint64_t authenticated_numeric_id_ = 0;
    std::string authenticated_username_;

public:
    // Take ownership of the socket
    explicit websocket_session(tcp::socket socket);
    ~websocket_session() noexcept;

    // Start the asynchronous operation
    void run();

private:
    static bool is_supported_type(const std::string& type);
    static bool is_supported_action(const std::string& type, const std::string& action);
    static bool require_string_field(const json::object& obj,
                                     const char* field,
                                     std::string& error_message);
    static bool require_bool_field(const json::object& obj,
                                   const char* field,
                                   std::string& error_message);
    static bool validate_optional_string_max_len(const json::object& obj,
                                                 const char* field,
                                                 std::size_t max_len,
                                                 std::string& error_message);
    static bool handle_register(const json::object& data,
                                json::object& response_data,
                                std::string& message,
                                protocol_code& response_code);
    bool handle_login(const json::object& data,
                      json::object& response_data,
                      std::string& message,
                      protocol_code& response_code);
    bool handle_logout(const json::object& data,
                       json::object& response_data,
                       std::string& message,
                       protocol_code& response_code);
    static bool handle_profile_get(const json::object& data,
                                   json::object& response_data,
                                   std::string& message,
                                   protocol_code& response_code);
    static bool handle_profile_get_info(const json::object& data,
                                        json::object& response_data,
                                        std::string& message,
                                        protocol_code& response_code);
    static bool handle_profile_set_info(const json::object& data,
                                        json::object& response_data,
                                        std::string& message,
                                        protocol_code& response_code);
    static bool handle_profile_add_friend(const json::object& data,
                                          json::object& response_data,
                                          std::string& message,
                                          protocol_code& response_code);
    bool handle_profile_create_group(const json::object& data,
                                     json::object& response_data,
                                     std::string& message,
                                     protocol_code& response_code);
    bool handle_profile_join_group(const json::object& data,
                                   json::object& response_data,
                                   std::string& message,
                                   protocol_code& response_code);
    bool handle_profile_leave_group(const json::object& data,
                                    json::object& response_data,
                                    std::string& message,
                                    protocol_code& response_code);
    bool handle_profile_list_groups(const json::object& data,
                                    json::object& response_data,
                                    std::string& message,
                                    protocol_code& response_code);
    static bool handle_profile_list_friends(const json::object& data,
                                            json::object& response_data,
                                            std::string& message,
                                            protocol_code& response_code);
    static bool handle_profile_list_conversations(const json::object& data,
                                                  json::object& response_data,
                                                  std::string& message,
                                                  protocol_code& response_code);
    static bool handle_profile_delete_friend(const json::object& data,
                                             json::object& response_data,
                                             std::string& message,
                                             protocol_code& response_code);
    bool handle_message_send(const json::object& data,
                             json::object& response_data,
                             std::string& message,
                             protocol_code& response_code);
    static bool validate_data_schema(const std::string& type,
                                     const std::string& action,
                                     const json::object& data,
                                     std::string& error_message,
                                     protocol_code& error_code);
    static bool parse_envelope(const std::string& payload,
                               envelope& out,
                               std::string& error_message,
                               protocol_code& error_code);
    static std::string build_response_payload(const std::string& type,
                                              const std::string& action,
                                              const std::string& request_id,
                                              protocol_code code,
                                              bool ok,
                                              const std::string& message,
                                              json::object data);
    static std::vector<std::uint64_t> query_friend_user_ids(std::uint64_t user_id);
    static void broadcast_presence_to_friends(std::uint64_t user_id,
                                              std::uint64_t numeric_id,
                                              bool is_online,
                                              const std::string& last_seen_at,
                                              const char* presence_event);
    void bind_authenticated_user(std::uint64_t user_id,
                                 std::uint64_t numeric_id,
                                 const std::string& username,
                                 json::object* response_data = nullptr);
    void unbind_authenticated_user(bool explicit_logout,
                                   json::object* response_data = nullptr);
    void queue_outbound_message(std::string payload);
    void start_next_write();

    void on_accept(beast::error_code ec);

    void do_read();

    void on_read(beast::error_code ec, std::size_t bytes_transferred);

    void on_write(beast::error_code ec, std::size_t bytes_transferred);
};

} // namespace server
} // namespace qt_server

#endif // WEBSOCKET_SESSION_HPP
