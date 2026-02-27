#include "server/websocket_session.hpp"
#include <boost/beast/core/buffers_to_string.hpp>

namespace qt_server {
namespace server {

bool websocket_session::is_supported_type(const std::string& type)
{
    return type == "AUTH" || type == "PROFILE" || type == "MESSAGE";
}

bool websocket_session::is_supported_action(const std::string& type, const std::string& action)
{
    if (type == "AUTH") {
        return action == "LOGIN" || action == "LOGOUT" || action == "REFRESH_TOKEN";
    }
    if (type == "PROFILE") {
        return action == "GET" || action == "UPDATE";
    }
    if (type == "MESSAGE") {
        return action == "SEND" || action == "PULL" || action == "ACK";
    }
    return false;
}

bool websocket_session::require_string_field(const json::object& obj,
                                             const char* field,
                                             std::string& error_message)
{
    const auto it = obj.find(field);
    if (it == obj.end() || !it->value().is_string()) {
        error_message = std::string("field 'data.") + field + "' is required and must be string";
        return false;
    }
    if (it->value().as_string().empty()) {
        error_message = std::string("field 'data.") + field + "' cannot be empty";
        return false;
    }
    return true;
}

bool websocket_session::require_bool_field(const json::object& obj,
                                           const char* field,
                                           std::string& error_message)
{
    const auto it = obj.find(field);
    if (it == obj.end() || !it->value().is_bool()) {
        error_message = std::string("field 'data.") + field + "' is required and must be bool";
        return false;
    }
    return true;
}

bool websocket_session::validate_data_schema(const std::string& type,
                                             const std::string& action,
                                             const json::object& data,
                                             std::string& error_message)
{
    if (type == "AUTH") {
        if (action == "LOGIN") {
            return require_string_field(data, "username", error_message)
                && require_string_field(data, "password", error_message);
        }
        if (action == "LOGOUT") {
            return require_string_field(data, "token", error_message);
        }
        if (action == "REFRESH_TOKEN") {
            return require_string_field(data, "refresh_token", error_message);
        }
    }

    if (type == "PROFILE") {
        if (action == "GET") {
            return require_string_field(data, "user_id", error_message);
        }
        if (action == "UPDATE") {
            return require_string_field(data, "user_id", error_message)
                && require_string_field(data, "nickname", error_message)
                && require_string_field(data, "avatar_url", error_message);
        }
    }

    if (type == "MESSAGE") {
        if (action == "SEND") {
            return require_string_field(data, "conversation_id", error_message)
                && require_string_field(data, "content", error_message);
        }
        if (action == "PULL") {
            return require_string_field(data, "conversation_id", error_message);
        }
        if (action == "ACK") {
            return require_string_field(data, "conversation_id", error_message)
                && require_string_field(data, "message_id", error_message)
                && require_bool_field(data, "read", error_message);
        }
    }

    error_message = "unsupported type/action combination";
    return false;
}

bool websocket_session::parse_envelope(const std::string& payload,
                                       envelope& out,
                                       std::string& error_message)
{
    boost::system::error_code ec;
    json::value parsed = json::parse(payload, ec);
    if (ec) {
        error_message = "invalid JSON payload";
        return false;
    }

    if (!parsed.is_object()) {
        error_message = "payload must be a JSON object";
        return false;
    }

    const json::object& root = parsed.as_object();

    auto type_it = root.find("type");
    auto action_it = root.find("action");
    auto request_id_it = root.find("request_id");
    auto data_it = root.find("data");

    if (type_it == root.end() || !type_it->value().is_string()) {
        error_message = "field 'type' is required and must be string";
        return false;
    }
    if (action_it == root.end() || !action_it->value().is_string()) {
        error_message = "field 'action' is required and must be string";
        return false;
    }
    if (request_id_it == root.end() || !request_id_it->value().is_string()) {
        error_message = "field 'request_id' is required and must be string";
        return false;
    }
    if (data_it == root.end() || !data_it->value().is_object()) {
        error_message = "field 'data' is required and must be object";
        return false;
    }

    out.type = type_it->value().as_string().c_str();
    out.action = action_it->value().as_string().c_str();
    out.request_id = request_id_it->value().as_string().c_str();
    out.data = data_it->value().as_object();

    if (!is_supported_type(out.type)) {
        error_message = "field 'type' must be one of AUTH, PROFILE, MESSAGE";
        return false;
    }

    if (out.action.empty()) {
        error_message = "field 'action' cannot be empty";
        return false;
    }

    if (!is_supported_action(out.type, out.action)) {
        error_message = "field 'action' is not supported for this 'type'";
        return false;
    }

    if (out.request_id.empty()) {
        error_message = "field 'request_id' cannot be empty";
        return false;
    }

    if (!validate_data_schema(out.type, out.action, out.data, error_message)) {
        return false;
    }

    return true;
}

std::string websocket_session::build_response_payload(const std::string& type,
                                                      const std::string& action,
                                                      const std::string& request_id,
                                                      bool ok,
                                                      const std::string& message,
                                                      json::object data)
{
    data["ok"] = ok;
    data["message"] = message;

    json::object response;
    response["type"] = type;
    response["action"] = action;
    response["request_id"] = request_id;
    response["data"] = std::move(data);
    return json::serialize(response);
}

websocket_session::websocket_session(tcp::socket socket)
    : ws_(std::move(socket))
{
    try {
        auto endpoint = ws_.next_layer().remote_endpoint();
        remote_endpoint_ = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
        std::cout << "WebSocket session created for " << remote_endpoint_ << std::endl;
    } catch (const boost::system::system_error& e) {
        std::cout << "WebSocket session can't create with a unavailable remote endpoint: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cout << "WebSocket session can't get remote endpoint: " << e.what() << std::endl;
    }
}

void websocket_session::run()
{
    // Set suggested timeout settings for the websocket
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));

    // Set a decorator to change the Server of the handshake
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res)
        {
            res.set(http::field::server,
                std::string(BOOST_BEAST_VERSION_STRING) + " websocket-server-async");
        }));

    // Accept the websocket handshake
    ws_.async_accept(
        beast::bind_front_handler(
            &websocket_session::on_accept,
            shared_from_this()));
}

void websocket_session::on_accept(beast::error_code ec)
{
    if(ec) {
        std::cerr << "accept: " << ec.message() << std::endl;
        return;
    }

    if (!remote_endpoint_.empty()) {
        std::cout << "WebSocket client connected: " << remote_endpoint_ << std::endl;
    }

    // Read a message
    do_read();
}

void websocket_session::do_read()
{
    // Read a message into our buffer
    ws_.async_read(
        buffer_,
        beast::bind_front_handler(
            &websocket_session::on_read,
            shared_from_this()));
}

void websocket_session::on_read(
    beast::error_code ec,
    std::size_t bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);

    // This indicates that the websocket_session was closed
    if(ec == websocket::error::closed)
        return;

    if(ec) {
        std::cerr << "read: " << ec.message() << std::endl;
        return;
    }

    if (!remote_endpoint_.empty()) {
        std::cout << "WebSocket message received from " << remote_endpoint_
                  << ": " << beast::make_printable(buffer_.data()) << std::endl;
    }

    const std::string payload = beast::buffers_to_string(buffer_.data());
    envelope request;
    std::string error_message;
    json::object response_data;
    std::string response_type = "MESSAGE";
    std::string response_action = "ERROR";
    std::string response_request_id;
    bool ok = false;
    std::string message;

    if (!ws_.got_text()) {
        message = "binary frame is not supported, use text JSON payload";
        response_data["received_format"] = "binary";
    } else if (!parse_envelope(payload, request, error_message)) {
        message = error_message;
        response_data["received_payload"] = payload;
    } else {
        response_type = request.type;
        response_action = request.action;
        response_request_id = request.request_id;
        if (request.type == "AUTH" && request.action == "LOGIN") {
            ok = true;
            message = "login accepted (verification disabled)";
        } else {
            ok = true;
            message = "request accepted";
        }
        response_data["echo"] = request.data;
    }

    outbound_message_ = build_response_payload(
        response_type, response_action, response_request_id, ok, message, std::move(response_data));

    if (!remote_endpoint_.empty()) {
        std::cout << "Sending JSON response to " << remote_endpoint_
                  << ": " << outbound_message_ << std::endl;
    }

    ws_.text(true);
    ws_.async_write(
        net::buffer(outbound_message_),
        beast::bind_front_handler(
            &websocket_session::on_write,
            shared_from_this()));
}

void websocket_session::on_write(
    beast::error_code ec,
    std::size_t bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);

    if(ec) {
        std::cerr << "write: " << ec.message() << std::endl;
        return;
    }

    // Clear the buffer
    buffer_.consume(buffer_.size());
    outbound_message_.clear();

    // Do another read
    do_read();
}

websocket_session::~websocket_session() noexcept
{
    if (!remote_endpoint_.empty()) {
        std::cout << "WebSocket session closed for " << remote_endpoint_ << std::endl;
    }
}

} // namespace server
} // namespace qt_server
