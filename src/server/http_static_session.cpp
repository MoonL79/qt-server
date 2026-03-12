#include "http_static_session.hpp"
#include <boost/core/ignore_unused.hpp>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <cerrno>

#if defined(_WIN32)
#include <direct.h>
#define QT_SERVER_MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define QT_SERVER_MKDIR(path) mkdir(path, 0755)
#endif

namespace qt_server {
namespace server {

namespace {

const std::size_t k_avatar_max_bytes = 2U * 1024U * 1024U;
const std::size_t k_http_body_limit_bytes = 3U * 1024U * 1024U;

std::string mime_type_from_path(const std::string& path)
{
    const std::size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) {
        return "application/octet-stream";
    }
    std::string ext = path.substr(dot + 1U);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (ext == "jpg" || ext == "jpeg") {
        return "image/jpeg";
    }
    if (ext == "png") {
        return "image/png";
    }
    if (ext == "webp") {
        return "image/webp";
    }
    if (ext == "gif") {
        return "image/gif";
    }
    if (ext == "svg") {
        return "image/svg+xml";
    }
    if (ext == "ico") {
        return "image/x-icon";
    }
    return "application/octet-stream";
}

bool decode_url_component(const std::string& input, std::string& decoded)
{
    decoded.clear();
    decoded.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const char ch = input[i];
        if (ch != '%') {
            decoded.push_back(ch);
            continue;
        }

        if (i + 2U >= input.size()) {
            return false;
        }
        const char high = input[i + 1U];
        const char low = input[i + 2U];
        if (!std::isxdigit(static_cast<unsigned char>(high))
            || !std::isxdigit(static_cast<unsigned char>(low))) {
            return false;
        }
        const std::string hex = input.substr(i + 1U, 2U);
        const char value = static_cast<char>(std::strtoul(hex.c_str(), nullptr, 16));
        if (value == '\0') {
            return false;
        }
        decoded.push_back(value);
        i += 2U;
    }
    return true;
}

bool build_safe_relative_path(const std::string& raw_input, std::string& safe_relative)
{
    std::string decoded;
    if (!decode_url_component(raw_input, decoded)) {
        return false;
    }
    std::replace(decoded.begin(), decoded.end(), '\\', '/');

    std::vector<std::string> segments;
    std::istringstream iss(decoded);
    std::string segment;
    while (std::getline(iss, segment, '/')) {
        if (segment.empty() || segment == ".") {
            continue;
        }
        if (segment == "..") {
            return false;
        }
        if (segment.find(':') != std::string::npos) {
            return false;
        }
        segments.push_back(segment);
    }

    if (segments.empty()) {
        return false;
    }

    std::ostringstream joined;
    for (std::size_t i = 0; i < segments.size(); ++i) {
        if (i != 0U) {
            joined << "/";
        }
        joined << segments[i];
    }
    safe_relative = joined.str();
    return !safe_relative.empty();
}

std::string trim_trailing_slashes(const std::string& path)
{
    if (path.empty()) {
        return path;
    }
    std::size_t end = path.size();
    while (end > 0U && (path[end - 1U] == '/' || path[end - 1U] == '\\')) {
        --end;
    }
    return path.substr(0U, end);
}

std::string join_path(const std::string& lhs, const std::string& rhs)
{
    if (lhs.empty()) {
        return rhs;
    }
    if (rhs.empty()) {
        return lhs;
    }
    if (lhs.back() == '/' || lhs.back() == '\\') {
        return lhs + rhs;
    }
    return lhs + "/" + rhs;
}

std::string read_header_line_value(const std::string& headers, const std::string& field_name)
{
    const std::string marker = field_name + ":";
    std::istringstream iss(headers);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.size() < marker.size()) {
            continue;
        }
        std::string prefix = line.substr(0U, marker.size());
        std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::string lowered_marker = marker;
        std::transform(lowered_marker.begin(), lowered_marker.end(), lowered_marker.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (prefix != lowered_marker) {
            continue;
        }
        return line.substr(marker.size());
    }
    return "";
}

} // namespace

http_static_session::http_static_session(tcp::socket socket,
                                         std::string static_root,
                                         unsigned short static_port,
                                         std::string public_host,
                                         std::string public_scheme)
    : socket_(std::move(socket))
    , static_root_(trim_trailing_slashes(static_root))
    , static_port_(static_port)
    , public_host_(std::move(public_host))
    , public_scheme_(std::move(public_scheme))
{
}

void http_static_session::run()
{
    do_read();
}

void http_static_session::do_read()
{
    parser_.reset(new http::request_parser<http::string_body>());
    parser_->body_limit(k_http_body_limit_bytes);
    auto self = shared_from_this();
    http::async_read(socket_, buffer_, *parser_,
        [self](beast::error_code ec, std::size_t bytes_transferred) {
            self->on_read(ec, bytes_transferred);
        });
}

void http_static_session::on_read(beast::error_code ec, std::size_t bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);
    if (ec == http::error::end_of_stream) {
        on_write(ec);
        return;
    }
    if (ec) {
        std::cerr << "HTTP read error: " << ec.message() << std::endl;
        return;
    }
    request_ = parser_->release();
    parser_.reset();
    handle_request();
}

void http_static_session::send_json_response(http::status status,
                                             bool ok,
                                             const std::string& message,
                                             const std::string& avatar_url)
{
    std::ostringstream oss;
    oss << "{"
        << "\"ok\":" << (ok ? "true" : "false")
        << ",\"message\":\"" << json_escape(message) << "\"";
    if (!avatar_url.empty()) {
        oss << ",\"avatar_url\":\"" << json_escape(avatar_url) << "\"";
    }
    oss << "}";

    http::response<http::string_body> response{status, request_.version()};
    response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(http::field::content_type, "application/json; charset=utf-8");
    response.set(http::field::cache_control, "no-store");
    response.set("X-Content-Type-Options", "nosniff");
    response.keep_alive(false);
    response.body() = oss.str();
    response.prepare_payload();
    send_response(std::move(response));
}

void http_static_session::handle_request()
{
    if (request_.method() == http::verb::post && request_.target() == "/upload/avatar") {
        handle_upload_avatar();
        return;
    }

    const auto bad_request = [this](const std::string& why) {
        http::response<http::string_body> response{http::status::bad_request, request_.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/plain; charset=utf-8");
        response.set(http::field::cache_control, "public, max-age=3600");
        response.set("X-Content-Type-Options", "nosniff");
        response.keep_alive(false);
        response.body() = why;
        response.prepare_payload();
        send_response(std::move(response));
    };

    const auto not_found = [this]() {
        http::response<http::string_body> response{http::status::not_found, request_.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/plain; charset=utf-8");
        response.set(http::field::cache_control, "public, max-age=3600");
        response.set("X-Content-Type-Options", "nosniff");
        response.keep_alive(false);
        response.body() = "resource not found";
        response.prepare_payload();
        send_response(std::move(response));
    };

    const auto forbidden = [this]() {
        http::response<http::string_body> response{http::status::forbidden, request_.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/plain; charset=utf-8");
        response.set(http::field::cache_control, "public, max-age=3600");
        response.set("X-Content-Type-Options", "nosniff");
        response.keep_alive(false);
        response.body() = "forbidden";
        response.prepare_payload();
        send_response(std::move(response));
    };

    const auto method_not_allowed = [this]() {
        http::response<http::string_body> response{http::status::method_not_allowed, request_.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/plain; charset=utf-8");
        response.set(http::field::allow, "GET, HEAD, POST");
        response.set(http::field::cache_control, "public, max-age=3600");
        response.set("X-Content-Type-Options", "nosniff");
        response.keep_alive(false);
        response.body() = "method not allowed";
        response.prepare_payload();
        send_response(std::move(response));
    };

    if (request_.method() != http::verb::get && request_.method() != http::verb::head) {
        method_not_allowed();
        return;
    }

    const std::string target = std::string(request_.target());
    if (target.empty() || target[0] != '/') {
        bad_request("invalid request target");
        return;
    }

    const std::size_t query_pos = target.find('?');
    const std::string clean_target = target.substr(0U, query_pos);
    static const std::string prefix = "/static/";
    if (clean_target.rfind(prefix, 0U) != 0U) {
        not_found();
        return;
    }
    if (clean_target.size() == prefix.size()) {
        not_found();
        return;
    }

    std::string safe_relative;
    if (!build_safe_relative_path(clean_target.substr(prefix.size()), safe_relative)) {
        forbidden();
        return;
    }

    if (static_root_.empty()) {
        bad_request("static root is empty");
        return;
    }

    const std::string file_path = join_path(static_root_, safe_relative);
    beast::error_code file_ec;
    http::file_body::value_type body;
    body.open(file_path.c_str(), beast::file_mode::scan, file_ec);
    if (file_ec) {
        if (file_ec == beast::errc::no_such_file_or_directory) {
            not_found();
            return;
        }
        if (file_ec == beast::errc::permission_denied) {
            forbidden();
            return;
        }
        http::response<http::string_body> response{http::status::internal_server_error, request_.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, "text/plain; charset=utf-8");
        response.set(http::field::cache_control, "public, max-age=3600");
        response.set("X-Content-Type-Options", "nosniff");
        response.keep_alive(false);
        response.body() = "internal server error";
        response.prepare_payload();
        send_response(std::move(response));
        return;
    }

    const std::uint64_t file_size = body.size();
    if (request_.method() == http::verb::head) {
        http::response<http::empty_body> response{http::status::ok, request_.version()};
        response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(http::field::content_type, mime_type_from_path(file_path));
        response.set(http::field::cache_control, "public, max-age=3600");
        response.set("X-Content-Type-Options", "nosniff");
        response.keep_alive(false);
        response.content_length(file_size);
        send_response(std::move(response));
        return;
    }

    http::response<http::file_body> response{http::status::ok, request_.version()};
    response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(http::field::content_type, mime_type_from_path(file_path));
    response.set(http::field::cache_control, "public, max-age=3600");
    response.set("X-Content-Type-Options", "nosniff");
    response.keep_alive(false);
    response.content_length(file_size);
    response.body() = std::move(body);
    send_response(std::move(response));
}

bool http_static_session::parse_authorization_bearer(std::string& token) const
{
    token.clear();
    auto it = request_.find(http::field::authorization);
    if (it == request_.end()) {
        return false;
    }
    const std::string raw = trim_copy(std::string(it->value()));
    const std::string prefix = "Bearer ";
    if (raw.size() <= prefix.size() || raw.substr(0U, prefix.size()) != prefix) {
        return false;
    }
    token = trim_copy(raw.substr(prefix.size()));
    return !token.empty();
}

bool http_static_session::parse_boundary_from_content_type(const std::string& content_type,
                                                           std::string& boundary)
{
    boundary.clear();
    const std::string key = "boundary=";
    std::string lowered = to_lower_copy(content_type);
    const std::size_t pos = lowered.find(key);
    if (pos == std::string::npos) {
        return false;
    }

    std::string raw = trim_copy(content_type.substr(pos + key.size()));
    if (raw.empty()) {
        return false;
    }
    const std::size_t semicolon = raw.find(';');
    if (semicolon != std::string::npos) {
        raw = trim_copy(raw.substr(0U, semicolon));
    }
    if (raw.front() == '"' && raw.back() == '"' && raw.size() >= 2U) {
        raw = raw.substr(1U, raw.size() - 2U);
    }
    boundary = raw;
    return !boundary.empty();
}

bool http_static_session::extract_disposition_param(const std::string& content_disposition,
                                                    const std::string& key,
                                                    std::string& value)
{
    value.clear();
    const std::string lowered = to_lower_copy(content_disposition);
    const std::string token = key + "=";
    const std::size_t pos = lowered.find(token);
    if (pos == std::string::npos) {
        return false;
    }

    std::size_t begin = pos + token.size();
    if (begin >= content_disposition.size()) {
        return false;
    }
    if (content_disposition[begin] == '"') {
        ++begin;
        const std::size_t end_quote = content_disposition.find('"', begin);
        if (end_quote == std::string::npos) {
            return false;
        }
        value = content_disposition.substr(begin, end_quote - begin);
        return true;
    }

    std::size_t end = content_disposition.find(';', begin);
    if (end == std::string::npos) {
        end = content_disposition.size();
    }
    value = trim_copy(content_disposition.substr(begin, end - begin));
    return !value.empty();
}

bool http_static_session::parse_multipart_avatar(std::string& user_id,
                                                 multipart_file_part& file_part,
                                                 std::string& error_message) const
{
    user_id.clear();
    file_part = multipart_file_part{};
    error_message.clear();

    auto content_type_it = request_.find(http::field::content_type);
    if (content_type_it == request_.end()) {
        error_message = "missing content-type";
        return false;
    }
    const std::string content_type = std::string(content_type_it->value());
    if (to_lower_copy(content_type).find("multipart/form-data") == std::string::npos) {
        error_message = "content-type must be multipart/form-data";
        return false;
    }

    std::string boundary;
    if (!parse_boundary_from_content_type(content_type, boundary)) {
        error_message = "missing multipart boundary";
        return false;
    }

    const std::string& body = request_.body();
    const std::string delimiter = "--" + boundary;
    std::size_t cursor = body.find(delimiter);
    if (cursor == std::string::npos) {
        error_message = "invalid multipart body";
        return false;
    }

    while (cursor != std::string::npos) {
        cursor += delimiter.size();
        if (cursor + 1U < body.size() && body[cursor] == '-' && body[cursor + 1U] == '-') {
            break;
        }
        if (cursor + 1U >= body.size() || body[cursor] != '\r' || body[cursor + 1U] != '\n') {
            error_message = "invalid multipart delimiter";
            return false;
        }
        cursor += 2U;

        const std::size_t headers_end = body.find("\r\n\r\n", cursor);
        if (headers_end == std::string::npos) {
            error_message = "invalid multipart headers";
            return false;
        }
        const std::string part_headers = body.substr(cursor, headers_end - cursor);
        const std::size_t data_start = headers_end + 4U;
        std::size_t next_delim = body.find("\r\n" + delimiter, data_start);
        if (next_delim == std::string::npos) {
            error_message = "invalid multipart closing boundary";
            return false;
        }
        const std::size_t data_end = next_delim;
        const std::string part_data = body.substr(data_start, data_end - data_start);

        std::string content_disposition = trim_copy(read_header_line_value(part_headers, "content-disposition"));
        if (content_disposition.empty()) {
            error_message = "missing content-disposition";
            return false;
        }
        std::string part_name;
        if (!extract_disposition_param(content_disposition, "name", part_name)) {
            error_message = "missing part name";
            return false;
        }

        if (part_name == "user_id") {
            user_id = trim_copy(part_data);
        } else if (part_name == "file") {
            file_part.data = part_data;
            file_part.content_type = trim_copy(read_header_line_value(part_headers, "content-type"));
            extract_disposition_param(content_disposition, "filename", file_part.filename);
        }

        cursor = next_delim + 2U;
    }

    if (user_id.empty()) {
        error_message = "missing user_id field";
        return false;
    }
    if (file_part.data.empty()) {
        error_message = "missing file field";
        return false;
    }
    return true;
}

bool http_static_session::is_unsigned_integer_text(const std::string& value)
{
    if (value.empty()) {
        return false;
    }
    for (char ch : value) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    return true;
}

std::string http_static_session::trim_copy(const std::string& input)
{
    std::size_t begin = 0U;
    std::size_t end = input.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1U])) != 0) {
        --end;
    }
    return input.substr(begin, end - begin);
}

std::string http_static_session::to_lower_copy(const std::string& input)
{
    std::string out = input;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string http_static_session::json_escape(const std::string& input)
{
    std::ostringstream oss;
    for (char ch : input) {
        switch (ch) {
        case '"':
            oss << "\\\"";
            break;
        case '\\':
            oss << "\\\\";
            break;
        case '\b':
            oss << "\\b";
            break;
        case '\f':
            oss << "\\f";
            break;
        case '\n':
            oss << "\\n";
            break;
        case '\r':
            oss << "\\r";
            break;
        case '\t':
            oss << "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20U) {
                oss << "\\u"
                    << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(ch))
                    << std::nouppercase << std::dec;
            } else {
                oss << ch;
            }
            break;
        }
    }
    return oss.str();
}

bool http_static_session::infer_extension(const std::string& content_type,
                                          const std::string& filename,
                                          std::string& extension)
{
    extension.clear();
    const std::string lowered = to_lower_copy(trim_copy(content_type));
    if (lowered == "image/jpeg" || lowered == "image/jpg") {
        extension = "jpg";
        return true;
    }
    if (lowered == "image/png") {
        extension = "png";
        return true;
    }
    if (lowered == "image/webp") {
        extension = "webp";
        return true;
    }
    if (lowered == "image/gif") {
        extension = "gif";
        return true;
    }

    const std::size_t dot = filename.find_last_of('.');
    if (dot == std::string::npos || dot + 1U >= filename.size()) {
        return false;
    }
    std::string ext = to_lower_copy(filename.substr(dot + 1U));
    if (ext == "jpeg") {
        ext = "jpg";
    }
    if (ext == "jpg" || ext == "png" || ext == "webp" || ext == "gif") {
        extension = ext;
        return true;
    }
    return false;
}

bool http_static_session::ensure_directory_tree(const std::string& path)
{
    if (path.empty()) {
        return false;
    }
    std::string normalized = path;
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    std::string current;
    if (!normalized.empty() && normalized[0] == '/') {
        current = "/";
    }
#if defined(_WIN32)
    if (normalized.size() >= 2U && std::isalpha(static_cast<unsigned char>(normalized[0])) && normalized[1] == ':') {
        current = normalized.substr(0U, 2U);
    }
#endif

    std::istringstream iss(normalized);
    std::string segment;
    while (std::getline(iss, segment, '/')) {
        if (segment.empty()) {
            continue;
        }
        if (!current.empty() && current.back() != '/' && current.back() != '\\') {
            current += "/";
        }
        current += segment;
        if (QT_SERVER_MKDIR(current.c_str()) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

bool http_static_session::cleanup_old_avatar_files(const std::string& avatar_dir, const std::string& user_id)
{
    static const char* exts[] = {"jpg", "png", "webp", "gif"};
    bool ok = true;
    for (const char* ext : exts) {
        const std::string path = join_path(avatar_dir, user_id + "." + ext);
        if (std::remove(path.c_str()) != 0 && errno != ENOENT) {
            ok = false;
        }
    }
    return ok;
}

std::string http_static_session::build_avatar_absolute_url(const std::string& filename) const
{
    std::ostringstream oss;
    oss << (public_scheme_.empty() ? "http" : public_scheme_)
        << "://"
        << (public_host_.empty() ? "127.0.0.1" : public_host_)
        << ":"
        << static_port_
        << "/static/avatar/"
        << filename;
    return oss.str();
}

void http_static_session::handle_upload_avatar()
{
    std::string bearer;
    if (!parse_authorization_bearer(bearer)) {
        send_json_response(http::status::unauthorized, false, "missing or invalid bearer token");
        return;
    }

    std::string user_id;
    multipart_file_part file_part;
    std::string parse_error;
    if (!parse_multipart_avatar(user_id, file_part, parse_error)) {
        send_json_response(http::status::bad_request, false, parse_error);
        return;
    }
    if (!is_unsigned_integer_text(user_id)) {
        send_json_response(http::status::bad_request, false, "field 'user_id' must be unsigned integer string");
        return;
    }
    const unsigned long long user_id_num = std::strtoull(user_id.c_str(), nullptr, 10);
    unsigned long long token_user_id = 0ULL;
    std::string token_error;
    if (!validate_upload_token(bearer, token_user_id, token_error)) {
        send_json_response(http::status::unauthorized, false, token_error);
        return;
    }
    if (token_user_id != user_id_num) {
        send_json_response(http::status::unauthorized, false, "token does not match user_id");
        return;
    }
    if (file_part.data.size() > k_avatar_max_bytes) {
        send_json_response(http::status::payload_too_large, false, "avatar file too large (max 2MB)");
        return;
    }

    std::string extension;
    if (!infer_extension(file_part.content_type, file_part.filename, extension)) {
        send_json_response(http::status::unsupported_media_type, false, "unsupported avatar media type");
        return;
    }

    const std::string avatar_dir = join_path(static_root_, "avatar");
    if (!ensure_directory_tree(avatar_dir)) {
        send_json_response(http::status::internal_server_error, false, "failed to create avatar directory");
        return;
    }
    if (!cleanup_old_avatar_files(avatar_dir, user_id)) {
        send_json_response(http::status::internal_server_error, false, "failed to cleanup previous avatar");
        return;
    }

    const std::string filename = user_id + "." + extension;
    const std::string path = join_path(avatar_dir, filename);
    std::ofstream ofs(path.c_str(), std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        send_json_response(http::status::internal_server_error, false, "failed to open avatar file");
        return;
    }
    ofs.write(file_part.data.data(), static_cast<std::streamsize>(file_part.data.size()));
    ofs.close();
    if (!ofs.good()) {
        send_json_response(http::status::internal_server_error, false, "failed to write avatar file");
        return;
    }

    send_json_response(http::status::ok, true, "avatar uploaded", build_avatar_absolute_url(filename));
}

void http_static_session::on_write(beast::error_code ec)
{
    if (ec == http::error::end_of_stream) {
        ec = {};
    }
    if (ec) {
        std::cerr << "HTTP write error: " << ec.message() << std::endl;
    }
    response_.reset();
    beast::error_code ignored;
    socket_.shutdown(tcp::socket::shutdown_send, ignored);
    socket_.close(ignored);
}

} // namespace server
} // namespace qt_server
