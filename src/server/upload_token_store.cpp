#include "upload_token_store.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <unordered_map>

namespace qt_server {
namespace server {

namespace {

struct token_entry
{
    unsigned long long user_id = 0ULL;
    std::string purpose;
    std::chrono::system_clock::time_point expires_at;
};

std::unordered_map<std::string, token_entry> g_upload_tokens;
std::mutex g_upload_tokens_mutex;

std::string now_plus_seconds_utc_iso8601(int ttl_seconds,
                                         std::chrono::system_clock::time_point& expires_at_out)
{
    expires_at_out = std::chrono::system_clock::now() + std::chrono::seconds(ttl_seconds);
    const std::time_t tt = std::chrono::system_clock::to_time_t(expires_at_out);
    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &tt);
#else
    gmtime_r(&tt, &utc_tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string random_hex_token(std::size_t byte_len)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 255);
    static const char* hex = "0123456789abcdef";

    std::string out;
    out.reserve(byte_len * 2U);
    for (std::size_t i = 0; i < byte_len; ++i) {
        const int b = dist(gen);
        out.push_back(hex[(b >> 4) & 0x0F]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

void cleanup_expired_locked(const std::chrono::system_clock::time_point now)
{
    for (auto it = g_upload_tokens.begin(); it != g_upload_tokens.end();) {
        if (it->second.expires_at <= now) {
            it = g_upload_tokens.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace

bool issue_upload_token(unsigned long long user_id,
                        const std::string& purpose,
                        int ttl_seconds,
                        std::string& out_token,
                        std::string& out_expires_at_utc)
{
    if (user_id == 0ULL || ttl_seconds <= 0 || purpose.empty()) {
        return false;
    }

    std::chrono::system_clock::time_point expires_at;
    out_expires_at_utc = now_plus_seconds_utc_iso8601(ttl_seconds, expires_at);
    out_token = random_hex_token(32U);

    std::lock_guard<std::mutex> lock(g_upload_tokens_mutex);
    cleanup_expired_locked(std::chrono::system_clock::now());
    g_upload_tokens[out_token] = token_entry{user_id, purpose, expires_at};
    return true;
}

bool validate_upload_token(const std::string& token,
                           const std::string& required_purpose,
                           unsigned long long& out_user_id,
                           std::string& error_message)
{
    error_message.clear();
    out_user_id = 0ULL;
    if (token.empty()) {
        error_message = "missing bearer token";
        return false;
    }

    std::lock_guard<std::mutex> lock(g_upload_tokens_mutex);
    const auto now = std::chrono::system_clock::now();
    cleanup_expired_locked(now);

    const auto it = g_upload_tokens.find(token);
    if (it == g_upload_tokens.end()) {
        error_message = "token invalid or expired";
        return false;
    }
    if (it->second.expires_at <= now) {
        g_upload_tokens.erase(it);
        error_message = "token expired";
        return false;
    }
    if (!required_purpose.empty() && it->second.purpose != required_purpose) {
        error_message = "token purpose mismatch";
        return false;
    }
    out_user_id = it->second.user_id;
    return true;
}

} // namespace server
} // namespace qt_server
