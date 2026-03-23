#ifndef UPLOAD_TOKEN_STORE_HPP
#define UPLOAD_TOKEN_STORE_HPP

#include <string>

namespace qt_server {
namespace server {

bool issue_upload_token(unsigned long long user_id,
                        const std::string& purpose,
                        int ttl_seconds,
                        std::string& out_token,
                        std::string& out_expires_at_utc);

bool validate_upload_token(const std::string& token,
                           const std::string& required_purpose,
                           unsigned long long& out_user_id,
                           std::string& error_message);

} // namespace server
} // namespace qt_server

#endif // UPLOAD_TOKEN_STORE_HPP
