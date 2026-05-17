#ifndef USER_ADMIN_SERVICE_HPP
#define USER_ADMIN_SERVICE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace qt_server {
namespace server {

enum class user_admin_error_code
{
    none = 0,
    unauthorized,
    validation,
    conflict,
    not_found,
    config,
    database
};

struct user_admin_error
{
    user_admin_error_code code = user_admin_error_code::none;
    std::string message;
    std::string debug;
};

struct managed_user_record
{
    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    std::string user_uuid;
    std::string username;
    std::string email;
    std::string phone;
    unsigned int status = 0U;
    std::string nickname;
    std::string avatar_url;
    std::string bio;
    bool is_online = false;
    std::string last_seen_at;
    std::string last_login_at;
    std::string created_at;
    std::string updated_at;
};

struct user_list_options
{
    std::string keyword;
    std::size_t limit = 100U;
    bool include_disabled = true;
};

struct create_user_request
{
    std::string username;
    std::string email;
    std::string phone;
    std::string password;
    std::string nickname;
    std::string avatar_url;
    std::string bio;
    unsigned int status = 1U;
};

struct update_user_request
{
    unsigned long long user_id = 0ULL;
    bool has_email = false;
    std::string email;
    bool has_phone = false;
    std::string phone;
    bool has_nickname = false;
    std::string nickname;
    bool has_avatar_url = false;
    std::string avatar_url;
    bool has_bio = false;
    std::string bio;
    bool has_status = false;
    unsigned int status = 1U;
};

struct admin_user_account
{
    unsigned long long admin_user_id = 0ULL;
    std::string username;
    std::string display_name;
    unsigned int status = 0U;
    std::string last_login_at;
    std::string created_at;
    std::string updated_at;
};

struct admin_login_result
{
    admin_user_account admin;
    std::string session_token;
    int session_ttl_seconds = 0;
};

bool list_managed_users(const user_list_options& options,
                        std::vector<managed_user_record>& users,
                        user_admin_error& error);
bool create_managed_user(const create_user_request& request,
                         managed_user_record& created_user,
                         user_admin_error& error);
bool update_managed_user(const update_user_request& request,
                         managed_user_record& updated_user,
                         user_admin_error& error);
bool reset_managed_user_password(unsigned long long user_id,
                                 const std::string& new_password,
                                 user_admin_error& error);

bool login_admin_user(const std::string& username,
                      const std::string& password,
                      admin_login_result& result,
                      user_admin_error& error);
bool validate_admin_session(const std::string& session_token,
                            admin_user_account& admin,
                            user_admin_error& error);
void logout_admin_session(const std::string& session_token);
std::string admin_session_cookie_name();
int admin_session_ttl_seconds();
std::string default_bootstrap_admin_username();
std::string default_bootstrap_admin_password();

} // namespace server
} // namespace qt_server

#endif // USER_ADMIN_SERVICE_HPP
