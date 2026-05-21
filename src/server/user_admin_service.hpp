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

struct admin_overview_summary
{
    std::size_t total_users = 0U;
    std::size_t enabled_users = 0U;
    std::size_t disabled_users = 0U;
    std::size_t online_users = 0U;
    std::size_t recent_login_users = 0U;
    std::size_t recent_seen_users = 0U;
    std::vector<managed_user_record> recent_users;
};

struct admin_group_list_options
{
    std::string keyword;
    unsigned long long group_numeric_id = 0ULL;
    unsigned long long owner_user_id = 0ULL;
    std::size_t limit = 50U;
};

struct admin_conversation_list_options
{
    std::string keyword;
    std::string conversation_id;
    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    unsigned long long group_numeric_id = 0ULL;
    std::size_t limit = 50U;
};

struct admin_message_list_options
{
    std::size_t limit = 50U;
};

struct admin_chat_file_list_options
{
    std::string keyword;
    std::string conversation_id;
    std::string file_id;
    unsigned long long uploader_user_id = 0ULL;
    std::size_t limit = 50U;
};

struct admin_group_record
{
    std::string conversation_id;
    unsigned long long group_numeric_id = 0ULL;
    std::string name;
    std::string avatar_url;
    std::string notice;
    unsigned long long owner_user_id = 0ULL;
    unsigned long long owner_numeric_id = 0ULL;
    std::string owner_username;
    std::string owner_nickname;
    std::size_t member_count = 0U;
    std::string created_at;
    std::string updated_at;
    unsigned long long last_message_seq = 0ULL;
    std::string last_message_id;
    std::string last_message_sent_at;
};

struct admin_group_member_record
{
    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    std::string username;
    std::string nickname;
    std::string avatar_url;
    unsigned int status = 0U;
    bool is_online = false;
    std::string last_seen_at;
    unsigned int role = 0U;
    std::string mute_until;
};

struct admin_conversation_record
{
    std::string conversation_id;
    unsigned int conversation_type = 0U;
    unsigned long long group_numeric_id = 0ULL;
    std::string name;
    std::string avatar_url;
    std::string notice;
    unsigned long long owner_user_id = 0ULL;
    std::size_t member_count = 0U;
    std::string created_at;
    std::string updated_at;
    unsigned long long last_message_seq = 0ULL;
    std::string last_message_id;
    std::string last_message_sent_at;
    std::string participants_summary;
};

struct admin_message_record
{
    std::string conversation_id;
    std::string message_id;
    unsigned long long seq = 0ULL;
    unsigned long long message_type = 0ULL;
    std::string message_kind;
    std::string content_preview;
    std::string content_json;
    std::string file_id;
    std::string file_name;
    unsigned long long file_size_bytes = 0ULL;
    std::string sent_at;
    unsigned long long sender_user_id = 0ULL;
    unsigned long long sender_numeric_id = 0ULL;
    std::string sender_username;
    std::size_t receipt_total = 0U;
    std::size_t delivered_count = 0U;
    std::size_t pending_count = 0U;
};

struct admin_message_receipt_record
{
    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    std::string username;
    std::string nickname;
    bool delivered = false;
    std::string delivered_at;
};

struct admin_chat_file_record
{
    std::string file_id;
    std::string conversation_id;
    unsigned long long uploader_user_id = 0ULL;
    unsigned long long uploader_numeric_id = 0ULL;
    std::string uploader_username;
    std::string uploader_nickname;
    std::string original_name;
    std::string stored_name;
    std::string stored_relative_path;
    std::string content_type;
    std::string sha256;
    std::size_t size_bytes = 0U;
    bool attached = false;
    std::string bound_message_id;
    std::string created_at;
    std::string attached_at;
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
bool load_admin_overview(admin_overview_summary& summary,
                         user_admin_error& error);
bool list_admin_groups(const admin_group_list_options& options,
                       std::vector<admin_group_record>& groups,
                       user_admin_error& error);
bool load_admin_group_detail(const std::string& conversation_id,
                             admin_group_record& group,
                             std::vector<admin_group_member_record>& members,
                             std::vector<admin_message_record>& recent_messages,
                             user_admin_error& error);
bool list_admin_conversations(const admin_conversation_list_options& options,
                              std::vector<admin_conversation_record>& conversations,
                              user_admin_error& error);
bool list_admin_conversation_messages(const std::string& conversation_id,
                                      const admin_message_list_options& options,
                                      std::vector<admin_message_record>& messages,
                                      user_admin_error& error);
bool list_admin_message_receipts(const std::string& conversation_id,
                                 const std::string& message_id,
                                 std::vector<admin_message_receipt_record>& receipts,
                                 user_admin_error& error);
bool list_admin_chat_files(const admin_chat_file_list_options& options,
                           std::vector<admin_chat_file_record>& files,
                           user_admin_error& error);
bool load_admin_chat_file(const std::string& file_id,
                          admin_chat_file_record& file,
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
