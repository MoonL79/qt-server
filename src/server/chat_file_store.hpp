#ifndef CHAT_FILE_STORE_HPP
#define CHAT_FILE_STORE_HPP

#include <cstddef>
#include <string>

namespace qt_server {
namespace server {

struct chat_file_record
{
    unsigned long long conversation_internal_id = 0ULL;
    unsigned long long uploader_user_id = 0ULL;
    std::string conversation_id;
    std::string file_id;
    std::string original_name;
    std::string stored_name;
    std::string stored_relative_path;
    std::string content_type;
    std::string sha256;
    std::size_t size_bytes = 0U;
    bool attached = false;
};

struct conversation_access
{
    unsigned long long internal_conversation_id = 0ULL;
    unsigned long long conversation_type = 0ULL;
    bool is_member = false;
};

bool resolve_conversation_access(const std::string& conversation_id,
                                 unsigned long long user_id,
                                 conversation_access& out_access,
                                 std::string& error_message,
                                 std::string& debug_output);

bool create_chat_file_record(const chat_file_record& record,
                             std::string& error_message,
                             std::string& debug_output);

bool load_chat_file_for_sender(const std::string& file_id,
                               unsigned long long uploader_user_id,
                               const std::string& conversation_id,
                               chat_file_record& out_record,
                               std::string& error_message,
                               std::string& debug_output);

bool bind_chat_file_to_message(const std::string& file_id,
                               unsigned long long uploader_user_id,
                               const std::string& conversation_id,
                               const std::string& message_id,
                               std::string& error_message,
                               std::string& debug_output);

bool load_chat_file_for_download(const std::string& file_id,
                                 unsigned long long requester_user_id,
                                 chat_file_record& out_record,
                                 std::string& error_message,
                                 std::string& debug_output);

} // namespace server
} // namespace qt_server

#endif // CHAT_FILE_STORE_HPP
