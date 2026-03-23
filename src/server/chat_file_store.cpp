#include "chat_file_store.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

namespace qt_server {
namespace server {

namespace {

struct mysql_config
{
    std::string host;
    std::string port;
    std::string database;
    std::string user;
    std::string password;
};

std::string trim_copy(const std::string& input)
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

std::string getenv_or_default(const char* key, const char* fallback)
{
    const char* value = std::getenv(key);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return value;
}

mysql_config load_mysql_config()
{
    mysql_config cfg;
    cfg.host = getenv_or_default("QT_SERVER_MYSQL_HOST", "");
    cfg.port = getenv_or_default("QT_SERVER_MYSQL_PORT", "");
    cfg.database = getenv_or_default("QT_SERVER_MYSQL_DB", "");
    cfg.user = getenv_or_default("QT_SERVER_MYSQL_USER", "");
    cfg.password = getenv_or_default("QT_SERVER_MYSQL_PASSWORD", "");
    return cfg;
}

bool is_mysql_config_valid(const mysql_config& cfg, std::string& error_message)
{
    if (cfg.host.empty() || cfg.port.empty() || cfg.database.empty() || cfg.user.empty()) {
        error_message = "database config missing";
        return false;
    }
    error_message.clear();
    return true;
}

std::string shell_quote(const std::string& input)
{
    std::string out = "'";
    for (char ch : input) {
        if (ch == '\'') {
            out += "'\\''";
        } else {
            out += ch;
        }
    }
    out += "'";
    return out;
}

int normalize_pclose_code(int raw_code)
{
#if defined(_WIN32)
    return raw_code;
#else
    if (WIFEXITED(raw_code) != 0) {
        return WEXITSTATUS(raw_code);
    }
    return raw_code;
#endif
}

bool run_mysql_sql(const mysql_config& cfg,
                   const std::string& sql,
                   std::string& command_output,
                   int& exit_code)
{
    std::vector<std::string> args;
    args.push_back("mysql");
    args.push_back("--batch");
    args.push_back("--raw");
    args.push_back("--skip-column-names");
    args.push_back("--default-character-set=utf8mb4");
    args.push_back("-h");
    args.push_back(cfg.host);
    args.push_back("-P");
    args.push_back(cfg.port);
    args.push_back("-u");
    args.push_back(cfg.user);
    args.push_back("-D");
    args.push_back(cfg.database);
    args.push_back("-e");
    args.push_back(sql);

    const char* previous_pwd_env = std::getenv("MYSQL_PWD");
    const bool had_previous_pwd = (previous_pwd_env != nullptr);
    const std::string previous_pwd = had_previous_pwd ? std::string(previous_pwd_env) : std::string();
    if (!cfg.password.empty()) {
#if defined(_WIN32)
        _putenv_s("MYSQL_PWD", cfg.password.c_str());
#else
        setenv("MYSQL_PWD", cfg.password.c_str(), 1);
#endif
    }

    std::ostringstream cmd;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i != 0U) {
            cmd << " ";
        }
        cmd << shell_quote(args[i]);
    }
    cmd << " 2>&1";

#if defined(_WIN32)
    FILE* pipe = _popen(cmd.str().c_str(), "r");
#else
    FILE* pipe = popen(cmd.str().c_str(), "r");
#endif
    if (pipe == nullptr) {
        if (had_previous_pwd) {
#if defined(_WIN32)
            _putenv_s("MYSQL_PWD", previous_pwd.c_str());
#else
            setenv("MYSQL_PWD", previous_pwd.c_str(), 1);
#endif
        } else {
#if defined(_WIN32)
            _putenv_s("MYSQL_PWD", "");
#else
            unsetenv("MYSQL_PWD");
#endif
        }
        command_output = "failed to start mysql command";
        exit_code = -1;
        return false;
    }

    char buffer[512];
    command_output.clear();
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        command_output += buffer;
    }

#if defined(_WIN32)
    const int raw_code = _pclose(pipe);
#else
    const int raw_code = pclose(pipe);
#endif

    if (had_previous_pwd) {
#if defined(_WIN32)
        _putenv_s("MYSQL_PWD", previous_pwd.c_str());
#else
        setenv("MYSQL_PWD", previous_pwd.c_str(), 1);
#endif
    } else {
#if defined(_WIN32)
        _putenv_s("MYSQL_PWD", "");
#else
        unsetenv("MYSQL_PWD");
#endif
    }
    exit_code = normalize_pclose_code(raw_code);
    return exit_code == 0;
}

std::string sql_escape(const std::string& input)
{
    std::string out;
    out.reserve(input.size() * 2U);
    for (char ch : input) {
        if (ch == '\\') {
            out += "\\\\";
        } else if (ch == '\'') {
            out += "''";
        } else {
            out += ch;
        }
    }
    return out;
}

bool parse_unsigned_long_long(const std::string& input, unsigned long long& value)
{
    if (input.empty()) {
        return false;
    }
    for (char ch : input) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    std::istringstream iss(input);
    iss >> value;
    return !iss.fail();
}

std::vector<std::string> split_by_tab(const std::string& input)
{
    std::vector<std::string> parts;
    std::size_t begin = 0U;
    while (begin <= input.size()) {
        const std::size_t end = input.find('\t', begin);
        if (end == std::string::npos) {
            parts.push_back(input.substr(begin));
            break;
        }
        parts.push_back(input.substr(begin, end - begin));
        begin = end + 1U;
    }
    return parts;
}

std::vector<std::string> collect_non_empty_lines(const std::string& text)
{
    std::vector<std::string> lines;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

bool ensure_chat_file_schema(const mysql_config& cfg, std::string& error_message, std::string& debug_output)
{
    std::ostringstream sql;
    sql << "CREATE TABLE IF NOT EXISTS chat_files ("
        << "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        << "file_uuid VARCHAR(64) NOT NULL,"
        << "conversation_id BIGINT UNSIGNED NOT NULL,"
        << "conversation_uuid VARCHAR(64) NOT NULL,"
        << "uploader_user_id BIGINT UNSIGNED NOT NULL,"
        << "original_name VARCHAR(255) NOT NULL,"
        << "stored_name VARCHAR(255) NOT NULL,"
        << "stored_relative_path VARCHAR(512) NOT NULL,"
        << "size_bytes BIGINT UNSIGNED NOT NULL,"
        << "content_type VARCHAR(128) NOT NULL,"
        << "sha256 CHAR(64) NOT NULL,"
        << "status VARCHAR(32) NOT NULL,"
        << "bound_message_uuid VARCHAR(64) NULL,"
        << "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        << "attached_at DATETIME NULL DEFAULT NULL,"
        << "UNIQUE KEY uk_chat_files_uuid (file_uuid),"
        << "KEY idx_chat_files_conversation (conversation_id, created_at),"
        << "KEY idx_chat_files_download (file_uuid, conversation_id, uploader_user_id)"
        << ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), debug_output, exit_code)) {
        error_message = "failed to ensure chat_files table";
        return false;
    }
    error_message.clear();
    return true;
}

} // namespace

bool resolve_conversation_access(const std::string& conversation_id,
                                 unsigned long long user_id,
                                 conversation_access& out_access,
                                 std::string& error_message,
                                 std::string& debug_output)
{
    out_access = conversation_access{};
    error_message.clear();
    debug_output.clear();

    if (conversation_id.empty() || user_id == 0ULL) {
        error_message = "conversation access requires conversation_id and user_id";
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        error_message = config_error;
        return false;
    }
    if (!ensure_chat_file_schema(cfg, error_message, debug_output)) {
        return false;
    }

    std::ostringstream sql;
    sql << "SELECT c.id, c.type, "
        << "CASE WHEN EXISTS(SELECT 1 FROM conversation_members cm WHERE cm.conversation_id=c.id AND cm.user_id="
        << user_id << ") THEN 1 ELSE 0 END "
        << "FROM conversations c "
        << "WHERE c.conversation_uuid='" << sql_escape(conversation_id) << "' "
        << "LIMIT 1;";

    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), debug_output, exit_code)) {
        error_message = "conversation lookup failed in database";
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(debug_output);
    if (lines.empty()) {
        error_message = "conversation not found";
        return false;
    }
    const std::vector<std::string> cols = split_by_tab(trim_copy(lines.back()));
    if (cols.size() < 3U
        || !parse_unsigned_long_long(cols[0], out_access.internal_conversation_id)
        || !parse_unsigned_long_long(cols[1], out_access.conversation_type)) {
        error_message = "conversation lookup returned unexpected result";
        return false;
    }
    unsigned long long is_member = 0ULL;
    if (!parse_unsigned_long_long(cols[2], is_member)) {
        error_message = "conversation access lookup returned unexpected membership result";
        return false;
    }
    out_access.is_member = (is_member != 0ULL);
    return true;
}

bool create_chat_file_record(const chat_file_record& record,
                             std::string& error_message,
                             std::string& debug_output)
{
    error_message.clear();
    debug_output.clear();
    if (record.conversation_internal_id == 0ULL || record.uploader_user_id == 0ULL || record.file_id.empty()) {
        error_message = "chat file record missing required fields";
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        error_message = config_error;
        return false;
    }
    if (!ensure_chat_file_schema(cfg, error_message, debug_output)) {
        return false;
    }

    std::ostringstream sql;
    sql << "INSERT INTO chat_files ("
        << "file_uuid, conversation_id, conversation_uuid, uploader_user_id, "
        << "original_name, stored_name, stored_relative_path, size_bytes, content_type, sha256, status"
        << ") VALUES ("
        << "'" << sql_escape(record.file_id) << "', "
        << record.conversation_internal_id << ", "
        << "'" << sql_escape(record.conversation_id) << "', "
        << record.uploader_user_id << ", "
        << "'" << sql_escape(record.original_name) << "', "
        << "'" << sql_escape(record.stored_name) << "', "
        << "'" << sql_escape(record.stored_relative_path) << "', "
        << static_cast<unsigned long long>(record.size_bytes) << ", "
        << "'" << sql_escape(record.content_type) << "', "
        << "'" << sql_escape(record.sha256) << "', "
        << "'uploaded');";

    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), debug_output, exit_code)) {
        error_message = "failed to create chat file record";
        return false;
    }
    return true;
}

bool load_chat_file_for_sender(const std::string& file_id,
                               unsigned long long uploader_user_id,
                               const std::string& conversation_id,
                               chat_file_record& out_record,
                               std::string& error_message,
                               std::string& debug_output)
{
    out_record = chat_file_record{};
    error_message.clear();
    debug_output.clear();
    if (file_id.empty() || uploader_user_id == 0ULL || conversation_id.empty()) {
        error_message = "chat file lookup requires file_id, uploader_user_id and conversation_id";
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        error_message = config_error;
        return false;
    }
    if (!ensure_chat_file_schema(cfg, error_message, debug_output)) {
        return false;
    }

    std::ostringstream sql;
    sql << "SELECT conversation_id, conversation_uuid, uploader_user_id, original_name, stored_name, "
        << "stored_relative_path, size_bytes, content_type, sha256, "
        << "CASE WHEN bound_message_uuid IS NULL OR bound_message_uuid='' THEN 0 ELSE 1 END "
        << "FROM chat_files "
        << "WHERE file_uuid='" << sql_escape(file_id) << "' "
        << "AND uploader_user_id=" << uploader_user_id << " "
        << "AND conversation_uuid='" << sql_escape(conversation_id) << "' "
        << "AND status IN ('uploaded', 'attached') "
        << "LIMIT 1;";

    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), debug_output, exit_code)) {
        error_message = "chat file lookup failed in database";
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(debug_output);
    if (lines.empty()) {
        error_message = "chat file not found";
        return false;
    }
    const std::vector<std::string> cols = split_by_tab(trim_copy(lines.back()));
    unsigned long long size_bytes = 0ULL;
    unsigned long long attached = 0ULL;
    if (cols.size() < 10U
        || !parse_unsigned_long_long(cols[0], out_record.conversation_internal_id)
        || !parse_unsigned_long_long(cols[2], out_record.uploader_user_id)
        || !parse_unsigned_long_long(cols[6], size_bytes)
        || !parse_unsigned_long_long(cols[9], attached)) {
        error_message = "chat file lookup returned unexpected result";
        return false;
    }

    out_record.conversation_id = cols[1];
    out_record.file_id = file_id;
    out_record.original_name = cols[3];
    out_record.stored_name = cols[4];
    out_record.stored_relative_path = cols[5];
    out_record.size_bytes = static_cast<std::size_t>(size_bytes);
    out_record.content_type = cols[7];
    out_record.sha256 = cols[8];
    out_record.attached = (attached != 0ULL);
    return true;
}

bool bind_chat_file_to_message(const std::string& file_id,
                               unsigned long long uploader_user_id,
                               const std::string& conversation_id,
                               const std::string& message_id,
                               std::string& error_message,
                               std::string& debug_output)
{
    error_message.clear();
    debug_output.clear();
    if (file_id.empty() || uploader_user_id == 0ULL || conversation_id.empty() || message_id.empty()) {
        error_message = "chat file bind requires file_id, uploader_user_id, conversation_id and message_id";
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        error_message = config_error;
        return false;
    }
    if (!ensure_chat_file_schema(cfg, error_message, debug_output)) {
        return false;
    }

    std::ostringstream sql;
    sql << "UPDATE chat_files "
        << "SET bound_message_uuid='" << sql_escape(message_id) << "', "
        << "status='attached', attached_at=NOW() "
        << "WHERE file_uuid='" << sql_escape(file_id) << "' "
        << "AND uploader_user_id=" << uploader_user_id << " "
        << "AND conversation_uuid='" << sql_escape(conversation_id) << "' "
        << "AND (bound_message_uuid IS NULL OR bound_message_uuid=''); "
        << "SELECT ROW_COUNT();";

    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), debug_output, exit_code)) {
        error_message = "failed to bind chat file to message";
        return false;
    }
    const std::vector<std::string> lines = collect_non_empty_lines(debug_output);
    if (lines.empty()) {
        error_message = "chat file bind missing row count";
        return false;
    }
    unsigned long long updated_rows = 0ULL;
    if (!parse_unsigned_long_long(trim_copy(lines.back()), updated_rows) || updated_rows == 0ULL) {
        error_message = "chat file already attached or unavailable";
        return false;
    }
    return true;
}

bool load_chat_file_for_download(const std::string& file_id,
                                 unsigned long long requester_user_id,
                                 chat_file_record& out_record,
                                 std::string& error_message,
                                 std::string& debug_output)
{
    out_record = chat_file_record{};
    error_message.clear();
    debug_output.clear();
    if (file_id.empty() || requester_user_id == 0ULL) {
        error_message = "chat file download requires file_id and requester_user_id";
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        error_message = config_error;
        return false;
    }
    if (!ensure_chat_file_schema(cfg, error_message, debug_output)) {
        return false;
    }

    std::ostringstream sql;
    sql << "SELECT cf.conversation_id, cf.conversation_uuid, cf.uploader_user_id, cf.original_name, "
        << "cf.stored_name, cf.stored_relative_path, cf.size_bytes, cf.content_type, cf.sha256, "
        << "CASE WHEN EXISTS(SELECT 1 FROM conversation_members cm "
        << "WHERE cm.conversation_id=cf.conversation_id AND cm.user_id=" << requester_user_id
        << ") THEN 1 ELSE 0 END "
        << "FROM chat_files cf "
        << "WHERE cf.file_uuid='" << sql_escape(file_id) << "' "
        << "AND cf.status='attached' "
        << "LIMIT 1;";

    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), debug_output, exit_code)) {
        error_message = "chat file download lookup failed in database";
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(debug_output);
    if (lines.empty()) {
        error_message = "chat file not found";
        return false;
    }
    const std::vector<std::string> cols = split_by_tab(trim_copy(lines.back()));
    unsigned long long size_bytes = 0ULL;
    unsigned long long is_member = 0ULL;
    if (cols.size() < 10U
        || !parse_unsigned_long_long(cols[0], out_record.conversation_internal_id)
        || !parse_unsigned_long_long(cols[2], out_record.uploader_user_id)
        || !parse_unsigned_long_long(cols[6], size_bytes)
        || !parse_unsigned_long_long(cols[9], is_member)) {
        error_message = "chat file download lookup returned unexpected result";
        return false;
    }
    if (is_member == 0ULL) {
        error_message = "requester is not a conversation member";
        return false;
    }

    out_record.conversation_id = cols[1];
    out_record.file_id = file_id;
    out_record.original_name = cols[3];
    out_record.stored_name = cols[4];
    out_record.stored_relative_path = cols[5];
    out_record.size_bytes = static_cast<std::size_t>(size_bytes);
    out_record.content_type = cols[7];
    out_record.sha256 = cols[8];
    out_record.attached = true;
    return true;
}

} // namespace server
} // namespace qt_server
