#include "user_admin_service.hpp"

#include <boost/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <random>
#include <sstream>
#include <unordered_map>
#include <vector>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

namespace qt_server {
namespace server {

namespace json = boost::json;

std::string default_bootstrap_admin_username();
std::string default_bootstrap_admin_password();
int admin_session_ttl_seconds();

namespace {

struct mysql_config
{
    std::string host;
    std::string port;
    std::string database;
    std::string user;
    std::string password;
};

struct admin_session_entry
{
    unsigned long long admin_user_id = 0ULL;
    std::chrono::system_clock::time_point expires_at;
};

std::mutex g_admin_sessions_mutex;
std::unordered_map<std::string, admin_session_entry> g_admin_sessions;

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

std::string to_lower_copy(const std::string& input)
{
    std::string lowered = input;
    for (char& ch : lowered) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return lowered;
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

std::string mysql_sanitized_sql(const std::string& expr, const std::string& fallback_sql)
{
    return "REPLACE(REPLACE(REPLACE(COALESCE("
        + expr
        + ", "
        + fallback_sql
        + "), CHAR(13), ' '), CHAR(10), ' '), CHAR(9), ' ')";
}

std::string mysql_text_sql(const std::string& expr)
{
    return mysql_sanitized_sql(expr, "''");
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

bool parse_unsigned_long_long(const std::string& input, unsigned long long& value)
{
    value = 0ULL;
    const std::string trimmed = trim_copy(input);
    if (trimmed.empty()) {
        return false;
    }
    for (char ch : trimmed) {
        if (std::isdigit(static_cast<unsigned char>(ch)) == 0) {
            return false;
        }
    }
    std::istringstream iss(trimmed);
    iss >> value;
    return !iss.fail();
}

std::vector<std::string> split_by_tab(const std::string& line)
{
    std::vector<std::string> cols;
    std::string current;
    for (char ch : line) {
        if (ch == '\t') {
            cols.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    cols.push_back(current);
    return cols;
}

std::vector<std::string> collect_non_empty_lines(const std::string& text)
{
    std::vector<std::string> lines;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        std::string normalized = line;
        if (!normalized.empty() && normalized.back() == '\r') {
            normalized.pop_back();
        }
        if (!trim_copy(normalized).empty()) {
            lines.push_back(normalized);
        }
    }
    return lines;
}

std::string last_non_empty_line(const std::string& text)
{
    const std::vector<std::string> lines = collect_non_empty_lines(text);
    if (lines.empty()) {
        return "";
    }
    return lines.back();
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

bool is_mysql_config_valid(const mysql_config& cfg, std::string& reason)
{
    if (cfg.host.empty()) {
        reason = "missing QT_SERVER_MYSQL_HOST";
        return false;
    }
    if (cfg.port.empty()) {
        reason = "missing QT_SERVER_MYSQL_PORT";
        return false;
    }
    if (cfg.database.empty()) {
        reason = "missing QT_SERVER_MYSQL_DB";
        return false;
    }
    if (cfg.user.empty()) {
        reason = "missing QT_SERVER_MYSQL_USER";
        return false;
    }
    reason.clear();
    return true;
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

    command_output.clear();
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        command_output += buffer;
    }

#if defined(_WIN32)
    const int raw_code = _pclose(pipe);
#else
    const int raw_code = pclose(pipe);
#endif
    exit_code = normalize_pclose_code(raw_code);

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

    return exit_code == 0;
}

bool is_valid_username(const std::string& username)
{
    if (username.size() < 3U || username.size() > 32U) {
        return false;
    }
    for (char ch : username) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_') {
            return false;
        }
    }
    return true;
}

bool is_valid_email(const std::string& email)
{
    const std::size_t at = email.find('@');
    if (at == std::string::npos || at == 0U || at + 1U >= email.size()) {
        return false;
    }
    const std::size_t dot = email.find('.', at + 1U);
    return dot != std::string::npos && dot + 1U < email.size();
}

bool is_strong_password(const std::string& password)
{
    if (password.size() < 8U || password.size() > 64U) {
        return false;
    }
    bool has_lower = false;
    bool has_upper = false;
    bool has_digit = false;
    for (char ch : password) {
        const unsigned char uc = static_cast<unsigned char>(ch);
        if (std::islower(uc) != 0) {
            has_lower = true;
        } else if (std::isupper(uc) != 0) {
            has_upper = true;
        } else if (std::isdigit(uc) != 0) {
            has_digit = true;
        }
    }
    return has_lower && has_upper && has_digit;
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return oss.str();
}

int hex_nibble(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

bool hex_to_bytes(const std::string& hex, std::vector<unsigned char>& out)
{
    out.clear();
    if ((hex.size() % 2U) != 0U) {
        return false;
    }
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0U; i < hex.size(); i += 2U) {
        const int high = hex_nibble(hex[i]);
        const int low = hex_nibble(hex[i + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        out.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return true;
}

bool constant_time_equal(const std::vector<unsigned char>& lhs,
                         const std::vector<unsigned char>& rhs)
{
    if (lhs.size() != rhs.size()) {
        return false;
    }
    unsigned char diff = 0U;
    for (std::size_t i = 0U; i < lhs.size(); ++i) {
        diff |= static_cast<unsigned char>(lhs[i] ^ rhs[i]);
    }
    return diff == 0U;
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data)
{
    typedef std::uint32_t u32;
    typedef std::uint64_t u64;
    static const u32 k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    auto rotr = [](u32 value, unsigned int bits) {
        return (value >> bits) | (value << (32U - bits));
    };

    std::vector<unsigned char> bytes = data;
    const u64 bit_length = static_cast<u64>(bytes.size()) * 8ULL;
    bytes.push_back(0x80U);
    while ((bytes.size() % 64U) != 56U) {
        bytes.push_back(0x00U);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<unsigned char>((bit_length >> shift) & 0xffULL));
    }

    u32 h0 = 0x6a09e667U;
    u32 h1 = 0xbb67ae85U;
    u32 h2 = 0x3c6ef372U;
    u32 h3 = 0xa54ff53aU;
    u32 h4 = 0x510e527fU;
    u32 h5 = 0x9b05688cU;
    u32 h6 = 0x1f83d9abU;
    u32 h7 = 0x5be0cd19U;

    for (std::size_t chunk = 0U; chunk < bytes.size(); chunk += 64U) {
        u32 w[64];
        for (std::size_t i = 0U; i < 16U; ++i) {
            const std::size_t offset = chunk + (i * 4U);
            w[i] = (static_cast<u32>(bytes[offset]) << 24U)
                 | (static_cast<u32>(bytes[offset + 1U]) << 16U)
                 | (static_cast<u32>(bytes[offset + 2U]) << 8U)
                 | static_cast<u32>(bytes[offset + 3U]);
        }
        for (std::size_t i = 16U; i < 64U; ++i) {
            const u32 s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
            const u32 s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
            w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
        }

        u32 a = h0;
        u32 b = h1;
        u32 c = h2;
        u32 d = h3;
        u32 e = h4;
        u32 f = h5;
        u32 g = h6;
        u32 h = h7;

        for (std::size_t i = 0U; i < 64U; ++i) {
            const u32 s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
            const u32 ch = (e & f) ^ ((~e) & g);
            const u32 temp1 = h + s1 + ch + k[i] + w[i];
            const u32 s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
            const u32 maj = (a & b) ^ (a & c) ^ (b & c);
            const u32 temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    std::vector<unsigned char> digest(32U, 0U);
    const u32 hs[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (std::size_t i = 0U; i < 8U; ++i) {
        digest[i * 4U] = static_cast<unsigned char>((hs[i] >> 24U) & 0xffU);
        digest[i * 4U + 1U] = static_cast<unsigned char>((hs[i] >> 16U) & 0xffU);
        digest[i * 4U + 2U] = static_cast<unsigned char>((hs[i] >> 8U) & 0xffU);
        digest[i * 4U + 3U] = static_cast<unsigned char>(hs[i] & 0xffU);
    }
    return digest;
}

std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& data)
{
    static const std::size_t kBlockSize = 64U;
    std::vector<unsigned char> normalized_key = key;
    if (normalized_key.size() > kBlockSize) {
        normalized_key = sha256(normalized_key);
    }
    normalized_key.resize(kBlockSize, 0U);

    std::vector<unsigned char> o_key_pad(kBlockSize, 0U);
    std::vector<unsigned char> i_key_pad(kBlockSize, 0U);
    for (std::size_t i = 0U; i < kBlockSize; ++i) {
        o_key_pad[i] = static_cast<unsigned char>(normalized_key[i] ^ 0x5cU);
        i_key_pad[i] = static_cast<unsigned char>(normalized_key[i] ^ 0x36U);
    }

    std::vector<unsigned char> inner = i_key_pad;
    inner.insert(inner.end(), data.begin(), data.end());
    const std::vector<unsigned char> inner_hash = sha256(inner);

    std::vector<unsigned char> outer = o_key_pad;
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return sha256(outer);
}

std::vector<unsigned char> pbkdf2_hmac_sha256(const std::vector<unsigned char>& password,
                                              const std::vector<unsigned char>& salt,
                                              int iterations,
                                              std::size_t dk_len)
{
    const std::size_t hash_len = 32U;
    const std::size_t block_count = (dk_len + hash_len - 1U) / hash_len;
    std::vector<unsigned char> derived;
    derived.reserve(block_count * hash_len);

    for (std::size_t block = 1U; block <= block_count; ++block) {
        std::vector<unsigned char> salt_block = salt;
        salt_block.push_back(static_cast<unsigned char>((block >> 24U) & 0xffU));
        salt_block.push_back(static_cast<unsigned char>((block >> 16U) & 0xffU));
        salt_block.push_back(static_cast<unsigned char>((block >> 8U) & 0xffU));
        salt_block.push_back(static_cast<unsigned char>(block & 0xffU));

        std::vector<unsigned char> u = hmac_sha256(password, salt_block);
        std::vector<unsigned char> t = u;
        for (int i = 1; i < iterations; ++i) {
            u = hmac_sha256(password, u);
            for (std::size_t j = 0U; j < hash_len; ++j) {
                t[j] ^= u[j];
            }
        }
        derived.insert(derived.end(), t.begin(), t.end());
    }

    derived.resize(dk_len);
    return derived;
}

std::vector<unsigned char> secure_random_bytes(std::size_t len)
{
    std::vector<unsigned char> out(len, 0U);
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.good()) {
        urandom.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(len));
        if (urandom.gcount() == static_cast<std::streamsize>(len)) {
            return out;
        }
    }

    std::random_device rd;
    for (std::size_t i = 0U; i < len; ++i) {
        out[i] = static_cast<unsigned char>(rd() & 0xffU);
    }
    return out;
}

std::string hash_password_for_storage(const std::string& plain_password)
{
    const int iterations = 210000;
    const std::vector<unsigned char> salt = secure_random_bytes(16U);
    const std::vector<unsigned char> password_bytes(plain_password.begin(), plain_password.end());
    const std::vector<unsigned char> dk = pbkdf2_hmac_sha256(password_bytes, salt, iterations, 32U);
    std::ostringstream oss;
    oss << "pbkdf2_sha256$" << iterations << "$" << bytes_to_hex(salt) << "$" << bytes_to_hex(dk);
    return oss.str();
}

bool verify_password_against_storage(const std::string& plain_password,
                                     const std::string& stored_hash)
{
    const std::string prefix = "pbkdf2_sha256$";
    if (stored_hash.rfind(prefix, 0U) != 0U) {
        return false;
    }

    const std::string body = stored_hash.substr(prefix.size());
    const std::size_t p1 = body.find('$');
    const std::size_t p2 = (p1 == std::string::npos) ? std::string::npos : body.find('$', p1 + 1U);
    if (p1 == std::string::npos || p2 == std::string::npos) {
        return false;
    }

    const std::string iterations_text = body.substr(0U, p1);
    const std::string salt_hex = body.substr(p1 + 1U, p2 - (p1 + 1U));
    const std::string digest_hex = body.substr(p2 + 1U);
    if (iterations_text.empty() || salt_hex.empty() || digest_hex.empty()) {
        return false;
    }

    int iterations = 0;
    std::istringstream iter_stream(iterations_text);
    iter_stream >> iterations;
    if (iter_stream.fail() || iterations <= 0) {
        return false;
    }

    std::vector<unsigned char> salt;
    std::vector<unsigned char> stored_digest;
    if (!hex_to_bytes(salt_hex, salt) || !hex_to_bytes(digest_hex, stored_digest) || stored_digest.empty()) {
        return false;
    }

    const std::vector<unsigned char> password_bytes(plain_password.begin(), plain_password.end());
    const std::vector<unsigned char> computed = pbkdf2_hmac_sha256(password_bytes,
                                                                   salt,
                                                                   iterations,
                                                                   stored_digest.size());
    return constant_time_equal(stored_digest, computed);
}

std::string generate_uuid_v4_like()
{
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<unsigned int> dist(0U, 15U);
    static const char* hex = "0123456789abcdef";

    std::string uuid(36U, '0');
    const int dash_positions[] = {8, 13, 18, 23};
    for (int pos : dash_positions) {
        uuid[static_cast<std::size_t>(pos)] = '-';
    }
    for (std::size_t i = 0U; i < uuid.size(); ++i) {
        if (uuid[i] == '-') {
            continue;
        }
        uuid[i] = hex[dist(gen)];
    }
    uuid[14] = '4';
    uuid[19] = hex[(dist(gen) & 0x3U) | 0x8U];
    return uuid;
}

void set_error(user_admin_error& error,
               user_admin_error_code code,
               const std::string& message,
               const std::string& debug = std::string())
{
    error.code = code;
    error.message = message;
    error.debug = debug;
}

std::string default_bootstrap_admin_display_name()
{
    return "系统管理员";
}

std::string read_env_string_or_default(const char* key, const std::string& fallback)
{
    const char* value = std::getenv(key);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return value;
}

std::string make_admin_session_token()
{
    return bytes_to_hex(secure_random_bytes(24U));
}

void prune_expired_admin_sessions_locked()
{
    const auto now = std::chrono::system_clock::now();
    for (auto it = g_admin_sessions.begin(); it != g_admin_sessions.end(); ) {
        if (it->second.expires_at <= now) {
            it = g_admin_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

std::string build_admin_select_sql()
{
    std::ostringstream sql;
    sql << "SELECT "
        << "id, "
        << "username, "
        << "display_name, "
        << "password_hash, "
        << "status, "
        << "COALESCE(DATE_FORMAT(last_login_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s'), '') "
        << "FROM admin_users ";
    return sql.str();
}

bool parse_admin_user_cols(const std::vector<std::string>& cols,
                           admin_user_account& admin,
                           std::string* password_hash = nullptr)
{
    if (cols.size() < 8U) {
        return false;
    }

    unsigned long long admin_user_id = 0ULL;
    unsigned long long status = 0ULL;
    if (!parse_unsigned_long_long(cols[0], admin_user_id)
        || !parse_unsigned_long_long(cols[4], status)) {
        return false;
    }

    admin.admin_user_id = admin_user_id;
    admin.username = (cols[1] == "\\N") ? "" : cols[1];
    admin.display_name = (cols[2] == "\\N") ? "" : cols[2];
    admin.status = static_cast<unsigned int>(status);
    admin.last_login_at = (cols[5] == "\\N") ? "" : cols[5];
    admin.created_at = (cols[6] == "\\N") ? "" : cols[6];
    admin.updated_at = (cols[7] == "\\N") ? "" : cols[7];
    if (password_hash != nullptr) {
        *password_hash = (cols[3] == "\\N") ? "" : cols[3];
    }
    return true;
}

bool ensure_admin_users_bootstrap(const mysql_config& cfg,
                                  user_admin_error& error)
{
    const std::string bootstrap_username = trim_copy(read_env_string_or_default("QT_SERVER_ADMIN_BOOTSTRAP_USERNAME",
                                                                                 default_bootstrap_admin_username()));
    const std::string bootstrap_password = read_env_string_or_default("QT_SERVER_ADMIN_BOOTSTRAP_PASSWORD",
                                                                      default_bootstrap_admin_password());
    const std::string bootstrap_display_name = trim_copy(read_env_string_or_default("QT_SERVER_ADMIN_BOOTSTRAP_DISPLAY_NAME",
                                                                                     default_bootstrap_admin_display_name()));

    if (!is_valid_username(bootstrap_username)) {
        set_error(error,
                  user_admin_error_code::config,
                  "invalid bootstrap admin username",
                  "QT_SERVER_ADMIN_BOOTSTRAP_USERNAME must match [A-Za-z0-9_], length 3~32");
        return false;
    }
    if (!is_strong_password(bootstrap_password)) {
        set_error(error,
                  user_admin_error_code::config,
                  "invalid bootstrap admin password",
                  "QT_SERVER_ADMIN_BOOTSTRAP_PASSWORD must be 8~64 and include upper/lower letters and digits");
        return false;
    }
    if (bootstrap_display_name.empty() || bootstrap_display_name.size() > 64U) {
        set_error(error,
                  user_admin_error_code::config,
                  "invalid bootstrap admin display_name",
                  "QT_SERVER_ADMIN_BOOTSTRAP_DISPLAY_NAME length must be 1~64");
        return false;
    }

    const std::string bootstrap_hash = hash_password_for_storage(bootstrap_password);
    std::ostringstream sql;
    sql << "CREATE TABLE IF NOT EXISTS admin_users ("
        << "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        << "username VARCHAR(64) NOT NULL,"
        << "display_name VARCHAR(64) NOT NULL,"
        << "password_hash VARCHAR(255) NOT NULL,"
        << "status TINYINT UNSIGNED NOT NULL DEFAULT 1,"
        << "last_login_at DATETIME NULL,"
        << "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        << "updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
        << "PRIMARY KEY (id),"
        << "UNIQUE KEY uk_admin_users_username (username),"
        << "KEY idx_admin_users_status (status)"
        << ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci; "
        << "INSERT INTO admin_users (username, display_name, password_hash, status, created_at, updated_at) "
        << "SELECT '"
        << sql_escape(bootstrap_username) << "', '"
        << sql_escape(bootstrap_display_name) << "', '"
        << sql_escape(bootstrap_hash) << "', 1, NOW(), NOW() "
        << "FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM admin_users LIMIT 1);";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to prepare admin_users", debug.str());
        return false;
    }
    return true;
}

bool load_admin_user_by_id(const mysql_config& cfg,
                           unsigned long long admin_user_id,
                           admin_user_account& admin,
                           std::string* password_hash,
                           user_admin_error& error)
{
    std::ostringstream sql;
    sql << build_admin_select_sql()
        << "WHERE id=" << admin_user_id << " "
        << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to query admin user", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        set_error(error, user_admin_error_code::not_found, "admin user not found");
        return false;
    }

    if (!parse_admin_user_cols(split_by_tab(lines.back()), admin, password_hash)) {
        set_error(error, user_admin_error_code::database, "failed to parse admin user row", trim_copy(command_output));
        return false;
    }
    return true;
}

bool load_admin_user_by_username(const mysql_config& cfg,
                                 const std::string& username,
                                 admin_user_account& admin,
                                 std::string& password_hash,
                                 user_admin_error& error)
{
    std::ostringstream sql;
    sql << build_admin_select_sql()
        << "WHERE username='" << sql_escape(username) << "' "
        << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to query admin user", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        set_error(error, user_admin_error_code::unauthorized, "invalid admin username or password");
        return false;
    }

    if (!parse_admin_user_cols(split_by_tab(lines.back()), admin, &password_hash)) {
        set_error(error, user_admin_error_code::database, "failed to parse admin user row", trim_copy(command_output));
        return false;
    }
    return true;
}

bool parse_managed_user_cols(const std::vector<std::string>& cols,
                             managed_user_record& user)
{
    if (cols.size() < 15U) {
        return false;
    }

    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    unsigned long long status = 0ULL;
    unsigned long long is_online = 0ULL;
    if (!parse_unsigned_long_long(cols[0], user_id)
        || !parse_unsigned_long_long(cols[1], numeric_id)
        || !parse_unsigned_long_long(cols[5], status)
        || !parse_unsigned_long_long(cols[10], is_online)) {
        return false;
    }

    user.user_id = user_id;
    user.numeric_id = numeric_id;
    user.username = (cols[2] == "\\N") ? "" : cols[2];
    user.email = (cols[3] == "\\N") ? "" : cols[3];
    user.phone = (cols[4] == "\\N") ? "" : cols[4];
    user.status = static_cast<unsigned int>(status);
    user.user_uuid = (cols[6] == "\\N") ? "" : cols[6];
    user.nickname = (cols[7] == "\\N") ? "" : cols[7];
    user.avatar_url = (cols[8] == "\\N") ? "" : cols[8];
    user.bio = (cols[9] == "\\N") ? "" : cols[9];
    user.is_online = (is_online != 0ULL);
    user.last_seen_at = (cols[11] == "\\N") ? "" : cols[11];
    user.last_login_at = (cols[12] == "\\N") ? "" : cols[12];
    user.created_at = (cols[13] == "\\N") ? "" : cols[13];
    user.updated_at = (cols[14] == "\\N") ? "" : cols[14];
    return true;
}

std::string build_user_select_sql()
{
    std::ostringstream sql;
    sql << "SELECT "
        << "u.id, "
        << "COALESCE(u.numeric_id, 0), "
        << mysql_text_sql("u.username") << ", "
        << mysql_text_sql("u.email") << ", "
        << mysql_text_sql("u.phone") << ", "
        << "u.status, "
        << mysql_text_sql("p.user_uuid") << ", "
        << mysql_text_sql("p.nickname") << ", "
        << mysql_text_sql("p.avatar_url") << ", "
        << mysql_text_sql("p.bio") << ", "
        << "COALESCE(p.is_online, 0), "
        << "COALESCE(DATE_FORMAT(p.last_seen_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(u.last_login_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(u.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(u.updated_at, '%Y-%m-%d %H:%i:%s'), '') "
        << "FROM user_data u "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL ";
    return sql.str();
}

bool load_managed_user_by_id(unsigned long long user_id,
                             managed_user_record& user,
                             user_admin_error& error)
{
    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    std::ostringstream sql;
    sql << build_user_select_sql()
        << "WHERE u.id=" << user_id << " "
        << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to query user", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        set_error(error, user_admin_error_code::not_found, "user not found");
        return false;
    }

    if (!parse_managed_user_cols(split_by_tab(lines.back()), user)) {
        set_error(error, user_admin_error_code::database, "failed to parse user row", trim_copy(command_output));
        return false;
    }
    return true;
}

bool validate_common_user_fields(const std::string& email,
                                 const std::string& phone,
                                 const std::string& nickname,
                                 const std::string& avatar_url,
                                 const std::string& bio,
                                 unsigned int status,
                                 user_admin_error& error)
{
    if (email.empty() || email.size() > 128U || !is_valid_email(email)) {
        set_error(error, user_admin_error_code::validation, "email must be a valid address with max length 128");
        return false;
    }
    if (phone.size() > 32U) {
        set_error(error, user_admin_error_code::validation, "phone length must be <= 32");
        return false;
    }
    if (nickname.empty() || nickname.size() > 64U) {
        set_error(error, user_admin_error_code::validation, "nickname length must be 1~64");
        return false;
    }
    if (avatar_url.size() > 255U) {
        set_error(error, user_admin_error_code::validation, "avatar_url length must be <= 255");
        return false;
    }
    if (bio.size() > 255U) {
        set_error(error, user_admin_error_code::validation, "bio length must be <= 255");
        return false;
    }
    if (status != 0U && status != 1U) {
        set_error(error, user_admin_error_code::validation, "status must be 0 or 1");
        return false;
    }
    return true;
}

std::string json_string_or_empty(const json::object& obj, const char* field)
{
    const auto it = obj.find(field);
    if (it == obj.end() || !it->value().is_string()) {
        return "";
    }
    return std::string(it->value().as_string().c_str());
}

std::string truncate_text(const std::string& input, std::size_t max_len)
{
    if (input.size() <= max_len) {
        return input;
    }
    if (max_len <= 3U) {
        return input.substr(0U, max_len);
    }
    return input.substr(0U, max_len - 3U) + "...";
}

void summarize_message_content(unsigned long long message_type,
                               const std::string& content_json,
                               std::string& message_kind,
                               std::string& content_preview,
                               std::string& file_id,
                               std::string& file_name,
                               unsigned long long& file_size_bytes)
{
    message_kind = "unknown";
    content_preview = truncate_text(content_json, 160U);
    file_id.clear();
    file_name.clear();
    file_size_bytes = 0ULL;

    json::error_code ec;
    json::value raw = json::parse(content_json.empty() ? "{}" : content_json, ec);
    if (ec || !raw.is_object()) {
        return;
    }

    const json::object& obj = raw.as_object();
    if (message_type == 1ULL) {
        message_kind = "text";
        const std::string text = json_string_or_empty(obj, "text");
        content_preview = text.empty() ? "(空文本消息)" : truncate_text(text, 160U);
        return;
    }

    if (message_type == 2ULL) {
        message_kind = "file";
        file_id = json_string_or_empty(obj, "file_id");
        file_name = json_string_or_empty(obj, "original_name");
        if (file_name.empty()) {
            file_name = json_string_or_empty(obj, "stored_name");
        }
        const auto size_it = obj.find("size_bytes");
        if (size_it != obj.end()) {
            if (size_it->value().is_uint64()) {
                file_size_bytes = size_it->value().as_uint64();
            } else if (size_it->value().is_int64() && size_it->value().as_int64() > 0) {
                file_size_bytes = static_cast<unsigned long long>(size_it->value().as_int64());
            } else if (size_it->value().is_string()) {
                parse_unsigned_long_long(std::string(size_it->value().as_string().c_str()), file_size_bytes);
            }
        }
        std::ostringstream preview;
        preview << "文件";
        if (!file_name.empty()) {
            preview << ": " << file_name;
        }
        if (file_size_bytes > 0ULL) {
            preview << " (" << file_size_bytes << " B)";
        }
        content_preview = preview.str();
        return;
    }
}

bool parse_admin_group_cols(const std::vector<std::string>& cols,
                            admin_group_record& group)
{
    if (cols.size() < 15U) {
        return false;
    }

    unsigned long long group_numeric_id = 0ULL;
    unsigned long long owner_user_id = 0ULL;
    unsigned long long owner_numeric_id = 0ULL;
    unsigned long long member_count = 0ULL;
    unsigned long long last_message_seq = 0ULL;
    if (!parse_unsigned_long_long(cols[1], group_numeric_id)
        || !parse_unsigned_long_long(cols[5], owner_user_id)
        || !parse_unsigned_long_long(cols[6], owner_numeric_id)
        || !parse_unsigned_long_long(cols[9], member_count)
        || !parse_unsigned_long_long(cols[12], last_message_seq)) {
        return false;
    }

    group.conversation_id = (cols[0] == "\\N") ? "" : cols[0];
    group.group_numeric_id = group_numeric_id;
    group.name = (cols[2] == "\\N") ? "" : cols[2];
    group.avatar_url = (cols[3] == "\\N") ? "" : cols[3];
    group.notice = (cols[4] == "\\N") ? "" : cols[4];
    group.owner_user_id = owner_user_id;
    group.owner_numeric_id = owner_numeric_id;
    group.owner_username = (cols[7] == "\\N") ? "" : cols[7];
    group.owner_nickname = (cols[8] == "\\N") ? "" : cols[8];
    group.member_count = static_cast<std::size_t>(member_count);
    group.created_at = (cols[10] == "\\N") ? "" : cols[10];
    group.updated_at = (cols[11] == "\\N") ? "" : cols[11];
    group.last_message_seq = last_message_seq;
    group.last_message_id = (cols[13] == "\\N") ? "" : cols[13];
    group.last_message_sent_at = (cols[14] == "\\N") ? "" : cols[14];
    return true;
}

bool parse_admin_group_member_cols(const std::vector<std::string>& cols,
                                   admin_group_member_record& member)
{
    if (cols.size() < 10U) {
        return false;
    }

    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    unsigned long long status = 0ULL;
    unsigned long long is_online = 0ULL;
    unsigned long long role = 0ULL;
    if (!parse_unsigned_long_long(cols[0], user_id)
        || !parse_unsigned_long_long(cols[1], numeric_id)
        || !parse_unsigned_long_long(cols[5], status)
        || !parse_unsigned_long_long(cols[6], is_online)
        || !parse_unsigned_long_long(cols[8], role)) {
        return false;
    }

    member.user_id = user_id;
    member.numeric_id = numeric_id;
    member.username = (cols[2] == "\\N") ? "" : cols[2];
    member.nickname = (cols[3] == "\\N") ? "" : cols[3];
    member.avatar_url = (cols[4] == "\\N") ? "" : cols[4];
    member.status = static_cast<unsigned int>(status);
    member.is_online = (is_online != 0ULL);
    member.last_seen_at = (cols[7] == "\\N") ? "" : cols[7];
    member.role = static_cast<unsigned int>(role);
    member.mute_until = (cols[9] == "\\N") ? "" : cols[9];
    return true;
}

bool parse_admin_conversation_cols(const std::vector<std::string>& cols,
                                   admin_conversation_record& conversation)
{
    if (cols.size() < 14U) {
        return false;
    }

    unsigned long long conversation_type = 0ULL;
    unsigned long long group_numeric_id = 0ULL;
    unsigned long long owner_user_id = 0ULL;
    unsigned long long member_count = 0ULL;
    unsigned long long last_message_seq = 0ULL;
    if (!parse_unsigned_long_long(cols[1], conversation_type)
        || !parse_unsigned_long_long(cols[2], group_numeric_id)
        || !parse_unsigned_long_long(cols[6], owner_user_id)
        || !parse_unsigned_long_long(cols[7], member_count)
        || !parse_unsigned_long_long(cols[10], last_message_seq)) {
        return false;
    }

    conversation.conversation_id = (cols[0] == "\\N") ? "" : cols[0];
    conversation.conversation_type = static_cast<unsigned int>(conversation_type);
    conversation.group_numeric_id = group_numeric_id;
    conversation.name = (cols[3] == "\\N") ? "" : cols[3];
    conversation.avatar_url = (cols[4] == "\\N") ? "" : cols[4];
    conversation.notice = (cols[5] == "\\N") ? "" : cols[5];
    conversation.owner_user_id = owner_user_id;
    conversation.member_count = static_cast<std::size_t>(member_count);
    conversation.created_at = (cols[8] == "\\N") ? "" : cols[8];
    conversation.updated_at = (cols[9] == "\\N") ? "" : cols[9];
    conversation.last_message_seq = last_message_seq;
    conversation.last_message_id = (cols[11] == "\\N") ? "" : cols[11];
    conversation.last_message_sent_at = (cols[12] == "\\N") ? "" : cols[12];
    conversation.participants_summary = (cols[13] == "\\N") ? "" : cols[13];
    return true;
}

bool parse_admin_message_cols(const std::vector<std::string>& cols,
                              admin_message_record& message)
{
    if (cols.size() < 10U) {
        return false;
    }

    unsigned long long seq = 0ULL;
    unsigned long long message_type = 0ULL;
    unsigned long long sender_user_id = 0ULL;
    unsigned long long sender_numeric_id = 0ULL;
    unsigned long long receipt_total = 0ULL;
    unsigned long long delivered_count = 0ULL;
    if (!parse_unsigned_long_long(cols[1], seq)
        || !parse_unsigned_long_long(cols[2], message_type)
        || !parse_unsigned_long_long(cols[5], sender_user_id)
        || !parse_unsigned_long_long(cols[6], sender_numeric_id)
        || !parse_unsigned_long_long(cols[8], receipt_total)
        || !parse_unsigned_long_long(cols[9], delivered_count)) {
        return false;
    }

    message.message_id = (cols[0] == "\\N") ? "" : cols[0];
    message.seq = seq;
    message.message_type = message_type;
    message.content_json = (cols[3] == "\\N") ? "{}" : cols[3];
    message.sent_at = (cols[4] == "\\N") ? "" : cols[4];
    message.sender_user_id = sender_user_id;
    message.sender_numeric_id = sender_numeric_id;
    message.sender_username = (cols[7] == "\\N") ? "" : cols[7];
    message.receipt_total = static_cast<std::size_t>(receipt_total);
    message.delivered_count = static_cast<std::size_t>(delivered_count);
    message.pending_count = message.receipt_total >= message.delivered_count
        ? (message.receipt_total - message.delivered_count)
        : 0U;
    summarize_message_content(message_type,
                              message.content_json,
                              message.message_kind,
                              message.content_preview,
                              message.file_id,
                              message.file_name,
                              message.file_size_bytes);
    return true;
}

bool parse_admin_message_receipt_cols(const std::vector<std::string>& cols,
                                      admin_message_receipt_record& receipt)
{
    if (cols.size() < 5U) {
        return false;
    }

    unsigned long long user_id = 0ULL;
    unsigned long long numeric_id = 0ULL;
    if (!parse_unsigned_long_long(cols[0], user_id)
        || !parse_unsigned_long_long(cols[1], numeric_id)) {
        return false;
    }

    receipt.user_id = user_id;
    receipt.numeric_id = numeric_id;
    receipt.username = (cols[2] == "\\N") ? "" : cols[2];
    receipt.nickname = (cols[3] == "\\N") ? "" : cols[3];
    receipt.delivered_at = (cols[4] == "\\N") ? "" : cols[4];
    receipt.delivered = !receipt.delivered_at.empty();
    return true;
}

bool parse_admin_chat_file_cols(const std::vector<std::string>& cols,
                                admin_chat_file_record& file)
{
    if (cols.size() < 16U) {
        return false;
    }

    unsigned long long uploader_user_id = 0ULL;
    unsigned long long uploader_numeric_id = 0ULL;
    unsigned long long size_bytes = 0ULL;
    unsigned long long attached_flag = 0ULL;
    if (!parse_unsigned_long_long(cols[2], uploader_user_id)
        || !parse_unsigned_long_long(cols[3], uploader_numeric_id)
        || !parse_unsigned_long_long(cols[11], size_bytes)
        || !parse_unsigned_long_long(cols[12], attached_flag)) {
        return false;
    }

    file.file_id = (cols[0] == "\\N") ? "" : cols[0];
    file.conversation_id = (cols[1] == "\\N") ? "" : cols[1];
    file.uploader_user_id = uploader_user_id;
    file.uploader_numeric_id = uploader_numeric_id;
    file.uploader_username = (cols[4] == "\\N") ? "" : cols[4];
    file.uploader_nickname = (cols[5] == "\\N") ? "" : cols[5];
    file.original_name = (cols[6] == "\\N") ? "" : cols[6];
    file.stored_name = (cols[7] == "\\N") ? "" : cols[7];
    file.stored_relative_path = (cols[8] == "\\N") ? "" : cols[8];
    file.content_type = (cols[9] == "\\N") ? "" : cols[9];
    file.sha256 = (cols[10] == "\\N") ? "" : cols[10];
    file.size_bytes = static_cast<std::size_t>(size_bytes);
    file.attached = (attached_flag != 0ULL);
    file.bound_message_id = (cols[13] == "\\N") ? "" : cols[13];
    file.created_at = (cols[14] == "\\N") ? "" : cols[14];
    file.attached_at = (cols[15] == "\\N") ? "" : cols[15];
    return true;
}

bool chat_files_table_exists(const mysql_config& cfg,
                             bool& exists,
                             std::string& command_output,
                             int& exit_code)
{
    exists = false;
    command_output.clear();
    exit_code = 0;
    if (!run_mysql_sql(cfg, "SHOW TABLES LIKE 'chat_files';", command_output, exit_code)) {
        return false;
    }
    exists = !collect_non_empty_lines(command_output).empty();
    return true;
}

} // namespace

bool list_managed_users(const user_list_options& options,
                        std::vector<managed_user_record>& users,
                        user_admin_error& error)
{
    users.clear();
    error = user_admin_error{};

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::string keyword = trim_copy(options.keyword);
    const std::size_t raw_limit = options.limit == 0U ? 100U : options.limit;
    const std::size_t limit = std::min<std::size_t>(raw_limit, 200U);

    std::ostringstream sql;
    sql << build_user_select_sql() << "WHERE 1=1 ";
    if (!options.include_disabled) {
        sql << "AND u.status=1 ";
    }
    if (!keyword.empty()) {
        const std::string escaped = sql_escape(keyword);
        sql << "AND ("
            << "CAST(u.id AS CHAR) LIKE '%" << escaped << "%' "
            << "OR CAST(COALESCE(u.numeric_id, 0) AS CHAR) LIKE '%" << escaped << "%' "
            << "OR u.username LIKE '%" << escaped << "%' "
            << "OR u.email LIKE '%" << escaped << "%' "
            << "OR COALESCE(p.nickname, '') LIKE '%" << escaped << "%'"
            << ") ";
    }
    sql << "ORDER BY u.id DESC "
        << "LIMIT " << static_cast<unsigned long long>(limit) << ";";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to list users", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    users.reserve(lines.size());
    for (const std::string& line : lines) {
        managed_user_record user;
        if (!parse_managed_user_cols(split_by_tab(line), user)) {
            set_error(error, user_admin_error_code::database, "failed to parse user list row", line);
            return false;
        }
        users.push_back(user);
    }
    return true;
}

bool load_admin_overview(admin_overview_summary& summary,
                         user_admin_error& error)
{
    summary = admin_overview_summary{};
    error = user_admin_error{};

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    std::ostringstream summary_sql;
    summary_sql
        << "SELECT "
        << "COUNT(*), "
        << "COALESCE(SUM(CASE WHEN u.status=1 THEN 1 ELSE 0 END), 0), "
        << "COALESCE(SUM(CASE WHEN u.status=0 THEN 1 ELSE 0 END), 0), "
        << "COALESCE(SUM(CASE WHEN COALESCE(p.is_online, 0) <> 0 THEN 1 ELSE 0 END), 0), "
        << "COALESCE(SUM(CASE WHEN u.last_login_at IS NOT NULL "
        << "AND u.last_login_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END), 0), "
        << "COALESCE(SUM(CASE WHEN p.last_seen_at IS NOT NULL "
        << "AND p.last_seen_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 ELSE 0 END), 0) "
        << "FROM user_data u "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, summary_sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to load admin overview", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        set_error(error, user_admin_error_code::database, "failed to load admin overview", "empty overview result");
        return false;
    }

    const std::vector<std::string> cols = split_by_tab(lines.back());
    if (cols.size() < 6U) {
        set_error(error, user_admin_error_code::database, "failed to parse admin overview", trim_copy(command_output));
        return false;
    }

    unsigned long long total_users = 0ULL;
    unsigned long long enabled_users = 0ULL;
    unsigned long long disabled_users = 0ULL;
    unsigned long long online_users = 0ULL;
    unsigned long long recent_login_users = 0ULL;
    unsigned long long recent_seen_users = 0ULL;
    if (!parse_unsigned_long_long(cols[0], total_users)
        || !parse_unsigned_long_long(cols[1], enabled_users)
        || !parse_unsigned_long_long(cols[2], disabled_users)
        || !parse_unsigned_long_long(cols[3], online_users)
        || !parse_unsigned_long_long(cols[4], recent_login_users)
        || !parse_unsigned_long_long(cols[5], recent_seen_users)) {
        set_error(error, user_admin_error_code::database, "failed to parse admin overview", trim_copy(command_output));
        return false;
    }

    summary.total_users = static_cast<std::size_t>(total_users);
    summary.enabled_users = static_cast<std::size_t>(enabled_users);
    summary.disabled_users = static_cast<std::size_t>(disabled_users);
    summary.online_users = static_cast<std::size_t>(online_users);
    summary.recent_login_users = static_cast<std::size_t>(recent_login_users);
    summary.recent_seen_users = static_cast<std::size_t>(recent_seen_users);

    std::ostringstream recent_sql;
    recent_sql << build_user_select_sql()
               << "ORDER BY "
               << "CASE WHEN u.last_login_at IS NULL THEN 1 ELSE 0 END ASC, "
               << "u.last_login_at DESC, "
               << "u.created_at DESC, "
               << "u.id DESC "
               << "LIMIT 6;";

    command_output.clear();
    exit_code = 0;
    if (!run_mysql_sql(cfg, recent_sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to load recent users", debug.str());
        return false;
    }

    const std::vector<std::string> recent_lines = collect_non_empty_lines(command_output);
    summary.recent_users.reserve(recent_lines.size());
    for (const std::string& line : recent_lines) {
        managed_user_record user;
        if (!parse_managed_user_cols(split_by_tab(line), user)) {
            set_error(error, user_admin_error_code::database, "failed to parse recent user row", line);
            return false;
        }
        summary.recent_users.push_back(user);
    }
    return true;
}

bool list_admin_groups(const admin_group_list_options& options,
                       std::vector<admin_group_record>& groups,
                       user_admin_error& error)
{
    groups.clear();
    error = user_admin_error{};

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::size_t raw_limit = options.limit == 0U ? 50U : options.limit;
    const std::size_t limit = std::min<std::size_t>(raw_limit, 200U);
    const std::string keyword = trim_copy(options.keyword);

    std::ostringstream sql;
    sql << "SELECT "
        << "c.conversation_uuid, "
        << "COALESCE(c.group_numeric_id, 0), "
        << mysql_text_sql("c.name") << ", "
        << mysql_text_sql("c.avatar_url") << ", "
        << mysql_text_sql("c.notice") << ", "
        << "COALESCE(c.owner_user_id, 0), "
        << "COALESCE(owner.numeric_id, 0), "
        << mysql_text_sql("owner.username") << ", "
        << mysql_text_sql("op.nickname") << ", "
        << "(SELECT COUNT(*) FROM conversation_members cm WHERE cm.conversation_id=c.id), "
        << "COALESCE(DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(c.updated_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(lastm.seq, 0), "
        << mysql_text_sql("lastm.message_uuid") << ", "
        << "COALESCE(DATE_FORMAT(lastm.created_at, '%Y-%m-%d %H:%i:%s'), '') "
        << "FROM conversations c "
        << "LEFT JOIN user_data owner ON owner.id=c.owner_user_id "
        << "LEFT JOIN user_im_profile op ON op.user_id=owner.id AND op.deleted_at IS NULL "
        << "LEFT JOIN messages lastm ON lastm.id=c.last_message_id "
        << "WHERE c.type=2 ";
    if (options.group_numeric_id != 0ULL) {
        sql << "AND c.group_numeric_id=" << options.group_numeric_id << " ";
    }
    if (options.owner_user_id != 0ULL) {
        sql << "AND c.owner_user_id=" << options.owner_user_id << " ";
    }
    if (!keyword.empty()) {
        const std::string escaped = sql_escape(keyword);
        sql << "AND ("
            << "c.conversation_uuid LIKE '%" << escaped << "%' "
            << "OR COALESCE(c.name, '') LIKE '%" << escaped << "%' "
            << "OR COALESCE(owner.username, '') LIKE '%" << escaped << "%' "
            << "OR COALESCE(op.nickname, '') LIKE '%" << escaped << "%'"
            << ") ";
    }
    sql << "ORDER BY c.updated_at DESC, c.id DESC "
        << "LIMIT " << static_cast<unsigned long long>(limit) << ";";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to list groups", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    groups.reserve(lines.size());
    for (const std::string& line : lines) {
        admin_group_record group;
        if (!parse_admin_group_cols(split_by_tab(line), group)) {
            set_error(error, user_admin_error_code::database, "failed to parse group row", line);
            return false;
        }
        groups.push_back(group);
    }
    return true;
}

bool list_admin_conversations(const admin_conversation_list_options& options,
                              std::vector<admin_conversation_record>& conversations,
                              user_admin_error& error)
{
    conversations.clear();
    error = user_admin_error{};

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::size_t raw_limit = options.limit == 0U ? 50U : options.limit;
    const std::size_t limit = std::min<std::size_t>(raw_limit, 200U);
    const std::string keyword = trim_copy(options.keyword);
    const std::string conversation_id = trim_copy(options.conversation_id);
    const std::string participants_summary_sql = mysql_text_sql(
        "(SELECT GROUP_CONCAT(CONCAT(COALESCE(u.numeric_id, 0), ':', "
        + mysql_text_sql("u.username")
        + ", ':', "
        + mysql_text_sql("p.nickname")
        + ") ORDER BY u.id SEPARATOR ' || ') "
        + "FROM conversation_members cm2 "
        + "JOIN user_data u ON u.id=cm2.user_id "
        + "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
        + "WHERE cm2.conversation_id=c.id)");

    std::ostringstream sql;
    sql << "SELECT "
        << "c.conversation_uuid, "
        << "c.type, "
        << "COALESCE(c.group_numeric_id, 0), "
        << mysql_text_sql("c.name") << ", "
        << mysql_text_sql("c.avatar_url") << ", "
        << mysql_text_sql("c.notice") << ", "
        << "COALESCE(c.owner_user_id, 0), "
        << "(SELECT COUNT(*) FROM conversation_members cm WHERE cm.conversation_id=c.id), "
        << "COALESCE(DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(c.updated_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(lastm.seq, 0), "
        << mysql_text_sql("lastm.message_uuid") << ", "
        << "COALESCE(DATE_FORMAT(lastm.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << participants_summary_sql << " "
        << "FROM conversations c "
        << "LEFT JOIN messages lastm ON lastm.id=c.last_message_id "
        << "WHERE 1=1 ";
    if (!conversation_id.empty()) {
        sql << "AND c.conversation_uuid='" << sql_escape(conversation_id) << "' ";
    }
    if (options.group_numeric_id != 0ULL) {
        sql << "AND c.group_numeric_id=" << options.group_numeric_id << " ";
    }
    if (options.user_id != 0ULL) {
        sql << "AND EXISTS(SELECT 1 FROM conversation_members cmu WHERE cmu.conversation_id=c.id AND cmu.user_id="
            << options.user_id << ") ";
    }
    if (options.numeric_id != 0ULL) {
        sql << "AND EXISTS(SELECT 1 FROM conversation_members cmn "
            << "JOIN user_data un ON un.id=cmn.user_id "
            << "WHERE cmn.conversation_id=c.id AND COALESCE(un.numeric_id, 0)=" << options.numeric_id << ") ";
    }
    if (!keyword.empty()) {
        const std::string escaped = sql_escape(keyword);
        sql << "AND ("
            << "c.conversation_uuid LIKE '%" << escaped << "%' "
            << "OR COALESCE(c.name, '') LIKE '%" << escaped << "%' "
            << "OR EXISTS(SELECT 1 FROM conversation_members cmk "
            << "JOIN user_data uk ON uk.id=cmk.user_id "
            << "LEFT JOIN user_im_profile pk ON pk.user_id=uk.id AND pk.deleted_at IS NULL "
            << "WHERE cmk.conversation_id=c.id "
            << "AND (uk.username LIKE '%" << escaped << "%' OR COALESCE(pk.nickname, '') LIKE '%" << escaped << "%'))"
            << ") ";
    }
    sql << "ORDER BY c.updated_at DESC, c.id DESC "
        << "LIMIT " << static_cast<unsigned long long>(limit) << ";";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to list conversations", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    conversations.reserve(lines.size());
    for (const std::string& line : lines) {
        admin_conversation_record conversation;
        if (!parse_admin_conversation_cols(split_by_tab(line), conversation)) {
            set_error(error, user_admin_error_code::database, "failed to parse conversation row", line);
            return false;
        }
        conversations.push_back(conversation);
    }
    return true;
}

bool list_admin_conversation_messages(const std::string& conversation_id,
                                      const admin_message_list_options& options,
                                      std::vector<admin_message_record>& messages,
                                      user_admin_error& error)
{
    messages.clear();
    error = user_admin_error{};

    const std::string trimmed_conversation_id = trim_copy(conversation_id);
    if (trimmed_conversation_id.empty()) {
        set_error(error, user_admin_error_code::validation, "conversation_id is required");
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::size_t raw_limit = options.limit == 0U ? 50U : options.limit;
    const std::size_t limit = std::min<std::size_t>(raw_limit, 200U);

    std::ostringstream sql;
    sql << "SELECT "
        << "m.message_uuid, "
        << "m.seq, "
        << "m.message_type, "
        << mysql_sanitized_sql("m.content", "'{}'") << ", "
        << "COALESCE(DATE_FORMAT(m.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(u.id, 0), "
        << "COALESCE(u.numeric_id, 0), "
        << mysql_text_sql("u.username") << ", "
        << "(SELECT COUNT(*) FROM message_receipts mr WHERE mr.message_id=m.id), "
        << "(SELECT COUNT(*) FROM message_receipts mr WHERE mr.message_id=m.id AND mr.delivered_at IS NOT NULL) "
        << "FROM messages m "
        << "JOIN conversations c ON c.id=m.conversation_id "
        << "LEFT JOIN user_data u ON u.id=m.sender_user_id "
        << "WHERE c.conversation_uuid='" << sql_escape(trimmed_conversation_id) << "' "
        << "ORDER BY m.seq DESC "
        << "LIMIT " << static_cast<unsigned long long>(limit) << ";";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to list conversation messages", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    messages.reserve(lines.size());
    for (const std::string& line : lines) {
        admin_message_record message;
        if (!parse_admin_message_cols(split_by_tab(line), message)) {
            set_error(error, user_admin_error_code::database, "failed to parse message row", line);
            return false;
        }
        message.conversation_id = trimmed_conversation_id;
        messages.push_back(message);
    }
    return true;
}

bool list_admin_message_receipts(const std::string& conversation_id,
                                 const std::string& message_id,
                                 std::vector<admin_message_receipt_record>& receipts,
                                 user_admin_error& error)
{
    receipts.clear();
    error = user_admin_error{};

    const std::string trimmed_conversation_id = trim_copy(conversation_id);
    const std::string trimmed_message_id = trim_copy(message_id);
    if (trimmed_conversation_id.empty() || trimmed_message_id.empty()) {
        set_error(error, user_admin_error_code::validation, "conversation_id and message_id are required");
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    std::ostringstream sql;
    sql << "SELECT "
        << "u.id, "
        << "COALESCE(u.numeric_id, 0), "
        << mysql_text_sql("u.username") << ", "
        << mysql_text_sql("p.nickname") << ", "
        << "COALESCE(DATE_FORMAT(mr.delivered_at, '%Y-%m-%d %H:%i:%s'), '') "
        << "FROM message_receipts mr "
        << "JOIN messages m ON m.id=mr.message_id "
        << "JOIN conversations c ON c.id=m.conversation_id "
        << "JOIN user_data u ON u.id=mr.user_id "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
        << "WHERE c.conversation_uuid='" << sql_escape(trimmed_conversation_id) << "' "
        << "AND m.message_uuid='" << sql_escape(trimmed_message_id) << "' "
        << "ORDER BY mr.delivered_at IS NULL DESC, mr.delivered_at ASC, u.id ASC;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to list message receipts", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    receipts.reserve(lines.size());
    for (const std::string& line : lines) {
        admin_message_receipt_record receipt;
        if (!parse_admin_message_receipt_cols(split_by_tab(line), receipt)) {
            set_error(error, user_admin_error_code::database, "failed to parse message receipt row", line);
            return false;
        }
        receipts.push_back(receipt);
    }
    return true;
}

bool load_admin_group_detail(const std::string& conversation_id,
                             admin_group_record& group,
                             std::vector<admin_group_member_record>& members,
                             std::vector<admin_message_record>& recent_messages,
                             user_admin_error& error)
{
    group = admin_group_record{};
    members.clear();
    recent_messages.clear();
    error = user_admin_error{};

    const std::string trimmed_conversation_id = trim_copy(conversation_id);
    if (trimmed_conversation_id.empty()) {
        set_error(error, user_admin_error_code::validation, "conversation_id is required");
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    std::ostringstream group_sql;
    group_sql << "SELECT "
              << "c.conversation_uuid, "
              << "COALESCE(c.group_numeric_id, 0), "
              << mysql_text_sql("c.name") << ", "
              << mysql_text_sql("c.avatar_url") << ", "
              << mysql_text_sql("c.notice") << ", "
              << "COALESCE(c.owner_user_id, 0), "
              << "COALESCE(owner.numeric_id, 0), "
              << mysql_text_sql("owner.username") << ", "
              << mysql_text_sql("op.nickname") << ", "
              << "(SELECT COUNT(*) FROM conversation_members cm WHERE cm.conversation_id=c.id), "
              << "COALESCE(DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
              << "COALESCE(DATE_FORMAT(c.updated_at, '%Y-%m-%d %H:%i:%s'), ''), "
              << "COALESCE(lastm.seq, 0), "
              << mysql_text_sql("lastm.message_uuid") << ", "
              << "COALESCE(DATE_FORMAT(lastm.created_at, '%Y-%m-%d %H:%i:%s'), '') "
              << "FROM conversations c "
              << "LEFT JOIN user_data owner ON owner.id=c.owner_user_id "
              << "LEFT JOIN user_im_profile op ON op.user_id=owner.id AND op.deleted_at IS NULL "
              << "LEFT JOIN messages lastm ON lastm.id=c.last_message_id "
              << "WHERE c.type=2 AND c.conversation_uuid='" << sql_escape(trimmed_conversation_id) << "' "
              << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, group_sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to load group detail", debug.str());
        return false;
    }

    const std::vector<std::string> group_lines = collect_non_empty_lines(command_output);
    if (group_lines.empty()) {
        set_error(error, user_admin_error_code::not_found, "group not found");
        return false;
    }
    if (!parse_admin_group_cols(split_by_tab(group_lines.front()), group)) {
        set_error(error, user_admin_error_code::database, "failed to parse group detail row", group_lines.front());
        return false;
    }

    std::ostringstream members_sql;
    members_sql << "SELECT "
                << "u.id, "
                << "COALESCE(u.numeric_id, 0), "
                << mysql_text_sql("u.username") << ", "
                << mysql_text_sql("p.nickname") << ", "
                << mysql_text_sql("p.avatar_url") << ", "
                << "COALESCE(u.status, 0), "
                << "COALESCE(p.is_online, 0), "
                << "COALESCE(DATE_FORMAT(p.last_seen_at, '%Y-%m-%d %H:%i:%s'), ''), "
                << "COALESCE(cm.role, 0), "
                << "COALESCE(DATE_FORMAT(cm.mute_until, '%Y-%m-%d %H:%i:%s'), '') "
                << "FROM conversations c "
                << "JOIN conversation_members cm ON cm.conversation_id=c.id "
                << "JOIN user_data u ON u.id=cm.user_id "
                << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
                << "WHERE c.conversation_uuid='" << sql_escape(trimmed_conversation_id) << "' "
                << "ORDER BY cm.role DESC, u.id ASC;";

    command_output.clear();
    exit_code = 0;
    if (!run_mysql_sql(cfg, members_sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to load group members", debug.str());
        return false;
    }

    const std::vector<std::string> member_lines = collect_non_empty_lines(command_output);
    members.reserve(member_lines.size());
    for (const std::string& line : member_lines) {
        admin_group_member_record member;
        if (!parse_admin_group_member_cols(split_by_tab(line), member)) {
            set_error(error, user_admin_error_code::database, "failed to parse group member row", line);
            return false;
        }
        members.push_back(member);
    }

    admin_message_list_options message_options;
    message_options.limit = 20U;
    if (!list_admin_conversation_messages(trimmed_conversation_id, message_options, recent_messages, error)) {
        return false;
    }
    return true;
}

bool list_admin_chat_files(const admin_chat_file_list_options& options,
                           std::vector<admin_chat_file_record>& files,
                           user_admin_error& error)
{
    files.clear();
    error = user_admin_error{};

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    bool table_exists = false;
    std::string command_output;
    int exit_code = 0;
    if (!chat_files_table_exists(cfg, table_exists, command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to check chat_files table", debug.str());
        return false;
    }
    if (!table_exists) {
        return true;
    }

    const std::size_t raw_limit = options.limit == 0U ? 50U : options.limit;
    const std::size_t limit = std::min<std::size_t>(raw_limit, 200U);
    const std::string keyword = trim_copy(options.keyword);
    const std::string conversation_id = trim_copy(options.conversation_id);
    const std::string file_id = trim_copy(options.file_id);

    std::ostringstream sql;
    sql << "SELECT "
        << "cf.file_uuid, "
        << "cf.conversation_uuid, "
        << "cf.uploader_user_id, "
        << "COALESCE(u.numeric_id, 0), "
        << mysql_text_sql("u.username") << ", "
        << mysql_text_sql("p.nickname") << ", "
        << mysql_text_sql("cf.original_name") << ", "
        << "COALESCE(cf.stored_name, ''), "
        << "COALESCE(cf.stored_relative_path, ''), "
        << "COALESCE(cf.content_type, ''), "
        << "COALESCE(cf.sha256, ''), "
        << "cf.size_bytes, "
        << "CASE WHEN cf.bound_message_uuid IS NULL OR cf.bound_message_uuid='' THEN 0 ELSE 1 END, "
        << "COALESCE(cf.bound_message_uuid, ''), "
        << "COALESCE(DATE_FORMAT(cf.created_at, '%Y-%m-%d %H:%i:%s'), ''), "
        << "COALESCE(DATE_FORMAT(cf.attached_at, '%Y-%m-%d %H:%i:%s'), '') "
        << "FROM chat_files cf "
        << "LEFT JOIN user_data u ON u.id=cf.uploader_user_id "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
        << "WHERE 1=1 ";
    if (!conversation_id.empty()) {
        sql << "AND cf.conversation_uuid='" << sql_escape(conversation_id) << "' ";
    }
    if (!file_id.empty()) {
        sql << "AND cf.file_uuid='" << sql_escape(file_id) << "' ";
    }
    if (options.uploader_user_id != 0ULL) {
        sql << "AND cf.uploader_user_id=" << options.uploader_user_id << " ";
    }
    if (!keyword.empty()) {
        const std::string escaped = sql_escape(keyword);
        sql << "AND ("
            << "cf.file_uuid LIKE '%" << escaped << "%' "
            << "OR cf.original_name LIKE '%" << escaped << "%' "
            << "OR cf.stored_name LIKE '%" << escaped << "%' "
            << "OR cf.sha256 LIKE '%" << escaped << "%'"
            << ") ";
    }
    sql << "ORDER BY cf.created_at DESC, cf.id DESC "
        << "LIMIT " << static_cast<unsigned long long>(limit) << ";";

    command_output.clear();
    exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to list chat files", debug.str());
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    files.reserve(lines.size());
    for (const std::string& line : lines) {
        admin_chat_file_record file;
        if (!parse_admin_chat_file_cols(split_by_tab(line), file)) {
            set_error(error, user_admin_error_code::database, "failed to parse chat file row", line);
            return false;
        }
        files.push_back(file);
    }
    return true;
}

bool load_admin_chat_file(const std::string& file_id,
                          admin_chat_file_record& file,
                          user_admin_error& error)
{
    file = admin_chat_file_record{};
    error = user_admin_error{};

    const std::string trimmed_file_id = trim_copy(file_id);
    if (trimmed_file_id.empty()) {
        set_error(error, user_admin_error_code::validation, "file_id is required");
        return false;
    }

    admin_chat_file_list_options options;
    options.file_id = trimmed_file_id;
    options.limit = 1U;
    std::vector<admin_chat_file_record> files;
    if (!list_admin_chat_files(options, files, error)) {
        return false;
    }
    if (files.empty()) {
        set_error(error, user_admin_error_code::not_found, "chat file not found");
        return false;
    }
    file = files.front();
    return true;
}

bool create_managed_user(const create_user_request& request,
                         managed_user_record& created_user,
                         user_admin_error& error)
{
    error = user_admin_error{};

    const std::string username = trim_copy(request.username);
    const std::string email = to_lower_copy(trim_copy(request.email));
    const std::string phone = trim_copy(request.phone);
    const std::string password = request.password;
    const std::string nickname = trim_copy(request.nickname);
    const std::string avatar_url = trim_copy(request.avatar_url);
    const std::string bio = trim_copy(request.bio);

    if (!is_valid_username(username)) {
        set_error(error, user_admin_error_code::validation, "username must match [A-Za-z0-9_], length 3~32");
        return false;
    }
    if (!validate_common_user_fields(email, phone, nickname, avatar_url, bio, request.status, error)) {
        return false;
    }
    if (!is_strong_password(password)) {
        set_error(error, user_admin_error_code::validation, "password must be 8~64 and include upper/lower letters and digits");
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::string password_hash = hash_password_for_storage(password);
    const std::string phone_sql = phone.empty() ? "NULL" : ("'" + sql_escape(phone) + "'");
    const std::string avatar_sql = avatar_url.empty() ? "NULL" : ("'" + sql_escape(avatar_url) + "'");
    const std::string bio_sql = bio.empty() ? "NULL" : ("'" + sql_escape(bio) + "'");
    const std::string user_uuid = generate_uuid_v4_like();

    std::ostringstream sql;
    sql << "START TRANSACTION; "
        << "INSERT INTO user_data (username, email, phone, password_hash, status, last_login_at, created_at, updated_at) VALUES ("
        << "'" << sql_escape(username) << "', "
        << "'" << sql_escape(email) << "', "
        << phone_sql << ", "
        << "'" << sql_escape(password_hash) << "', "
        << request.status << ", NULL, NOW(), NOW()); "
        << "SET @new_user_id = LAST_INSERT_ID(); "
        << "SET @new_numeric_id = @new_user_id + 9999; "
        << "UPDATE user_data SET numeric_id=@new_numeric_id, updated_at=NOW() WHERE id=@new_user_id; "
        << "INSERT INTO user_im_profile (user_id, user_uuid, nickname, avatar_url, bio, gender, region, last_seen_at, is_online, extra, created_at, updated_at, deleted_at) VALUES ("
        << "@new_user_id, "
        << "'" << sql_escape(user_uuid) << "', "
        << "'" << sql_escape(nickname) << "', "
        << avatar_sql << ", "
        << bio_sql << ", "
        << "0, NULL, NULL, 0, NULL, NOW(), NOW(), NULL); "
        << "COMMIT; "
        << "SELECT @new_user_id;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        if (command_output.find("Duplicate entry") != std::string::npos) {
            set_error(error, user_admin_error_code::conflict, "username or email already exists", trim_copy(command_output));
        } else {
            std::ostringstream debug;
            debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
            set_error(error, user_admin_error_code::database, "failed to create user", debug.str());
        }
        return false;
    }

    unsigned long long user_id = 0ULL;
    if (!parse_unsigned_long_long(last_non_empty_line(command_output), user_id) || user_id == 0ULL) {
        set_error(error, user_admin_error_code::database, "failed to parse created user id", trim_copy(command_output));
        return false;
    }

    return load_managed_user_by_id(user_id, created_user, error);
}

bool update_managed_user(const update_user_request& request,
                         managed_user_record& updated_user,
                         user_admin_error& error)
{
    error = user_admin_error{};
    if (request.user_id == 0ULL) {
        set_error(error, user_admin_error_code::validation, "user_id must be a positive integer");
        return false;
    }
    if (!request.has_email && !request.has_phone && !request.has_nickname
        && !request.has_avatar_url && !request.has_bio && !request.has_status) {
        set_error(error, user_admin_error_code::validation, "no updatable fields were provided");
        return false;
    }

    managed_user_record existing_user;
    if (!load_managed_user_by_id(request.user_id, existing_user, error)) {
        return false;
    }

    const std::string email = request.has_email
        ? to_lower_copy(trim_copy(request.email))
        : existing_user.email;
    const std::string phone = request.has_phone
        ? trim_copy(request.phone)
        : existing_user.phone;
    const std::string nickname = request.has_nickname
        ? trim_copy(request.nickname)
        : existing_user.nickname;
    const std::string avatar_url = request.has_avatar_url
        ? trim_copy(request.avatar_url)
        : existing_user.avatar_url;
    const std::string bio = request.has_bio
        ? trim_copy(request.bio)
        : existing_user.bio;
    const unsigned int status = request.has_status
        ? request.status
        : existing_user.status;

    if (!validate_common_user_fields(email, phone, nickname, avatar_url, bio, status, error)) {
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::string phone_sql = phone.empty() ? "NULL" : ("'" + sql_escape(phone) + "'");
    const std::string avatar_sql = avatar_url.empty() ? "NULL" : ("'" + sql_escape(avatar_url) + "'");
    const std::string bio_sql = bio.empty() ? "NULL" : ("'" + sql_escape(bio) + "'");

    std::ostringstream sql;
    sql << "START TRANSACTION; "
        << "UPDATE user_data SET "
        << "email='" << sql_escape(email) << "', "
        << "phone=" << phone_sql << ", "
        << "status=" << status << ", "
        << "updated_at=NOW() "
        << "WHERE id=" << request.user_id << "; "
        << "INSERT INTO user_im_profile (user_id, user_uuid, nickname, avatar_url, bio, gender, region, last_seen_at, is_online, extra, created_at, updated_at, deleted_at) VALUES ("
        << request.user_id << ", "
        << "'" << sql_escape(generate_uuid_v4_like()) << "', "
        << "'" << sql_escape(nickname) << "', "
        << avatar_sql << ", "
        << bio_sql << ", "
        << "0, NULL, NULL, 0, NULL, NOW(), NOW(), NULL) "
        << "ON DUPLICATE KEY UPDATE "
        << "nickname=VALUES(nickname), "
        << "avatar_url=VALUES(avatar_url), "
        << "bio=VALUES(bio), "
        << "updated_at=NOW(), "
        << "deleted_at=NULL; "
        << "COMMIT;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        if (command_output.find("Duplicate entry") != std::string::npos) {
            set_error(error, user_admin_error_code::conflict, "email already exists", trim_copy(command_output));
        } else {
            std::ostringstream debug;
            debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
            set_error(error, user_admin_error_code::database, "failed to update user", debug.str());
        }
        return false;
    }

    return load_managed_user_by_id(request.user_id, updated_user, error);
}

bool reset_managed_user_password(unsigned long long user_id,
                                 const std::string& new_password,
                                 user_admin_error& error)
{
    error = user_admin_error{};
    if (user_id == 0ULL) {
        set_error(error, user_admin_error_code::validation, "user_id must be a positive integer");
        return false;
    }
    if (!is_strong_password(new_password)) {
        set_error(error, user_admin_error_code::validation, "password must be 8~64 and include upper/lower letters and digits");
        return false;
    }

    managed_user_record ignored_user;
    if (!load_managed_user_by_id(user_id, ignored_user, error)) {
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }

    const std::string password_hash = hash_password_for_storage(new_password);
    std::ostringstream sql;
    sql << "UPDATE user_data SET "
        << "password_hash='" << sql_escape(password_hash) << "', "
        << "updated_at=NOW() "
        << "WHERE id=" << user_id << ";";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << exit_code << "; output=" << trim_copy(command_output);
        set_error(error, user_admin_error_code::database, "failed to reset password", debug.str());
        return false;
    }
    return true;
}

bool login_admin_user(const std::string& username,
                      const std::string& password,
                      admin_login_result& result,
                      user_admin_error& error)
{
    result = admin_login_result{};
    error = user_admin_error{};

    const std::string trimmed_username = trim_copy(username);
    if (!is_valid_username(trimmed_username)) {
        set_error(error, user_admin_error_code::validation, "admin username format is invalid");
        return false;
    }
    if (password.empty()) {
        set_error(error, user_admin_error_code::validation, "admin password is required");
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }
    if (!ensure_admin_users_bootstrap(cfg, error)) {
        return false;
    }

    admin_user_account admin;
    std::string password_hash;
    if (!load_admin_user_by_username(cfg, trimmed_username, admin, password_hash, error)) {
        return false;
    }
    if (!verify_password_against_storage(password, password_hash)) {
        set_error(error, user_admin_error_code::unauthorized, "invalid admin username or password");
        return false;
    }
    if (admin.status == 0U) {
        set_error(error, user_admin_error_code::unauthorized, "admin account is disabled");
        return false;
    }

    std::ostringstream update_sql;
    update_sql << "UPDATE admin_users SET last_login_at=NOW(), updated_at=NOW() "
               << "WHERE id=" << admin.admin_user_id << ";";
    std::string update_output;
    int update_exit_code = 0;
    if (!run_mysql_sql(cfg, update_sql.str(), update_output, update_exit_code)) {
        std::ostringstream debug;
        debug << "exit_code=" << update_exit_code << "; output=" << trim_copy(update_output);
        set_error(error, user_admin_error_code::database, "failed to update admin login time", debug.str());
        return false;
    }

    if (!load_admin_user_by_id(cfg, admin.admin_user_id, admin, nullptr, error)) {
        return false;
    }

    result.admin = admin;
    result.session_token = make_admin_session_token();
    result.session_ttl_seconds = admin_session_ttl_seconds();
    {
        std::lock_guard<std::mutex> lock(g_admin_sessions_mutex);
        prune_expired_admin_sessions_locked();
        g_admin_sessions[result.session_token] = admin_session_entry{
            admin.admin_user_id,
            std::chrono::system_clock::now() + std::chrono::seconds(result.session_ttl_seconds)
        };
    }
    return true;
}

bool validate_admin_session(const std::string& session_token,
                            admin_user_account& admin,
                            user_admin_error& error)
{
    admin = admin_user_account{};
    error = user_admin_error{};
    if (session_token.empty()) {
        set_error(error, user_admin_error_code::unauthorized, "missing admin session");
        return false;
    }

    unsigned long long admin_user_id = 0ULL;
    {
        std::lock_guard<std::mutex> lock(g_admin_sessions_mutex);
        prune_expired_admin_sessions_locked();
        const auto it = g_admin_sessions.find(session_token);
        if (it == g_admin_sessions.end()) {
            set_error(error, user_admin_error_code::unauthorized, "admin session is invalid or expired");
            return false;
        }
        admin_user_id = it->second.admin_user_id;
        it->second.expires_at = std::chrono::system_clock::now() + std::chrono::seconds(admin_session_ttl_seconds());
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        set_error(error, user_admin_error_code::config, "database config missing", config_error);
        return false;
    }
    if (!ensure_admin_users_bootstrap(cfg, error)) {
        return false;
    }
    if (!load_admin_user_by_id(cfg, admin_user_id, admin, nullptr, error)) {
        return false;
    }
    if (admin.status == 0U) {
        logout_admin_session(session_token);
        set_error(error, user_admin_error_code::unauthorized, "admin account is disabled");
        return false;
    }
    return true;
}

void logout_admin_session(const std::string& session_token)
{
    if (session_token.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_admin_sessions_mutex);
    g_admin_sessions.erase(session_token);
}

std::string admin_session_cookie_name()
{
    return "qt_server_admin_session";
}

int admin_session_ttl_seconds()
{
    return 12 * 60 * 60;
}

std::string default_bootstrap_admin_username()
{
    return "admin";
}

std::string default_bootstrap_admin_password()
{
    return "Admin123456";
}

} // namespace server
} // namespace qt_server
