#include "user_admin_service.hpp"

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
#include <random>
#include <sstream>
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
        const std::string trimmed = trim_copy(line);
        if (!trimmed.empty()) {
            lines.push_back(trimmed);
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
        << "u.username, "
        << "u.email, "
        << "COALESCE(u.phone, ''), "
        << "u.status, "
        << "COALESCE(p.user_uuid, ''), "
        << "COALESCE(p.nickname, ''), "
        << "COALESCE(p.avatar_url, ''), "
        << "COALESCE(p.bio, ''), "
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

std::string default_dev_admin_token()
{
    return "dev-admin-123456";
}

bool is_dev_admin_token_valid(const std::string& token)
{
    const std::string fallback = default_dev_admin_token();
    const std::string expected = getenv_or_default("QT_SERVER_DEV_ADMIN_TOKEN",
                                                   fallback.c_str());
    return !token.empty() && token == expected;
}

} // namespace server
} // namespace qt_server
