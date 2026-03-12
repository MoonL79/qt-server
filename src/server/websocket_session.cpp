#include "server/websocket_session.hpp"
#include "server/upload_token_store.hpp"
#include <boost/beast/core/buffers_to_string.hpp>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <fstream>
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

namespace {

std::mutex g_presence_mutex;
std::unordered_map<unsigned long long, std::size_t> g_online_session_counts;

struct mysql_config
{
    std::string host;
    std::string port;
    std::string database;
    std::string user;
    std::string password;
};

json::object build_mysql_config_debug(const mysql_config& cfg);

std::string mask_secret(const std::string& value)
{
    if (value.empty()) {
        return "<empty>";
    }
    if (value.size() <= 2) {
        return std::string(value.size(), '*');
    }
    return value.substr(0, 1) + std::string(value.size() - 2, '*') + value.substr(value.size() - 1, 1);
}

std::string trim_copy(const std::string& input)
{
    std::size_t begin = 0;
    std::size_t end = input.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
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

bool build_numeric_user_id(unsigned long long internal_user_id, unsigned int& numeric_user_id)
{
    // external numeric id starts from 10000 and follows registration order.
    constexpr unsigned long long kNumericUserIdBase = 10000ULL;
    constexpr unsigned long long kNumericUserIdOffset = kNumericUserIdBase - 1ULL;
    constexpr unsigned long long kNumericUserIdMax =
        static_cast<unsigned long long>(std::numeric_limits<unsigned int>::max());
    if (internal_user_id == 0ULL) {
        return false;
    }
    const unsigned long long candidate = internal_user_id + kNumericUserIdOffset;
    if (candidate < kNumericUserIdBase || candidate > kNumericUserIdMax) {
        return false;
    }
    numeric_user_id = static_cast<unsigned int>(candidate);
    return true;
}

bool is_valid_username(const std::string& username)
{
    if (username.size() < 3 || username.size() > 32) {
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
    if (at == std::string::npos || at == 0 || at + 1 >= email.size()) {
        return false;
    }
    const std::size_t dot = email.find('.', at + 1);
    return dot != std::string::npos && dot + 1 < email.size();
}

bool is_strong_password(const std::string& password)
{
    if (password.size() < 8 || password.size() > 64) {
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

std::string sql_escape(const std::string& input)
{
    std::string out;
    out.reserve(input.size() * 2);
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

std::string bytes_to_hex(const std::vector<unsigned char>& bytes)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
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
    if ((hex.size() % 2U) != 0U) {
        return false;
    }
    out.clear();
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
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
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        diff = static_cast<unsigned char>(diff | (lhs[i] ^ rhs[i]));
    }
    return diff == 0U;
}

uint32_t rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& input)
{
    static const uint32_t k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    uint32_t h0 = 0x6a09e667U;
    uint32_t h1 = 0xbb67ae85U;
    uint32_t h2 = 0x3c6ef372U;
    uint32_t h3 = 0xa54ff53aU;
    uint32_t h4 = 0x510e527fU;
    uint32_t h5 = 0x9b05688cU;
    uint32_t h6 = 0x1f83d9abU;
    uint32_t h7 = 0x5be0cd19U;

    std::vector<unsigned char> msg = input;
    const uint64_t bit_len = static_cast<uint64_t>(msg.size()) * 8ULL;
    msg.push_back(0x80U);
    while ((msg.size() % 64U) != 56U) {
        msg.push_back(0x00U);
    }
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<unsigned char>((bit_len >> (i * 8)) & 0xffU));
    }

    for (std::size_t offset = 0; offset < msg.size(); offset += 64U) {
        uint32_t w[64] = {0};
        for (int i = 0; i < 16; ++i) {
            const std::size_t base = offset + static_cast<std::size_t>(i) * 4U;
            w[i] = (static_cast<uint32_t>(msg[base]) << 24U)
                | (static_cast<uint32_t>(msg[base + 1]) << 16U)
                | (static_cast<uint32_t>(msg[base + 2]) << 8U)
                | static_cast<uint32_t>(msg[base + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr32(w[i - 15], 7U) ^ rotr32(w[i - 15], 18U) ^ (w[i - 15] >> 3U);
            const uint32_t s1 = rotr32(w[i - 2], 17U) ^ rotr32(w[i - 2], 19U) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            const uint32_t s0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = s0 + maj;

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
    const uint32_t hs[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (int i = 0; i < 8; ++i) {
        digest[i * 4 + 0] = static_cast<unsigned char>((hs[i] >> 24U) & 0xffU);
        digest[i * 4 + 1] = static_cast<unsigned char>((hs[i] >> 16U) & 0xffU);
        digest[i * 4 + 2] = static_cast<unsigned char>((hs[i] >> 8U) & 0xffU);
        digest[i * 4 + 3] = static_cast<unsigned char>(hs[i] & 0xffU);
    }
    return digest;
}

std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> k = key;
    if (k.size() > 64U) {
        k = sha256(k);
    }
    k.resize(64U, 0U);

    std::vector<unsigned char> o_key_pad(64U, 0x5cU);
    std::vector<unsigned char> i_key_pad(64U, 0x36U);
    for (std::size_t i = 0; i < 64U; ++i) {
        o_key_pad[i] ^= k[i];
        i_key_pad[i] ^= k[i];
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

    for (std::size_t block = 1; block <= block_count; ++block) {
        std::vector<unsigned char> salt_block = salt;
        salt_block.push_back(static_cast<unsigned char>((block >> 24U) & 0xffU));
        salt_block.push_back(static_cast<unsigned char>((block >> 16U) & 0xffU));
        salt_block.push_back(static_cast<unsigned char>((block >> 8U) & 0xffU));
        salt_block.push_back(static_cast<unsigned char>(block & 0xffU));

        std::vector<unsigned char> u = hmac_sha256(password, salt_block);
        std::vector<unsigned char> t = u;
        for (int i = 1; i < iterations; ++i) {
            u = hmac_sha256(password, u);
            for (std::size_t j = 0; j < hash_len; ++j) {
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
    for (std::size_t i = 0; i < len; ++i) {
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
    if (stored_hash.rfind(prefix, 0) != 0U) {
        return false;
    }

    const std::string body = stored_hash.substr(prefix.size());
    const std::size_t p1 = body.find('$');
    if (p1 == std::string::npos) {
        return false;
    }
    const std::size_t p2 = body.find('$', p1 + 1U);
    if (p2 == std::string::npos) {
        return false;
    }

    const std::string iterations_text = body.substr(0, p1);
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
    if (!hex_to_bytes(salt_hex, salt) || !hex_to_bytes(digest_hex, stored_digest)) {
        return false;
    }
    if (stored_digest.empty()) {
        return false;
    }

    const std::vector<unsigned char> password_bytes(plain_password.begin(), plain_password.end());
    const std::vector<unsigned char> computed = pbkdf2_hmac_sha256(password_bytes, salt, iterations, stored_digest.size());
    return constant_time_equal(stored_digest, computed);
}

std::string read_string_or_empty(const json::object& obj, const char* field)
{
    const auto it = obj.find(field);
    if (it == obj.end() || !it->value().is_string()) {
        return "";
    }
    return std::string(it->value().as_string().c_str());
}

std::string now_utc_iso8601()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);
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

std::string generate_uuid_v4_like()
{
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<unsigned int> dist(0, 15);
    static const char* hex = "0123456789abcdef";
    std::string uuid(36, '0');
    const int dash_positions[] = {8, 13, 18, 23};
    for (int pos : dash_positions) {
        uuid[pos] = '-';
    }
    for (std::size_t i = 0; i < uuid.size(); ++i) {
        if (uuid[i] == '-') {
            continue;
        }
        uuid[i] = hex[dist(gen)];
    }
    uuid[14] = '4';
    uuid[19] = hex[(dist(gen) & 0x3u) | 0x8u];
    return uuid;
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
        if (i != 0) {
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

std::string last_non_empty_line(const std::string& text)
{
    std::string last;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        const std::string trimmed = trim_copy(line);
        if (!trimmed.empty()) {
            last = trimmed;
        }
    }
    return last;
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
    std::size_t begin = 0;
    while (begin <= input.size()) {
        const std::size_t end = input.find('\t', begin);
        if (end == std::string::npos) {
            parts.push_back(input.substr(begin));
            break;
        }
        parts.push_back(input.substr(begin, end - begin));
        begin = end + 1;
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

bool parse_profile_row_line(const std::string& row_line,
                            std::string& avatar_url,
                            std::string& nickname,
                            std::string& signature,
                            std::string& theme)
{
    const std::vector<std::string> cols = split_by_tab(row_line);
    if (cols.size() < 4U) {
        return false;
    }
    avatar_url = (cols[0] == "\\N") ? "" : cols[0];
    nickname = (cols[1] == "\\N") ? "" : cols[1];
    signature = (cols[2] == "\\N") ? "" : cols[2];
    theme = (cols[3] == "\\N") ? "default" : cols[3];
    if (theme.empty()) {
        theme = "default";
    }
    return true;
}

bool parse_user_id_from_data(const json::object& data,
                             unsigned long long& user_id,
                             std::string& error_message)
{
    const std::string user_id_text = trim_copy(read_string_or_empty(data, "user_id"));
    if (!parse_unsigned_long_long(user_id_text, user_id)) {
        error_message = "field 'data.user_id' must be unsigned integer string";
        return false;
    }
    return true;
}

bool parse_numeric_id_from_data(const json::object& data,
                                unsigned long long& numeric_id,
                                std::string& error_message)
{
    const std::string numeric_id_text = trim_copy(read_string_or_empty(data, "numeric_id"));
    if (!parse_unsigned_long_long(numeric_id_text, numeric_id)) {
        error_message = "field 'data.numeric_id' must be unsigned integer string";
        return false;
    }
    return true;
}

bool parse_user_numeric_id_from_data(const json::object& data,
                                     unsigned long long& user_numeric_id,
                                     std::string& error_message)
{
    const std::string user_numeric_id_text = trim_copy(read_string_or_empty(data, "user_numeric_id"));
    if (!parse_unsigned_long_long(user_numeric_id_text, user_numeric_id)) {
        error_message = "field 'data.user_numeric_id' must be unsigned integer string";
        return false;
    }
    return true;
}

bool parse_friend_user_id_from_data(const json::object& data,
                                    unsigned long long& friend_user_id,
                                    std::string& error_message)
{
    const std::string friend_user_id_text = trim_copy(read_string_or_empty(data, "friend_user_id"));
    if (!parse_unsigned_long_long(friend_user_id_text, friend_user_id)) {
        error_message = "field 'data.friend_user_id' must be unsigned integer string";
        return false;
    }
    return true;
}

bool parse_friend_numeric_id_from_data(const json::object& data,
                                       unsigned long long& friend_numeric_id,
                                       std::string& error_message)
{
    const std::string friend_numeric_id_text = trim_copy(read_string_or_empty(data, "friend_numeric_id"));
    if (!parse_unsigned_long_long(friend_numeric_id_text, friend_numeric_id)) {
        error_message = "field 'data.friend_numeric_id' must be unsigned integer string";
        return false;
    }
    return true;
}

bool is_mysql_config_valid(const mysql_config& cfg, std::string& reason)
{
    if (cfg.host.empty()) {
        reason = "missing env QT_SERVER_MYSQL_HOST";
        return false;
    }
    if (cfg.port.empty()) {
        reason = "missing env QT_SERVER_MYSQL_PORT";
        return false;
    }
    if (cfg.database.empty()) {
        reason = "missing env QT_SERVER_MYSQL_DB";
        return false;
    }
    if (cfg.user.empty()) {
        reason = "missing env QT_SERVER_MYSQL_USER";
        return false;
    }
    if (cfg.password.empty()) {
        reason = "missing env QT_SERVER_MYSQL_PASSWORD";
        return false;
    }
    return true;
}

bool update_user_presence_in_db(const mysql_config& cfg,
                                unsigned long long user_id,
                                bool is_online,
                                std::string& command_output,
                                int& exit_code)
{
    std::ostringstream sql;
    sql << "UPDATE user_im_profile SET is_online=" << (is_online ? 1 : 0)
        << ", last_seen_at=NOW(), updated_at=NOW() "
        << "WHERE user_id=" << user_id << " AND deleted_at IS NULL;";
    return run_mysql_sql(cfg, sql.str(), command_output, exit_code);
}

bool mark_user_presence(unsigned long long user_id,
                        bool is_online,
                        json::object* response_data)
{
    if (user_id == 0ULL) {
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        if (response_data != nullptr) {
            (*response_data)["debug"] = build_mysql_config_debug(cfg);
            (*response_data)["debug"].as_object()["config_error"] = config_error;
        }
        return false;
    }

    std::string command_output;
    int exit_code = 0;
    if (!update_user_presence_in_db(cfg, user_id, is_online, command_output, exit_code)) {
        if (response_data != nullptr) {
            (*response_data)["debug"] = build_mysql_config_debug(cfg);
            (*response_data)["debug"].as_object()["mysql_exit_code"] = exit_code;
            (*response_data)["debug"].as_object()["mysql_output"] = command_output;
        }
        return false;
    }
    return true;
}

json::object build_mysql_config_debug(const mysql_config& cfg)
{
    json::object debug;
    const char* env_host = std::getenv("QT_SERVER_MYSQL_HOST");
    const char* env_port = std::getenv("QT_SERVER_MYSQL_PORT");
    const char* env_db = std::getenv("QT_SERVER_MYSQL_DB");
    const char* env_user = std::getenv("QT_SERVER_MYSQL_USER");
    const char* env_password = std::getenv("QT_SERVER_MYSQL_PASSWORD");
    const char* env_mysql_pwd = std::getenv("MYSQL_PWD");

    debug["env.QT_SERVER_MYSQL_HOST.present"] = (env_host != nullptr);
    debug["env.QT_SERVER_MYSQL_PORT.present"] = (env_port != nullptr);
    debug["env.QT_SERVER_MYSQL_DB.present"] = (env_db != nullptr);
    debug["env.QT_SERVER_MYSQL_USER.present"] = (env_user != nullptr);
    debug["env.QT_SERVER_MYSQL_PASSWORD.present"] = (env_password != nullptr);
    debug["env.MYSQL_PWD.present"] = (env_mysql_pwd != nullptr);

    debug["cfg.host"] = cfg.host;
    debug["cfg.port"] = cfg.port;
    debug["cfg.database"] = cfg.database;
    debug["cfg.user"] = cfg.user;
    debug["cfg.password_masked"] = mask_secret(cfg.password);
    debug["cfg.password_length"] = static_cast<int>(cfg.password.size());
    return debug;
}

} // namespace

bool websocket_session::is_supported_type(const std::string& type)
{
    return type == "AUTH" || type == "PROFILE" || type == "MESSAGE";
}

bool websocket_session::is_supported_action(const std::string& type, const std::string& action)
{
    if (type == "AUTH") {
        return action == "LOGIN" || action == "REGISTER" || action == "LOGOUT" || action == "REFRESH_TOKEN";
    }
    if (type == "PROFILE") {
        return action == "GET" || action == "GET_INFO" || action == "SET_INFO" || action == "UPDATE"
            || action == "ADD_FRIEND" || action == "DELETE_FRIEND" || action == "LIST_FRIENDS";
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

bool websocket_session::validate_optional_string_max_len(const json::object& obj,
                                                         const char* field,
                                                         std::size_t max_len,
                                                         std::string& error_message)
{
    const auto it = obj.find(field);
    if (it == obj.end()) {
        return true;
    }
    if (!it->value().is_string()) {
        error_message = std::string("field 'data.") + field + "' must be string";
        return false;
    }
    if (it->value().as_string().size() > max_len) {
        error_message = std::string("field 'data.") + field + "' is too long";
        return false;
    }
    return true;
}

bool websocket_session::validate_data_schema(const std::string& type,
                                             const std::string& action,
                                             const json::object& data,
                                             std::string& error_message,
                                             protocol_code& error_code)
{
    if (type == "AUTH") {
        if (action == "LOGIN") {
            if (!require_string_field(data, "username", error_message)
                || !require_string_field(data, "password", error_message)) {
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            return true;
        }
        if (action == "REGISTER") {
            if (!require_string_field(data, "username", error_message)
                || !require_string_field(data, "email", error_message)
                || !require_string_field(data, "password", error_message)
                || !require_string_field(data, "nickname", error_message)
                || !validate_optional_string_max_len(data, "phone", 32, error_message)
                || !validate_optional_string_max_len(data, "avatar_url", 255, error_message)
                || !validate_optional_string_max_len(data, "bio", 255, error_message)) {
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            const std::string username = trim_copy(read_string_or_empty(data, "username"));
            const std::string email = trim_copy(read_string_or_empty(data, "email"));
            const std::string password = read_string_or_empty(data, "password");
            const std::string nickname = trim_copy(read_string_or_empty(data, "nickname"));
            if (!is_valid_username(username)) {
                error_message = "field 'data.username' must match [A-Za-z0-9_], length 3~32";
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            if (email.size() > 128 || !is_valid_email(email)) {
                error_message = "field 'data.email' must be a valid email address with max length 128";
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            if (password.size() < 8 || password.size() > 64) {
                error_message = "field 'data.password' length must be 8~64";
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            if (!is_strong_password(password)) {
                error_message = "field 'data.password' must include upper/lower letters and digits";
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            if (nickname.empty() || nickname.size() > 64) {
                error_message = "field 'data.nickname' length must be 1~64";
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            return true;
        }
        if (action == "LOGOUT") {
            if (!require_string_field(data, "token", error_message)) {
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            return true;
        }
        if (action == "REFRESH_TOKEN") {
            if (!require_string_field(data, "refresh_token", error_message)) {
                error_code = protocol_code::INVALID_PARAM;
                return false;
            }
            return true;
        }
    }

    if (type == "PROFILE") {
        if (action == "GET") {
            if (!require_string_field(data, "numeric_id", error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            unsigned long long numeric_id = 0;
            if (!parse_numeric_id_from_data(data, numeric_id, error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
        if (action == "GET_INFO") {
            if (!require_string_field(data, "user_id", error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
        if (action == "UPDATE") {
            if (!require_string_field(data, "user_id", error_message)
                || !require_string_field(data, "nickname", error_message)
                || !require_string_field(data, "avatar_url", error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
        if (action == "SET_INFO") {
            const auto signature_it = data.find("signature");
            if (!require_string_field(data, "user_id", error_message)
                || !require_string_field(data, "avatar_url", error_message)
                || !require_string_field(data, "nickname", error_message)
                || signature_it == data.end()
                || !signature_it->value().is_string()
                || !validate_optional_string_max_len(data, "theme", 32, error_message)) {
                if (signature_it == data.end() || !signature_it->value().is_string()) {
                    error_message = "field 'data.signature' is required and must be string";
                }
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            const std::string nickname = trim_copy(read_string_or_empty(data, "nickname"));
            const std::string avatar_url = trim_copy(read_string_or_empty(data, "avatar_url"));
            const std::string signature = trim_copy(read_string_or_empty(data, "signature"));
            if (nickname.size() > 64) {
                error_message = "field 'data.nickname' length must be <= 64";
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            if (avatar_url.size() > 255) {
                error_message = "field 'data.avatar_url' length must be <= 255";
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            if (signature.size() > 255) {
                error_message = "field 'data.signature' length must be <= 255";
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
        if (action == "ADD_FRIEND") {
            if (!require_string_field(data, "user_numeric_id", error_message)
                || !require_string_field(data, "friend_numeric_id", error_message)
                || !validate_optional_string_max_len(data, "remark", 255, error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            unsigned long long user_numeric_id = 0;
            unsigned long long friend_numeric_id = 0;
            if (!parse_user_numeric_id_from_data(data, user_numeric_id, error_message)
                || !parse_friend_numeric_id_from_data(data, friend_numeric_id, error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            if (user_numeric_id == friend_numeric_id) {
                error_message = "field 'data.user_numeric_id' and 'data.friend_numeric_id' cannot be the same";
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
        if (action == "DELETE_FRIEND") {
            if (!require_string_field(data, "user_numeric_id", error_message)
                || !require_string_field(data, "friend_numeric_id", error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            unsigned long long user_numeric_id = 0;
            unsigned long long friend_numeric_id = 0;
            if (!parse_user_numeric_id_from_data(data, user_numeric_id, error_message)
                || !parse_friend_numeric_id_from_data(data, friend_numeric_id, error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            if (user_numeric_id == friend_numeric_id) {
                error_message = "field 'data.user_numeric_id' and 'data.friend_numeric_id' cannot be the same";
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
        if (action == "LIST_FRIENDS") {
            if (!require_string_field(data, "numeric_id", error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            unsigned long long numeric_id = 0;
            if (!parse_numeric_id_from_data(data, numeric_id, error_message)) {
                error_code = protocol_code::PROFILE_VALIDATION_FAILED;
                return false;
            }
            return true;
        }
    }

    if (type == "MESSAGE") {
        if (action == "SEND") {
            if (!require_string_field(data, "conversation_id", error_message)
                || !require_string_field(data, "content", error_message)) {
                error_code = protocol_code::MESSAGE_INVALID;
                return false;
            }
            return true;
        }
        if (action == "PULL") {
            if (!require_string_field(data, "conversation_id", error_message)) {
                error_code = protocol_code::MESSAGE_INVALID;
                return false;
            }
            return true;
        }
        if (action == "ACK") {
            if (!require_string_field(data, "conversation_id", error_message)
                || !require_string_field(data, "message_id", error_message)
                || !require_bool_field(data, "delivered", error_message)) {
                error_code = protocol_code::MESSAGE_INVALID;
                return false;
            }
            return true;
        }
    }

    error_message = "unsupported type/action combination";
    error_code = protocol_code::INVALID_ACTION;
    return false;
}

bool websocket_session::handle_register(const json::object& data,
                                        json::object& response_data,
                                        std::string& message,
                                        protocol_code& response_code)
{
    const std::string username = trim_copy(read_string_or_empty(data, "username"));
    const std::string email = to_lower_copy(trim_copy(read_string_or_empty(data, "email")));
    const std::string phone = trim_copy(read_string_or_empty(data, "phone"));
    const std::string plain_password = read_string_or_empty(data, "password");
    const std::string nickname = trim_copy(read_string_or_empty(data, "nickname"));
    const std::string avatar_url = trim_copy(read_string_or_empty(data, "avatar_url"));
    const std::string bio = trim_copy(read_string_or_empty(data, "bio"));
    const std::string user_uuid = generate_uuid_v4_like();
    const std::string password_hash = hash_password_for_storage(plain_password);
    const std::string created_at = now_utc_iso8601();

    const std::string phone_sql = phone.empty() ? "NULL" : ("'" + sql_escape(phone) + "'");
    const std::string avatar_sql = avatar_url.empty() ? "NULL" : ("'" + sql_escape(avatar_url) + "'");
    const std::string bio_sql = bio.empty() ? "NULL" : ("'" + sql_escape(bio) + "'");

    std::ostringstream sql;
    sql << "START TRANSACTION; "
        << "INSERT INTO user_data (username, email, phone, password_hash, status, last_login_at, created_at, updated_at) VALUES ("
        << "'" << sql_escape(username) << "', "
        << "'" << sql_escape(email) << "', "
        << phone_sql << ", "
        << "'" << sql_escape(password_hash) << "', "
        << "1, NULL, NOW(), NOW()); "
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
        << "SELECT @new_user_id, @new_numeric_id;";

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::cerr << "register mysql cfg: host=" << cfg.host
              << ", port=" << cfg.port
              << ", db=" << cfg.database
              << ", user=" << cfg.user
              << ", password=" << mask_secret(cfg.password)
              << ", password_len=" << cfg.password.size()
              << std::endl;
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::REGISTER_FAILED;
        message = "register failed: database config missing";
        std::cerr << "register config error: " << config_error << std::endl;
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }
    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        if (command_output.find("Duplicate entry") != std::string::npos) {
            response_code = protocol_code::REGISTER_CONFLICT;
            message = "username or email already exists";
        } else {
            response_code = protocol_code::REGISTER_FAILED;
            message = "register failed in database";
        }
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        std::cerr << "register db error: " << trim_copy(command_output) << std::endl;
        return false;
    }

    const std::string id_line = last_non_empty_line(command_output);
    const std::vector<std::string> id_cols = split_by_tab(id_line);
    unsigned long long user_id = 0;
    if (id_cols.empty() || !parse_unsigned_long_long(id_cols[0], user_id)) {
        response_code = protocol_code::REGISTER_FAILED;
        message = "register succeeded but failed to parse new user id";
        std::cerr << "register db parse error, output: " << trim_copy(command_output) << std::endl;
        return false;
    }
    unsigned int numeric_user_id = 0U;
    unsigned long long numeric_user_id_u64 = 0ULL;
    if (id_cols.size() >= 2U
        && parse_unsigned_long_long(id_cols[1], numeric_user_id_u64)
        && numeric_user_id_u64 <= static_cast<unsigned long long>(std::numeric_limits<unsigned int>::max())) {
        numeric_user_id = static_cast<unsigned int>(numeric_user_id_u64);
    } else if (!build_numeric_user_id(user_id, numeric_user_id)) {
        response_code = protocol_code::REGISTER_FAILED;
        message = "register succeeded but failed to generate numeric user id";
        std::cerr << "register numeric user id overflow, user_id=" << user_id << std::endl;
        return false;
    }

    json::object user_data;
    user_data["user_id"] = std::to_string(user_id);
    user_data["numeric_id"] = std::to_string(numeric_user_id);
    user_data["user_uuid"] = user_uuid;
    user_data["username"] = username;
    user_data["email"] = email;
    user_data["phone"] = phone;
    user_data["nickname"] = nickname;
    user_data["avatar_url"] = avatar_url;
    user_data["bio"] = bio;
    user_data["status"] = 1;
    user_data["created_at"] = created_at;
    response_data["user"] = std::move(user_data);
    response_code = protocol_code::OK;
    message = "register accepted";
    return true;
}

bool websocket_session::handle_login(const json::object& data,
                                     json::object& response_data,
                                     std::string& message,
                                     protocol_code& response_code)
{
    const std::string username = trim_copy(read_string_or_empty(data, "username"));
    const std::string plain_password = read_string_or_empty(data, "password");
    std::cout << "[presence] login request session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " username=" << username << std::endl;

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::LOGIN_FAILED;
        message = "login failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

    std::ostringstream sql;
    sql << "SELECT "
        << "u.id, "
        << "COALESCE(u.numeric_id, 0), "
        << "u.username, "
        << "u.email, "
        << "COALESCE(u.phone, ''), "
        << "u.status, "
        << "u.password_hash, "
        << "COALESCE(p.user_uuid, ''), "
        << "COALESCE(p.nickname, ''), "
        << "COALESCE(p.avatar_url, ''), "
        << "COALESCE(p.bio, '') "
        << "FROM user_data u "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
        << "WHERE u.username='" << sql_escape(username) << "' "
        << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::LOGIN_FAILED;
        message = "login failed in database";
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        response_code = protocol_code::LOGIN_FAILED;
        message = "invalid username or password";
        return false;
    }

    const std::vector<std::string> cols = split_by_tab(lines.back());
    if (cols.size() < 11U) {
        response_code = protocol_code::LOGIN_FAILED;
        message = "invalid username or password";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    unsigned long long user_id = 0;
    unsigned long long numeric_id = 0;
    unsigned long long status = 0;
    if (!parse_unsigned_long_long(cols[0], user_id)
        || !parse_unsigned_long_long(cols[1], numeric_id)
        || !parse_unsigned_long_long(cols[5], status)) {
        response_code = protocol_code::LOGIN_FAILED;
        message = "invalid username or password";
        return false;
    }

    const std::string password_hash = cols[6];
    if (!verify_password_against_storage(plain_password, password_hash)) {
        response_code = protocol_code::LOGIN_FAILED;
        message = "invalid username or password";
        return false;
    }

    if (status == 0ULL) {
        response_code = protocol_code::PERMISSION_DENIED;
        message = "account is disabled";
        return false;
    }

    std::ostringstream update_sql;
    update_sql << "UPDATE user_data SET last_login_at=NOW(), updated_at=NOW() WHERE id=" << user_id << ";";
    std::string update_output;
    int update_exit_code = 0;
    if (!run_mysql_sql(cfg, update_sql.str(), update_output, update_exit_code)) {
        response_data["debug"].as_object()["login_update_mysql_exit_code"] = update_exit_code;
        response_data["debug"].as_object()["login_update_mysql_output"] = update_output;
    }

    json::object user_data;
    user_data["user_id"] = std::to_string(user_id);
    user_data["numeric_id"] = std::to_string(numeric_id);
    user_data["username"] = (cols[2] == "\\N") ? "" : cols[2];
    user_data["email"] = (cols[3] == "\\N") ? "" : cols[3];
    user_data["phone"] = (cols[4] == "\\N") ? "" : cols[4];
    user_data["status"] = static_cast<int>(status);
    user_data["user_uuid"] = (cols[7] == "\\N") ? "" : cols[7];
    user_data["nickname"] = (cols[8] == "\\N") ? "" : cols[8];
    user_data["avatar_url"] = (cols[9] == "\\N") ? "" : cols[9];
    user_data["bio"] = (cols[10] == "\\N") ? "" : cols[10];
    response_data["user"] = std::move(user_data);

    std::string upload_token;
    std::string upload_token_expires_at;
    if (issue_upload_token(user_id, 2 * 60 * 60, upload_token, upload_token_expires_at)) {
        response_data["upload_token"] = upload_token;
        response_data["upload_token_expires_at"] = upload_token_expires_at;
        response_data["upload_token_type"] = "Bearer";
    } else {
        response_data["upload_token"] = "";
        response_data["upload_token_expires_at"] = "";
        response_data["upload_token_type"] = "Bearer";
    }

    bind_authenticated_user(user_id, numeric_id, username, &response_data);
    response_data["presence"] = json::object{
        {"is_online", true},
        {"last_seen_at", now_utc_iso8601()}
    };
    std::cout << "[presence] login accepted session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " user_id=" << user_id
              << " numeric_id=" << numeric_id
              << " username=" << username << std::endl;

    response_code = protocol_code::OK;
    message = "login accepted";
    return true;
}

bool websocket_session::handle_logout(const json::object& data,
                                      json::object& response_data,
                                      std::string& message,
                                      protocol_code& response_code)
{
    const std::string token = trim_copy(read_string_or_empty(data, "token"));
    unsigned long long token_user_id = 0;
    std::string token_error;
    std::cout << "[presence] logout request session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " token_len=" << token.size()
              << " bound_user_id=" << authenticated_user_id_
              << std::endl;
    if (!validate_upload_token(token, token_user_id, token_error)) {
        response_code = protocol_code::TOKEN_INVALID;
        message = token_error;
        std::cout << "[presence] logout token validation failed session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " error=" << token_error << std::endl;
        return false;
    }

    response_data["user_id"] = std::to_string(token_user_id);
    if (authenticated_user_id_ == token_user_id) {
        response_data["numeric_id"] = std::to_string(authenticated_numeric_id_);
    } else {
        unsigned int numeric_id = 0U;
        if (build_numeric_user_id(token_user_id, numeric_id)) {
            response_data["numeric_id"] = std::to_string(numeric_id);
        } else {
            response_data["numeric_id"] = "";
        }
    }
    response_data["offline"] = true;
    response_data["last_seen_at"] = now_utc_iso8601();
    if (authenticated_user_id_ == token_user_id) {
        unbind_authenticated_user(true, &response_data);
    } else {
        std::cout << "[presence] logout token user does not match bound session, forcing offline by token"
                  << " session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " token_user_id=" << token_user_id
                  << " bound_user_id=" << authenticated_user_id_
                  << std::endl;
        if (!mark_user_presence(token_user_id, false, &response_data)) {
            response_data["presence_sync_failed"] = true;
        }
        response_data["presence_event"] = "logout";
    }
    std::cout << "[presence] logout accepted session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " token_user_id=" << token_user_id
              << " response_offline=true" << std::endl;
    response_code = protocol_code::OK;
    message = "logout accepted";
    return true;
}

bool websocket_session::handle_profile_get(const json::object& data,
                                           json::object& response_data,
                                           std::string& message,
                                           protocol_code& response_code)
{
    unsigned long long requested_numeric_id = 0;
    std::string parse_error;
    if (!parse_numeric_id_from_data(data, requested_numeric_id, parse_error)) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = parse_error;
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

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
        << "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(p.extra, '$.signature')), ''), "
        << "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(p.extra, '$.theme')), 'default') "
        << "FROM user_data u "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
        << "WHERE u.numeric_id=" << requested_numeric_id << " "
        << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed in database";
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        response_code = protocol_code::PROFILE_NOT_FOUND;
        message = "profile not found";
        return false;
    }

    const std::vector<std::string> cols = split_by_tab(lines.back());
    if (cols.size() < 12U) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    unsigned long long parsed_user_id = 0;
    unsigned long long parsed_numeric_id = 0;
    unsigned long long status = 0;
    if (!parse_unsigned_long_long(cols[0], parsed_user_id)
        || !parse_unsigned_long_long(cols[1], parsed_numeric_id)
        || !parse_unsigned_long_long(cols[5], status)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }
    if (parsed_user_id == 0ULL || parsed_numeric_id == 0ULL) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: invalid user identity in database";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }
    unsigned int expected_numeric_id = 0U;
    if (!build_numeric_user_id(parsed_user_id, expected_numeric_id)
        || parsed_numeric_id != static_cast<unsigned long long>(expected_numeric_id)
        || parsed_numeric_id != requested_numeric_id) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: inconsistent user identity in database";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    json::object profile;
    profile["user_id"] = std::to_string(parsed_user_id);
    profile["numeric_id"] = std::to_string(parsed_numeric_id);
    profile["username"] = (cols[2] == "\\N") ? "" : cols[2];
    profile["email"] = (cols[3] == "\\N") ? "" : cols[3];
    profile["phone"] = (cols[4] == "\\N") ? "" : cols[4];
    profile["status"] = static_cast<int>(status);
    profile["user_uuid"] = (cols[6] == "\\N") ? "" : cols[6];
    profile["nickname"] = (cols[7] == "\\N") ? "" : cols[7];
    profile["avatar_url"] = (cols[8] == "\\N") ? "" : cols[8];
    profile["bio"] = (cols[9] == "\\N") ? "" : cols[9];
    profile["signature"] = (cols[10] == "\\N") ? "" : cols[10];
    profile["theme"] = (cols[11] == "\\N") ? "default" : cols[11];
    response_data["profile"] = std::move(profile);
    response_code = protocol_code::OK;
    message = "profile get accepted";
    return true;
}

bool websocket_session::handle_profile_get_info(const json::object& data,
                                                json::object& response_data,
                                                std::string& message,
                                                protocol_code& response_code)
{
    unsigned long long user_id = 0;
    std::string parse_error;
    if (!parse_user_id_from_data(data, user_id, parse_error)) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = parse_error;
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

    std::ostringstream sql;
    sql << "SELECT "
        << "COALESCE(avatar_url, ''), "
        << "COALESCE(nickname, ''), "
        << "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(extra, '$.signature')), ''), "
        << "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(extra, '$.theme')), 'default') "
        << "FROM user_im_profile "
        << "WHERE user_id=" << user_id << " AND deleted_at IS NULL "
        << "LIMIT 1;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed in database";
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        response_code = protocol_code::PROFILE_NOT_FOUND;
        message = "profile not found";
        return false;
    }

    std::string avatar_url;
    std::string nickname;
    std::string signature;
    std::string theme;
    if (!parse_profile_row_line(lines.back(), avatar_url, nickname, signature, theme)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile get failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    json::object profile;
    profile["avatar_url"] = avatar_url;
    profile["nickname"] = nickname;
    profile["signature"] = signature;
    profile["theme"] = theme;
    response_data["profile"] = std::move(profile);
    response_code = protocol_code::OK;
    message = "profile info request accepted";
    return true;
}

bool websocket_session::handle_profile_set_info(const json::object& data,
                                                json::object& response_data,
                                                std::string& message,
                                                protocol_code& response_code)
{
    unsigned long long user_id = 0;
    std::string parse_error;
    if (!parse_user_id_from_data(data, user_id, parse_error)) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = parse_error;
        return false;
    }

    const std::string avatar_url = trim_copy(read_string_or_empty(data, "avatar_url"));
    const std::string nickname = trim_copy(read_string_or_empty(data, "nickname"));
    const std::string signature = trim_copy(read_string_or_empty(data, "signature"));
    const std::string requested_theme = trim_copy(read_string_or_empty(data, "theme"));
    const std::string theme = requested_theme.empty() ? "default" : requested_theme;

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile set failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

    std::ostringstream sql;
    sql << "START TRANSACTION; "
        << "UPDATE user_im_profile SET "
        << "nickname='" << sql_escape(nickname) << "', "
        << "avatar_url='" << sql_escape(avatar_url) << "', "
        << "extra=JSON_SET(COALESCE(extra, JSON_OBJECT()), "
        << "'$.signature', '" << sql_escape(signature) << "', "
        << "'$.theme', '" << sql_escape(theme) << "'), "
        << "updated_at=NOW() "
        << "WHERE user_id=" << user_id << " AND deleted_at IS NULL; "
        << "SELECT ROW_COUNT(); "
        << "SELECT "
        << "COALESCE(avatar_url, ''), "
        << "COALESCE(nickname, ''), "
        << "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(extra, '$.signature')), ''), "
        << "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(extra, '$.theme')), 'default') "
        << "FROM user_im_profile "
        << "WHERE user_id=" << user_id << " AND deleted_at IS NULL "
        << "LIMIT 1; "
        << "COMMIT;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile set failed in database";
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.size() < 2U) {
        response_code = protocol_code::PROFILE_NOT_FOUND;
        message = "profile not found";
        return false;
    }

    std::string saved_avatar_url;
    std::string saved_nickname;
    std::string saved_signature;
    std::string saved_theme;
    if (!parse_profile_row_line(lines[1], saved_avatar_url, saved_nickname, saved_signature, saved_theme)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "profile set failed: unexpected profile row";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    json::object profile;
    profile["avatar_url"] = saved_avatar_url;
    profile["nickname"] = saved_nickname;
    profile["signature"] = saved_signature;
    profile["theme"] = saved_theme;
    response_data["profile"] = std::move(profile);
    response_code = protocol_code::OK;
    message = "profile info set accepted";
    return true;
}

bool websocket_session::handle_profile_add_friend(const json::object& data,
                                                  json::object& response_data,
                                                  std::string& message,
                                                  protocol_code& response_code)
{
    unsigned long long user_numeric_id = 0;
    unsigned long long friend_numeric_id = 0;
    std::string parse_error;
    if (!parse_user_numeric_id_from_data(data, user_numeric_id, parse_error)
        || !parse_friend_numeric_id_from_data(data, friend_numeric_id, parse_error)) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = parse_error;
        return false;
    }
    if (user_numeric_id == friend_numeric_id) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = "field 'data.user_numeric_id' and 'data.friend_numeric_id' cannot be the same";
        return false;
    }

    const std::string remark = trim_copy(read_string_or_empty(data, "remark"));
    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "add friend failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

    std::ostringstream sql;
    sql << "START TRANSACTION; "
        << "SET @user_id = (SELECT id FROM user_data WHERE numeric_id=" << user_numeric_id << " LIMIT 1); "
        << "SET @friend_user_id = (SELECT id FROM user_data WHERE numeric_id=" << friend_numeric_id << " LIMIT 1); "
        << "SELECT IFNULL(@user_id, 0); "
        << "SELECT IFNULL(@friend_user_id, 0); "
        << "SELECT COUNT(*) FROM friendships "
        << "WHERE ((user_id=@user_id AND friend_user_id=@friend_user_id) "
        << "OR (user_id=@friend_user_id AND friend_user_id=@user_id)) "
        << "AND status=2; "
        << "INSERT INTO friendships (user_id, friend_user_id, status, remark) "
        << "SELECT @user_id, @friend_user_id, 1, '" << sql_escape(remark) << "' "
        << "FROM DUAL WHERE @user_id IS NOT NULL "
        << "AND @friend_user_id IS NOT NULL "
        << "AND NOT EXISTS(SELECT 1 FROM friendships "
        << "WHERE ((user_id=@user_id AND friend_user_id=@friend_user_id) "
        << "OR (user_id=@friend_user_id AND friend_user_id=@user_id)) AND status=2) "
        << "ON DUPLICATE KEY UPDATE status=1, remark=VALUES(remark); "
        << "INSERT INTO friendships (user_id, friend_user_id, status, remark) "
        << "SELECT @friend_user_id, @user_id, 1, '' "
        << "FROM DUAL WHERE @user_id IS NOT NULL "
        << "AND @friend_user_id IS NOT NULL "
        << "AND NOT EXISTS(SELECT 1 FROM friendships "
        << "WHERE ((user_id=@user_id AND friend_user_id=@friend_user_id) "
        << "OR (user_id=@friend_user_id AND friend_user_id=@user_id)) AND status=2) "
        << "ON DUPLICATE KEY UPDATE status=1; "
        << "COMMIT;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "add friend failed in database";
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.size() < 3U) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "add friend failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    unsigned long long user_id = 0;
    unsigned long long friend_user_id = 0;
    unsigned long long blocked_count = 0;
    if (!parse_unsigned_long_long(trim_copy(lines[0]), user_id)
        || !parse_unsigned_long_long(trim_copy(lines[1]), friend_user_id)
        || !parse_unsigned_long_long(trim_copy(lines[2]), blocked_count)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "add friend failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    if (user_id == 0 || friend_user_id == 0) {
        response_code = protocol_code::PROFILE_NOT_FOUND;
        message = "user not found";
        return false;
    }

    if (blocked_count > 0) {
        response_code = protocol_code::PROFILE_UPDATE_CONFLICT;
        message = "friend relation blocked";
        return false;
    }

    response_data["user_id"] = std::to_string(user_id);
    response_data["friend_user_id"] = std::to_string(friend_user_id);
    response_data["user_numeric_id"] = std::to_string(user_numeric_id);
    response_data["friend_numeric_id"] = std::to_string(friend_numeric_id);
    response_data["status"] = 1;
    response_code = protocol_code::OK;
    message = "friend added";
    return true;
}

bool websocket_session::handle_profile_list_friends(const json::object& data,
                                                    json::object& response_data,
                                                    std::string& message,
                                                    protocol_code& response_code)
{
    unsigned long long requester_numeric_id = 0;
    std::string parse_error;
    if (!parse_numeric_id_from_data(data, requester_numeric_id, parse_error)) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = parse_error;
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "list friends failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

    std::ostringstream sql;
    sql << "SET @user_id = (SELECT id FROM user_data WHERE numeric_id=" << requester_numeric_id << " LIMIT 1); "
        << "SELECT IFNULL(@user_id, 0); "
        << "SELECT "
        << "u.id, "
        << "COALESCE(u.numeric_id, 0), "
        << "u.username, "
        << "u.status, "
        << "COALESCE(p.is_online, 0), "
        << "COALESCE(DATE_FORMAT(p.last_seen_at, '%Y-%m-%dT%H:%i:%sZ'), ''), "
        << "COALESCE(p.nickname, ''), "
        << "COALESCE(p.avatar_url, ''), "
        << "COALESCE(p.bio, '') "
        << "FROM friendships f "
        << "JOIN user_data u ON u.id=f.friend_user_id "
        << "LEFT JOIN user_im_profile p ON p.user_id=u.id AND p.deleted_at IS NULL "
        << "WHERE f.user_id=@user_id AND f.status=1 "
        << "ORDER BY u.id ASC;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "list friends failed in database";
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.empty()) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "list friends failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    unsigned long long requester_user_id = 0;
    if (!parse_unsigned_long_long(trim_copy(lines[0]), requester_user_id)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "list friends failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }
    if (requester_user_id == 0ULL) {
        response_code = protocol_code::PROFILE_NOT_FOUND;
        message = "user not found";
        return false;
    }

    json::array friends;
    for (std::size_t i = 1; i < lines.size(); ++i) {
        const std::vector<std::string> cols = split_by_tab(lines[i]);
        if (cols.size() < 9U) {
            response_code = protocol_code::INTERNAL_ERROR;
            message = "list friends failed: unexpected database output";
            response_data["debug"].as_object()["mysql_output"] = command_output;
            return false;
        }
        unsigned long long friend_user_id = 0;
        unsigned long long friend_numeric_id = 0;
        unsigned long long user_status = 0;
        unsigned long long is_online = 0;
        if (!parse_unsigned_long_long(cols[0], friend_user_id)
            || !parse_unsigned_long_long(cols[1], friend_numeric_id)
            || !parse_unsigned_long_long(cols[3], user_status)
            || !parse_unsigned_long_long(cols[4], is_online)) {
            response_code = protocol_code::INTERNAL_ERROR;
            message = "list friends failed: unexpected database output";
            response_data["debug"].as_object()["mysql_output"] = command_output;
            return false;
        }
        unsigned int expected_numeric_id = 0U;
        if (!build_numeric_user_id(friend_user_id, expected_numeric_id)
            || friend_numeric_id != static_cast<unsigned long long>(expected_numeric_id)) {
            response_code = protocol_code::INTERNAL_ERROR;
            message = "list friends failed: inconsistent user identity in database";
            response_data["debug"].as_object()["mysql_output"] = command_output;
            return false;
        }

        json::object item;
        item["user_id"] = std::to_string(friend_user_id);
        item["numeric_id"] = std::to_string(friend_numeric_id);
        item["username"] = (cols[2] == "\\N") ? "" : cols[2];
        item["status"] = static_cast<int>(user_status);
        item["user_status"] = static_cast<int>(user_status);
        item["is_online"] = (is_online != 0ULL);
        item["last_seen_at"] = (cols[5] == "\\N") ? "" : cols[5];
        item["nickname"] = (cols[6] == "\\N") ? "" : cols[6];
        item["avatar_url"] = (cols[7] == "\\N") ? "" : cols[7];
        item["bio"] = (cols[8] == "\\N") ? "" : cols[8];
        friends.push_back(std::move(item));
    }

    response_data["numeric_id"] = std::to_string(requester_numeric_id);
    response_data["user_id"] = std::to_string(requester_user_id);
    response_data["friends"] = std::move(friends);
    response_code = protocol_code::OK;
    message = "friend list request accepted";
    return true;
}

bool websocket_session::handle_profile_delete_friend(const json::object& data,
                                                     json::object& response_data,
                                                     std::string& message,
                                                     protocol_code& response_code)
{
    unsigned long long user_numeric_id = 0;
    unsigned long long friend_numeric_id = 0;
    std::string parse_error;
    if (!parse_user_numeric_id_from_data(data, user_numeric_id, parse_error)
        || !parse_friend_numeric_id_from_data(data, friend_numeric_id, parse_error)) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = parse_error;
        return false;
    }
    if (user_numeric_id == friend_numeric_id) {
        response_code = protocol_code::PROFILE_VALIDATION_FAILED;
        message = "field 'data.user_numeric_id' and 'data.friend_numeric_id' cannot be the same";
        return false;
    }

    const mysql_config cfg = load_mysql_config();
    response_data["debug"] = build_mysql_config_debug(cfg);
    std::string config_error;
    if (!is_mysql_config_valid(cfg, config_error)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "delete friend failed: database config missing";
        response_data["debug"].as_object()["config_error"] = config_error;
        return false;
    }

    std::ostringstream sql;
    sql << "START TRANSACTION; "
        << "SET @user_id = (SELECT id FROM user_data WHERE numeric_id=" << user_numeric_id << " LIMIT 1); "
        << "SET @friend_user_id = (SELECT id FROM user_data WHERE numeric_id=" << friend_numeric_id << " LIMIT 1); "
        << "SELECT IFNULL(@user_id, 0); "
        << "SELECT IFNULL(@friend_user_id, 0); "
        << "DELETE FROM friendships "
        << "WHERE (@user_id IS NOT NULL AND @friend_user_id IS NOT NULL) "
        << "AND ((user_id=@user_id AND friend_user_id=@friend_user_id) "
        << "OR (user_id=@friend_user_id AND friend_user_id=@user_id)); "
        << "SELECT ROW_COUNT(); "
        << "COMMIT;";

    std::string command_output;
    int exit_code = 0;
    if (!run_mysql_sql(cfg, sql.str(), command_output, exit_code)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "delete friend failed in database";
        response_data["debug"] = build_mysql_config_debug(cfg);
        response_data["debug"].as_object()["mysql_exit_code"] = exit_code;
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    const std::vector<std::string> lines = collect_non_empty_lines(command_output);
    if (lines.size() < 3U) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "delete friend failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    unsigned long long user_id = 0;
    unsigned long long friend_user_id = 0;
    unsigned long long deleted_rows = 0;
    if (!parse_unsigned_long_long(trim_copy(lines[0]), user_id)
        || !parse_unsigned_long_long(trim_copy(lines[1]), friend_user_id)
        || !parse_unsigned_long_long(trim_copy(lines[2]), deleted_rows)) {
        response_code = protocol_code::INTERNAL_ERROR;
        message = "delete friend failed: unexpected database output";
        response_data["debug"].as_object()["mysql_output"] = command_output;
        return false;
    }

    if (user_id == 0ULL || friend_user_id == 0ULL) {
        response_code = protocol_code::PROFILE_NOT_FOUND;
        message = "user not found";
        return false;
    }

    response_data["user_id"] = std::to_string(user_id);
    response_data["friend_user_id"] = std::to_string(friend_user_id);
    response_data["user_numeric_id"] = std::to_string(user_numeric_id);
    response_data["friend_numeric_id"] = std::to_string(friend_numeric_id);
    response_data["deleted_rows"] = static_cast<std::uint64_t>(deleted_rows);
    response_data["removed"] = (deleted_rows > 0ULL);
    response_code = protocol_code::OK;
    message = "friend deleted";
    return true;
}

bool websocket_session::parse_envelope(const std::string& payload,
                                       envelope& out,
                                       std::string& error_message,
                                       protocol_code& error_code)
{
    boost::system::error_code ec;
    json::value parsed = json::parse(payload, ec);
    if (ec) {
        error_message = "invalid JSON payload";
        error_code = protocol_code::INVALID_REQUEST;
        return false;
    }

    if (!parsed.is_object()) {
        error_message = "payload must be a JSON object";
        error_code = protocol_code::INVALID_REQUEST;
        return false;
    }

    const json::object& root = parsed.as_object();

    auto type_it = root.find("type");
    auto action_it = root.find("action");
    auto request_id_it = root.find("request_id");
    auto data_it = root.find("data");

    if (type_it == root.end() || !type_it->value().is_string()) {
        error_message = "field 'type' is required and must be string";
        error_code = protocol_code::INVALID_REQUEST;
        return false;
    }
    if (action_it == root.end() || !action_it->value().is_string()) {
        error_message = "field 'action' is required and must be string";
        error_code = protocol_code::INVALID_REQUEST;
        return false;
    }
    if (request_id_it == root.end() || !request_id_it->value().is_string()) {
        error_message = "field 'request_id' is required and must be string";
        error_code = protocol_code::REQUEST_ID_MISSING;
        return false;
    }
    if (data_it == root.end() || !data_it->value().is_object()) {
        error_message = "field 'data' is required and must be object";
        error_code = protocol_code::INVALID_REQUEST;
        return false;
    }

    out.type = type_it->value().as_string().c_str();
    out.action = action_it->value().as_string().c_str();
    out.request_id = request_id_it->value().as_string().c_str();
    out.data = data_it->value().as_object();

    if (!is_supported_type(out.type)) {
        error_message = "field 'type' must be one of AUTH, PROFILE, MESSAGE";
        error_code = protocol_code::UNSUPPORTED_TYPE;
        return false;
    }

    if (out.action.empty()) {
        error_message = "field 'action' cannot be empty";
        error_code = protocol_code::INVALID_ACTION;
        return false;
    }

    if (!is_supported_action(out.type, out.action)) {
        error_message = "field 'action' is not supported for this 'type'";
        error_code = protocol_code::INVALID_ACTION;
        return false;
    }

    if (out.request_id.empty()) {
        error_message = "field 'request_id' cannot be empty";
        error_code = protocol_code::REQUEST_ID_MISSING;
        return false;
    }

    if (!validate_data_schema(out.type, out.action, out.data, error_message, error_code)) {
        return false;
    }

    error_code = protocol_code::OK;
    return true;
}

std::string websocket_session::build_response_payload(const std::string& type,
                                                      const std::string& action,
                                                      const std::string& request_id,
                                                      protocol_code code,
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
    response["code"] = static_cast<int>(code);
    response["data"] = std::move(data);
    return json::serialize(response);
}

void websocket_session::bind_authenticated_user(std::uint64_t user_id,
                                                std::uint64_t numeric_id,
                                                const std::string& username,
                                                json::object* response_data)
{
    if (authenticated_user_id_ == user_id && authenticated_user_id_ != 0ULL) {
        std::cout << "[presence] bind skip same user session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " user_id=" << user_id
                  << " numeric_id=" << numeric_id << std::endl;
        authenticated_numeric_id_ = numeric_id;
        authenticated_username_ = username;
        return;
    }

    if (authenticated_user_id_ != 0ULL && authenticated_user_id_ != user_id) {
        unbind_authenticated_user(false, response_data);
    }

    bool should_mark_online = false;
    std::size_t old_count = 0U;
    std::size_t new_count = 0U;
    {
        std::lock_guard<std::mutex> lock(g_presence_mutex);
        std::size_t& count = g_online_session_counts[user_id];
        old_count = count;
        should_mark_online = (count == 0U);
        ++count;
        new_count = count;
    }

    authenticated_user_id_ = user_id;
    authenticated_numeric_id_ = numeric_id;
    authenticated_username_ = username;

    std::cout << "[presence] bind session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " user_id=" << user_id
              << " numeric_id=" << numeric_id
              << " old_count=" << old_count
              << " new_count=" << new_count
              << " should_mark_online=" << (should_mark_online ? "true" : "false")
              << std::endl;

    if (should_mark_online && !mark_user_presence(user_id, true, response_data) && response_data != nullptr) {
        (*response_data)["presence_sync_failed"] = true;
        std::cout << "[presence] bind mark online failed session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " user_id=" << user_id << std::endl;
    }
}

void websocket_session::unbind_authenticated_user(bool explicit_logout,
                                                  json::object* response_data)
{
    if (authenticated_user_id_ == 0ULL) {
        std::cout << "[presence] unbind skipped empty session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " explicit_logout=" << (explicit_logout ? "true" : "false")
                  << std::endl;
        return;
    }

    const std::uint64_t user_id = authenticated_user_id_;
    bool should_mark_offline = false;
    std::size_t old_count = 0U;
    std::size_t new_count = 0U;
    {
        std::lock_guard<std::mutex> lock(g_presence_mutex);
        const auto it = g_online_session_counts.find(user_id);
        if (it != g_online_session_counts.end()) {
            old_count = it->second;
            if (it->second > 1U) {
                --it->second;
                new_count = it->second;
            } else {
                g_online_session_counts.erase(it);
                should_mark_offline = true;
                new_count = 0U;
            }
        } else {
            should_mark_offline = true;
            old_count = 0U;
            new_count = 0U;
        }
    }

    std::cout << "[presence] unbind session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " user_id=" << user_id
              << " numeric_id=" << authenticated_numeric_id_
              << " explicit_logout=" << (explicit_logout ? "true" : "false")
              << " old_count=" << old_count
              << " new_count=" << new_count
              << " should_mark_offline=" << (should_mark_offline ? "true" : "false")
              << std::endl;

    authenticated_user_id_ = 0ULL;
    authenticated_numeric_id_ = 0ULL;
    authenticated_username_.clear();

    if (should_mark_offline && !mark_user_presence(user_id, false, response_data) && response_data != nullptr) {
        (*response_data)["presence_sync_failed"] = true;
        std::cout << "[presence] unbind mark offline failed session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " user_id=" << user_id << std::endl;
    }

    if (explicit_logout && response_data != nullptr) {
        (*response_data)["presence_event"] = "logout";
    }
}

websocket_session::websocket_session(tcp::socket socket)
    : ws_(std::move(socket))
{
    try {
        auto endpoint = ws_.next_layer().remote_endpoint();
        remote_endpoint_ = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
        std::cout << "WebSocket session created for " << remote_endpoint_ << std::endl;
        std::cout << "[presence] session created session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_ << std::endl;
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
    if(ec == websocket::error::closed) {
        std::cout << "[presence] websocket closed session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " bound_user_id=" << authenticated_user_id_
                  << std::endl;
        return;
    }

    if(ec) {
        std::cerr << "read: " << ec.message() << std::endl;
        std::cout << "[presence] websocket read error session=" << static_cast<const void*>(this)
                  << " remote=" << remote_endpoint_
                  << " bound_user_id=" << authenticated_user_id_
                  << " error=" << ec.message() << std::endl;
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
    protocol_code response_code = protocol_code::INTERNAL_ERROR;
    bool ok = false;
    std::string message;

    if (!ws_.got_text()) {
        response_code = protocol_code::INVALID_REQUEST;
        message = "binary frame is not supported, use text JSON payload";
        response_data["received_format"] = "binary";
    } else if (!parse_envelope(payload, request, error_message, response_code)) {
        message = error_message;
        response_data["received_payload"] = payload;
    } else {
        response_type = request.type;
        response_action = request.action;
        response_request_id = request.request_id;
        response_code = protocol_code::OK;
        if (request.type == "AUTH" && request.action == "LOGIN") {
            ok = handle_login(request.data, response_data, message, response_code);
        } else if (request.type == "AUTH" && request.action == "LOGOUT") {
            ok = handle_logout(request.data, response_data, message, response_code);
        } else if (request.type == "AUTH" && request.action == "REGISTER") {
            ok = handle_register(request.data, response_data, message, response_code);
        } else if (request.type == "PROFILE" && request.action == "GET") {
            ok = handle_profile_get(request.data, response_data, message, response_code);
        } else if (request.type == "PROFILE" && request.action == "GET_INFO") {
            ok = handle_profile_get_info(request.data, response_data, message, response_code);
        } else if (request.type == "PROFILE" && request.action == "SET_INFO") {
            ok = handle_profile_set_info(request.data, response_data, message, response_code);
        } else if (request.type == "PROFILE" && request.action == "ADD_FRIEND") {
            ok = handle_profile_add_friend(request.data, response_data, message, response_code);
        } else if (request.type == "PROFILE" && request.action == "LIST_FRIENDS") {
            ok = handle_profile_list_friends(request.data, response_data, message, response_code);
        } else if (request.type == "PROFILE" && request.action == "DELETE_FRIEND") {
            ok = handle_profile_delete_friend(request.data, response_data, message, response_code);
        } else {
            ok = true;
            message = "request accepted";
        }
        json::object safe_echo = request.data;
        if (request.type == "AUTH") {
            safe_echo.erase("password");
            safe_echo.erase("token");
            safe_echo.erase("refresh_token");
        }
        response_data["echo"] = std::move(safe_echo);
    }

    outbound_message_ = build_response_payload(
        response_type,
        response_action,
        response_request_id,
        response_code,
        ok,
        message,
        std::move(response_data));

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
    std::cout << "[presence] session destroying session=" << static_cast<const void*>(this)
              << " remote=" << remote_endpoint_
              << " bound_user_id=" << authenticated_user_id_
              << " bound_numeric_id=" << authenticated_numeric_id_
              << std::endl;
    unbind_authenticated_user(false, nullptr);
    if (!remote_endpoint_.empty()) {
        std::cout << "WebSocket session closed for " << remote_endpoint_ << std::endl;
    }
}

} // namespace server
} // namespace qt_server
