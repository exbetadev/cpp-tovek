// server.cpp - made getscriptbytecode
#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
static const uint32_t FLAG_DONT_REUSE_VAR = 1u << 0;
static const uint32_t FLAG_NO_SYNTH_HELPERS = 1u << 1;
static const uint32_t FLAG_ASSUME_NO_NAN = 1u << 2;
static const uint32_t FLAG_STRICT_NO_SYNTHETIC_CONTROL = 1u << 3;
static const uint32_t FLAG_EMIT_BINDING_PROVENANCE = 1u << 4;
static const uint32_t FLAG_SYNTHESIZE_ARITHMETIC_LOOPS = 1u << 5;
static const uint32_t FLAG_COMPACT_ANNOTATIONS = 1u << 6;
static const uint32_t FLAG_COMPACT_STYLE = 1u << 7;
static const uint32_t FLAG_ASSUME_STANDARD_LIBRARIES = 1u << 8;
static const uint32_t FLAG_ALL =
FLAG_DONT_REUSE_VAR | FLAG_NO_SYNTH_HELPERS | FLAG_ASSUME_NO_NAN |
FLAG_STRICT_NO_SYNTHETIC_CONTROL | FLAG_EMIT_BINDING_PROVENANCE |
FLAG_SYNTHESIZE_ARITHMETIC_LOOPS | FLAG_COMPACT_ANNOTATIONS |
FLAG_COMPACT_STYLE | FLAG_ASSUME_STANDARD_LIBRARIES;
static const uint8_t MDB1_FLAG_DONT_REUSE_VAR = (uint8_t)FLAG_DONT_REUSE_VAR;
static const uint8_t MDB1_FLAG_STRICT_NO_SYNTHETIC = (uint8_t)FLAG_STRICT_NO_SYNTHETIC_CONTROL;
static const uint8_t MDB1_SUPPORTED_FLAGS =
(uint8_t)(MDB1_FLAG_DONT_REUSE_VAR | MDB1_FLAG_STRICT_NO_SYNTHETIC);
struct DecompileOptions {
    bool dont_reuse_var = false;
    bool no_synth_helpers = false;
    bool assume_no_nan = false;
    bool emit_binding_provenance = false;
    bool synthesize_arithmetic_loops = false;
    bool compact_annotations = false;
    bool compact_style = false;
    bool assume_standard_libraries = false;
    int control_flow_policy = 0;
    DecompileOptions UnionWith(const DecompileOptions& o) const {
        DecompileOptions r = *this;
        r.dont_reuse_var = r.dont_reuse_var || o.dont_reuse_var;
        r.no_synth_helpers = r.no_synth_helpers || o.no_synth_helpers;
        r.assume_no_nan = r.assume_no_nan || o.assume_no_nan;
        r.emit_binding_provenance = r.emit_binding_provenance || o.emit_binding_provenance;
        r.synthesize_arithmetic_loops = r.synthesize_arithmetic_loops || o.synthesize_arithmetic_loops;
        r.compact_annotations = r.compact_annotations || o.compact_annotations;
        r.compact_style = r.compact_style || o.compact_style;
        r.assume_standard_libraries = r.assume_standard_libraries || o.assume_standard_libraries;
        if (o.control_flow_policy == 1) r.control_flow_policy = 1;
        return r;
    }
    static DecompileOptions FromFlagBits(uint32_t bits, bool* ok);
};

struct OptString { bool has = false; std::string value; };
std::string try_decompile_bytecode_with_options(const uint8_t* data, size_t len,
    uint8_t key, const OptString& script_name, const DecompileOptions& opt);
struct BatchInput { const uint8_t* bytecode; size_t len; uint8_t key; const std::string* script_name; };
struct BatchOutcome { bool ok; std::string value; };
std::vector<BatchOutcome> decompile_batch_with_options(
    const std::vector<BatchInput>& inputs, const DecompileOptions& opt);
void install_quiet_panic_hook();
static const char* BIND_ADDR = "127.0.0.1";
static const int     BIND_PORT = 6967;
static const uint8_t DEFAULT_KEY = 203;
static const size_t RAW_BODY_LIMIT = 16u * 1024u * 1024u;
static const size_t BATCH_BODY_LIMIT = 64u * 1024u * 1024u;
static const size_t LEGACY_BODY_LIMIT = 2u * 1024u * 1024u;
static const size_t MAX_ENTRIES = 50000;
static const size_t MAX_NAME_LEN = 4u * 1024u;
static const size_t MAX_CODE_LEN = 16u * 1024u * 1024u;
static const int    MAX_CONCURRENT_JOBS = 4;
static const int    DEFAULT_QUEUE_LIMIT = 1024;
static const char* RETRY_AFTER_SECS = "1";
static const char* UPLOAD_TIMEOUT_ENV = "TOVEK_UPLOAD_TIMEOUT_SECS";
static const char* QUEUE_TIMEOUT_ENV = "TOVEK_QUEUE_TIMEOUT_SECS";
static const char* QUEUE_LIMIT_ENV = "TOVEK_QUEUE_LIMIT";

typedef std::chrono::steady_clock clk;

static std::string to_lower_fn(const std::string& in) {
    std::string s = in;
    for (size_t i = 0; i < s.size(); ++i) s[i] = (char)tolower((unsigned char)s[i]);
    return s;
}
static std::string trim_fn(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
static std::chrono::seconds parse_seconds_fn(const std::string& name, const std::string& value) {
    try {
        long long x = std::stoll(value);
        if (x > 0 && x <= 4294967295LL) return std::chrono::seconds((long)x);
    }
    catch (...) {}
    throw std::runtime_error(name + " must be a positive 32-bit integer number of seconds");
}
static size_t parse_queue_limit_fn(const std::string& value) {
    try {
        long long x = std::stoll(value);
        if (x >= 0 && x <= 4294967295LL) return (size_t)x;
    }
    catch (...) {}
    throw std::runtime_error("TOVEK_QUEUE_LIMIT must be a non-negative 32-bit integer");
}
static OptString env_var_fn(const char* name) {
    OptString r;
    char* buf = 0;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, name) == 0 && buf != 0) {
        r.has = true;
        r.value = buf;
        free(buf);
    }
    return r;
}
static std::mutex g_log_mutex;

static void console_color_fn(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

static void log_success_fn(const std::string& script_path) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD orig = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    if (GetConsoleScreenBufferInfo(h, &csbi)) orig = csbi.wAttributes;
    console_color_fn(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "[ex:beta] Successfully decompiled " << script_path << std::endl;
    console_color_fn(orig);
}

static void log_error_fn(const std::string& script_path, const std::string& error) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD orig = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    if (GetConsoleScreenBufferInfo(h, &csbi)) orig = csbi.wAttributes;
    console_color_fn(FOREGROUND_RED | FOREGROUND_INTENSITY);
    if (script_path.empty())
        std::cout << "ERROR: " << error << std::endl;
    else
        std::cout << "ERROR " << script_path << ": " << error << std::endl;
    console_color_fn(orig);
}
struct Semaphore {
    std::mutex m;
    std::condition_variable cv;
    size_t count;
    explicit Semaphore(size_t n) : count(n) {}
    bool try_acquire() {
        std::lock_guard<std::mutex> l(m);
        if (count == 0) return false;
        --count;
        return true;
    }
    template <class R, class P>
    bool acquire_for(std::chrono::duration<R, P> d) {
        std::unique_lock<std::mutex> l(m);
        if (!cv.wait_for(l, d, [this] { return count > 0; })) return false;
        --count;
        return true;
    }
    void release() {
        { std::lock_guard<std::mutex> l(m); ++count; }
        cv.notify_one();
    }
};

struct AppState {
    std::shared_ptr<Semaphore> cpu;
    std::shared_ptr<Semaphore> queue;
    std::chrono::seconds queue_timeout;
    std::chrono::seconds upload_timeout;
    AppState() : queue_timeout(120), upload_timeout(30) {}
};
static AppState g_state;
static std::string base64_decode_fn(const std::string& in) {
    static int T[256];
    static bool init = false;
    if (!init) {
        memset(T, -1, sizeof T);
        const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; A[i]; ++i) T[(unsigned char)A[i]] = i;
        init = true;
    }
    std::string out;
    int val = 0, bits = 0;
    for (size_t k = 0; k < in.size(); ++k) {
        char c = in[k];
        if (c == '=') break;
        if (isspace((unsigned char)c)) continue;
        int d = T[(unsigned char)c];
        if (d < 0) throw std::runtime_error("base64: invalid character");
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((char)((val >> bits) & 0xFF)); }
    }
    return out;
}

static std::string base64_encode_fn(const uint8_t* data, size_t len) {
    static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | (uint32_t)data[i + 2];
        out += A[(v >> 18) & 63]; out += A[(v >> 12) & 63];
        out += A[(v >> 6) & 63]; out += A[v & 63];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)data[i] << 16;
        out += A[(v >> 18) & 63]; out += A[(v >> 12) & 63]; out += "==";
    }
    else if (rem == 2) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
        out += A[(v >> 18) & 63]; out += A[(v >> 12) & 63];
        out += A[(v >> 6) & 63]; out += '=';
    }
    return out;
}
struct HttpRequest {
    std::string method, path;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
};

static std::string get_header_fn(const HttpRequest& r, const std::string& name) {
    std::map<std::string, std::string>::const_iterator it = r.headers.find(to_lower_fn(name));
    if (it == r.headers.end()) return "";
    return it->second;
}

static void send_all_fn(SOCKET fd, const char* p, size_t n) {
    while (n > 0) {
        size_t chunk = n > 1048576u ? 1048576u : n;
        int w = send(fd, p, (int)chunk, 0);
        if (w <= 0) return;
        p += w; n -= (size_t)w;
    }
}

static void send_resp_fn(SOCKET fd, int code, const std::string& reason,
    std::map<std::string, std::string> h, const std::string& body) {
    if (h.find("Connection") == h.end()) h["Connection"] = "close";
    std::ostringstream oss;
    oss << "HTTP/1.1 " << code << " " << reason << "\r\n";
    oss << "Content-Length: " << (unsigned long long)body.size() << "\r\n";
    for (std::map<std::string, std::string>::iterator it = h.begin(); it != h.end(); ++it)
        oss << it->first << ": " << it->second << "\r\n";
    oss << "\r\n";
    std::string head = oss.str();
    send_all_fn(fd, head.data(), head.size());
    if (!body.empty()) send_all_fn(fd, body.data(), body.size());
}
DecompileOptions DecompileOptions::FromFlagBits(uint32_t bits, bool* ok) {
    DecompileOptions o;
    if ((bits & ~FLAG_ALL) != 0) { *ok = false; return o; }
    o.dont_reuse_var = (bits & FLAG_DONT_REUSE_VAR) != 0;
    o.no_synth_helpers = (bits & FLAG_NO_SYNTH_HELPERS) != 0;
    o.assume_no_nan = (bits & FLAG_ASSUME_NO_NAN) != 0;
    o.emit_binding_provenance = (bits & FLAG_EMIT_BINDING_PROVENANCE) != 0;
    o.synthesize_arithmetic_loops = (bits & FLAG_SYNTHESIZE_ARITHMETIC_LOOPS) != 0;
    o.compact_annotations = (bits & FLAG_COMPACT_ANNOTATIONS) != 0;
    o.compact_style = (bits & FLAG_COMPACT_STYLE) != 0;
    o.assume_standard_libraries = (bits & FLAG_ASSUME_STANDARD_LIBRARIES) != 0;
    o.control_flow_policy = (bits & FLAG_STRICT_NO_SYNTHETIC_CONTROL) != 0 ? 1 : 0;
    *ok = true;
    return o;
}

static DecompileOptions parse_flags_text_fn(const std::string& raw_in) {
    DecompileOptions o;
    std::string raw = trim_fn(raw_in);
    if (raw.empty()) return o;
    bool all_digits = !raw.empty();
    for (size_t i = 0; i < raw.size(); ++i)
        if (!isdigit((unsigned char)raw[i])) { all_digits = false; break; }
    if (all_digits) {
        unsigned long bits = strtoul(raw.c_str(), 0, 10);
        bool ok = false;
        DecompileOptions v = DecompileOptions::FromFlagBits((uint32_t)bits, &ok);
        if (!ok) throw std::runtime_error("unsupported decompile flag bits: " + raw);
        return v;
    }
    std::string token;
    for (size_t i = 0; i <= raw.size(); ++i) {
        char c = (i < raw.size()) ? raw[i] : ',';
        bool sep = (c == ',' || c == '|' || c == ';' || isspace((unsigned char)c));
        if (!sep) { token.push_back(c); continue; }
        std::string t = trim_fn(token);
        token.clear();
        if (t.empty()) continue;
        for (size_t j = 0; j < t.size(); ++j) {
            if (t[j] == '-') t[j] = '_';
            t[j] = (char)toupper((unsigned char)t[j]);
        }
        if (t == "NONE") {}
        else if (t == "DONT_REUSE_VAR") o.dont_reuse_var = true;
        else if (t == "COMPACT_STYLE") o.compact_style = true;
        else if (t == "ASSUME_STANDARD_LIBRARIES") o.assume_standard_libraries = true;
        else if (t == "STRICT_NO_SYNTHETIC_CONTROL") o.control_flow_policy = 1;
        else throw std::runtime_error("unsupported decompile flag: " + t);
    }
    return o;
}

static bool parse_bool_fn(const std::string& raw, const std::string& field) {
    std::string t = to_lower_fn(trim_fn(raw));
    if (t == "1" || t == "true" || t == "yes" || t == "on") return true;
    if (t == "0" || t == "false" || t == "no" || t == "off") return false;
    throw std::runtime_error(field + " must be a boolean (true/false)");
}

static void validate_options_fn(const DecompileOptions& o) {
    if (o.compact_annotations && !o.emit_binding_provenance)
        throw std::runtime_error("compact annotations require an artifact API with binding provenance");
}

static DecompileOptions parse_options_headers_fn(const HttpRequest& r) {
    DecompileOptions o;
    std::string flags = get_header_fn(r, "x-decompile-flags");
    if (!flags.empty()) o = o.UnionWith(parse_flags_text_fn(flags));
    std::string dont = get_header_fn(r, "x-dont-reuse-var");
    if (!dont.empty() && parse_bool_fn(dont, "x-dont-reuse-var")) o.dont_reuse_var = true;
    validate_options_fn(o);
    return o;
}

static uint8_t parse_key_header_fn(const HttpRequest& r) {
    std::string v = get_header_fn(r, "x-encode-key");
    if (v.empty()) return DEFAULT_KEY;
    try {
        long x = std::stol(trim_fn(v));
        if (x >= 0 && x <= 255) return (uint8_t)x;
    }
    catch (...) {}
    throw std::runtime_error("x-encode-key must be an integer 0..=255");
}

static bool is_json_content_type_fn(const HttpRequest& r) {
    std::string v = to_lower_fn(get_header_fn(r, "content-type"));
    size_t p = v.find(';');
    if (p != std::string::npos) v = v.substr(0, p);
    return trim_fn(v) == "application/json";
}
struct ParsedItem {
    bool ready = false;
    std::vector<uint8_t> code;
    uint8_t key = DEFAULT_KEY;
    DecompileOptions opt;
    OptString id, name;
    std::string error;
};

static std::string json_unescape_fn(const std::string& s, size_t* idx) {
    std::string out;
    size_t i = *idx;
    while (i < s.size() && s[i] != '"') {
        char c = s[i++];
        if (c == '\\' && i < s.size()) {
            char e = s[i++];
            switch (e) {
            case 'n': out += '\n'; break;
            case 't': out += '\t'; break;
            case 'r': out += '\r'; break;
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            default: out += e;
            }
        }
        else out += c;
    }
    if (i < s.size()) ++i;
    *idx = i;
    return out;
}

static OptString json_get_string_fn(const std::string& obj, const char* key) {
    OptString r;
    std::string quoted = std::string("\"") + key + "\"";
    size_t p = obj.find(quoted);
    if (p == std::string::npos) return r;
    size_t colon = obj.find(':', p);
    if (colon == std::string::npos) return r;
    size_t quote = obj.find('"', colon);
    if (quote == std::string::npos) return r;
    size_t i = quote + 1;
    r.has = true;
    r.value = json_unescape_fn(obj, &i);
    return r;
}

static bool json_get_bool_fn(const std::string& obj, const char* key) {
    std::string quoted = std::string("\"") + key + "\"";
    size_t p = obj.find(quoted);
    if (p == std::string::npos) return false;
    size_t colon = obj.find(':', p);
    if (colon == std::string::npos) return false;
    size_t v = colon + 1;
    while (v < obj.size() && isspace((unsigned char)obj[v])) ++v;
    return v < obj.size() && obj[v] == 't';
}

static std::vector<ParsedItem> parse_json_batch_fn(const std::vector<uint8_t>& body,
    const DecompileOptions& header_options) {
    std::string s(body.begin(), body.end());
    size_t scripts_key = s.find("\"scripts\"");
    if (scripts_key == std::string::npos)
        throw std::runtime_error("bad request: invalid JSON batch: missing scripts");
    uint8_t key = DEFAULT_KEY;
    size_t pk = s.find("\"key\"");
    if (pk != std::string::npos) {
        size_t colon = s.find(':', pk);
        if (colon != std::string::npos) key = (uint8_t)strtoul(s.c_str() + colon + 1, 0, 10);
    }
    DecompileOptions body_options;
    size_t pf = s.find("\"flags\"");
    if (pf != std::string::npos) {
        size_t colon = s.find(':', pf);
        size_t quote = s.find('"', colon);
        if (colon != std::string::npos && quote != std::string::npos) {
            size_t i = quote + 1;
            body_options = body_options.UnionWith(parse_flags_text_fn(json_unescape_fn(s, &i)));
        }
    }
    if (json_get_bool_fn(s, "dontReuseVar") || json_get_bool_fn(s, "dont_reuse_var"))
        body_options.dont_reuse_var = true;
    DecompileOptions options = header_options.UnionWith(body_options);
    validate_options_fn(options);
    size_t array = s.find('[', scripts_key);
    if (array == std::string::npos)
        throw std::runtime_error("bad request: invalid JSON batch: scripts is not an array");
    size_t end = s.rfind(']');
    std::vector<ParsedItem> out;
    size_t i = array;
    while (true) {
        i = s.find('{', i);
        if (i == std::string::npos || i >= end) break;
        size_t j = s.find('}', i);
        if (j == std::string::npos) break;
        std::string obj = s.substr(i, j - i);
        i = j + 1;
        if (obj.find("bytecode") == std::string::npos) continue;
        if (out.size() >= MAX_ENTRIES)
            throw std::runtime_error("bad request: too many scripts: (max 50000)");
        ParsedItem item;
        item.key = key; item.opt = options;
        item.id = json_get_string_fn(obj, "id");
        item.name = json_get_string_fn(obj, "scriptName");
        if (!item.name.has) item.name = json_get_string_fn(obj, "script_name");
        size_t bp = obj.find("\"bytecode\"");
        size_t colon = obj.find(':', bp);
        size_t quote = obj.find('"', colon);
        if (bp == std::string::npos || colon == std::string::npos || quote == std::string::npos) {
            item.ready = false; item.error = "base64: missing bytecode field";
            out.push_back(item); continue;
        }
        size_t bi = quote + 1;
        std::string encoded = json_unescape_fn(obj, &bi);
        try {
            std::string decoded = base64_decode_fn(encoded);
            item.ready = true;
            item.code.assign(decoded.begin(), decoded.end());
        }
        catch (const std::exception& e) {
            item.ready = false; item.error = std::string("base64: ") + e.what();
        }
        out.push_back(item);
    }
    return out;
}

static uint32_t read_u32_fn(const std::vector<uint8_t>& b, size_t* pp, bool* ok) {
    size_t p = *pp;
    if (p + 4 > b.size()) { *ok = false; return 0; }
    uint32_t v = (uint32_t)b[p] | ((uint32_t)b[p + 1] << 8) |
        ((uint32_t)b[p + 2] << 16) | ((uint32_t)b[p + 3] << 24);
    *pp = p + 4;
    return v;
}

static std::vector<ParsedItem> parse_mdb1_batch_fn(const std::vector<uint8_t>& body,
    const DecompileOptions& header_options) {
    if (body.size() < 12) throw std::runtime_error("bad request: MDB1: truncated header");
    if (memcmp(&body[0], "MDB1", 4) != 0)
        throw std::runtime_error("bad request: MDB1: bad magic");
    uint8_t version = body[4], key = body[5], flags = body[6], reserved = body[7];
    if (version != 1) throw std::runtime_error("bad request: MDB1: unsupported version 1 request");
    if ((flags & (uint8_t)~MDB1_SUPPORTED_FLAGS) != 0)
        throw std::runtime_error("bad request: MDB1: unsupported flags byte");
    if (reserved != 0)
        throw std::runtime_error("bad request: MDB1: reserved byte must be zero in v1");
    DecompileOptions mo;
    if ((flags & MDB1_FLAG_DONT_REUSE_VAR) != 0) mo.dont_reuse_var = true;
    if ((flags & MDB1_FLAG_STRICT_NO_SYNTHETIC) != 0) mo.control_flow_policy = 1;
    DecompileOptions options = header_options.UnionWith(mo);
    validate_options_fn(options);
    size_t p = 8; bool ok = true;
    uint32_t count = read_u32_fn(body, &p, &ok);
    if (!ok) throw std::runtime_error("bad request: MDB1: truncated header");
    if (count > MAX_ENTRIES) throw std::runtime_error("bad request: MDB1: too many entries");
    std::vector<ParsedItem> out;
    out.reserve(count < 1024u ? (size_t)count : 1024u);
    for (uint32_t k = 0; k < count; ++k) {
        uint32_t name_len = read_u32_fn(body, &p, &ok);
        if (!ok) throw std::runtime_error("bad request: MDB1: truncated (name length)");
        if (name_len > MAX_NAME_LEN) throw std::runtime_error("bad request: MDB1: name too large");
        if (p + name_len > body.size()) throw std::runtime_error("bad request: MDB1: truncated (name)");
        std::string name;
        if (name_len > 0) name.assign((const char*)&body[p], name_len);
        p += name_len;
        uint32_t code_len = read_u32_fn(body, &p, &ok);
        if (!ok) throw std::runtime_error("bad request: MDB1: truncated (code length)");
        if (code_len > MAX_CODE_LEN) throw std::runtime_error("bad request: MDB1: code too large");
        if (p + code_len > body.size()) throw std::runtime_error("bad request: MDB1: truncated (code)");
        ParsedItem item;
        item.ready = true; item.key = key; item.opt = options;
        item.code.assign(body.begin() + p, body.begin() + p + code_len);
        p += code_len;
        if (!name.empty() && name.find('\0') == std::string::npos) {
            item.name.has = true; item.name.value = name;
        }
        out.push_back(item);
    }
    if (p != body.size()) throw std::runtime_error("bad request: MDB1: trailing bytes");
    return out;
}

static std::string json_escape_fn(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if ((unsigned char)c < 0x20) {
            char buf[8]; sprintf_s(buf, sizeof buf, "\\u%04x", (unsigned)(unsigned char)c);
            out += buf;
        }
        else out += c;
    }
    return out;
}

static std::string display_name_fn(const OptString& name, const OptString& id, size_t index) {
    if (name.has && !name.value.empty()) return name.value;
    if (id.has && !id.value.empty()) return id.value;
    char buf[32]; sprintf_s(buf, sizeof buf, "#%u", (unsigned)index);
    return buf;
}

static bool make_temp_dir_fn(std::string* out_path) {
    char dir[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, dir);
    if (n == 0 || n > MAX_PATH) return false;
    static std::atomic<unsigned long> counter(0);
    unsigned long id = counter.fetch_add(1);
    for (int attempt = 0; attempt < 64; ++attempt) {
        std::ostringstream oss;
        oss << dir << "tovek-" << (unsigned long)GetCurrentProcessId() << "-"
            << (unsigned long)(id + (unsigned long)attempt);
        std::string p = oss.str();
        if (CreateDirectoryA(p.c_str(), 0)) { *out_path = p; return true; }
    }
    return false;
}

static void remove_tree_fn(const std::string& path) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((path + "\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::string name = fd.cFileName;
            if (name == "." || name == "..") continue;
            std::string child = path + "\\" + name;
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) remove_tree_fn(child);
            else DeleteFileA(child.c_str());
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(path.c_str());
}

struct TempDir { std::string path; bool valid = false; ~TempDir() { if (valid) remove_tree_fn(path); } };

static bool write_file_fn(const std::string& path, const uint8_t* data, size_t len) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t off = 0; bool ok = true;
    while (off < len) {
        DWORD chunk = (DWORD)((len - off) > 1048576u ? 1048576u : (len - off));
        DWORD written = 0;
        if (!WriteFile(h, data + off, chunk, &written, 0) || written == 0) { ok = false; break; }
        off += written;
    }
    CloseHandle(h);
    return ok;
}

static bool read_file_fn(const std::string& path, std::string* out) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) return false;
    out->clear();
    char buf[65536];
    while (true) {
        DWORD got = 0;
        if (!ReadFile(h, buf, (DWORD)sizeof buf, &got, 0)) { CloseHandle(h); return false; }
        if (got == 0) break;
        out->append(buf, got);
    }
    CloseHandle(h);
    return true;
}

static bool write_saved_bytecode_fn(const std::string& path, const uint8_t* data, size_t len, const std::string& label) {
    std::string safe = label;
    for (size_t i = 0; i < safe.size(); ++i)
        if (safe[i] == '\n' || safe[i] == '\r') safe[i] = ' ';
    std::string text = "-- " + safe + "\n" + base64_encode_fn(data, len) + "\n";
    return write_file_fn(path, (const uint8_t*)text.data(), text.size());
}

static std::string lifter_path_fn() {
    OptString p = env_var_fn("TOVEK_LIFTER_PATH");
    if (p.has && !p.value.empty()) return p.value;
    return "luau-lifter.exe";
}

static const DWORD LIFTER_TIMEOUT_MS = 600000;

static void append_quoted_fn(std::string* cmd, const std::string& arg) {
    *cmd += '"';
    size_t i = 0;
    while (i < arg.size()) {
        size_t sl = 0;
        while (i < arg.size() && arg[i] == '\\') { ++sl; ++i; }
        if (i == arg.size()) cmd->append(sl * 2, '\\');
        else if (arg[i] == '"') { cmd->append(sl * 2 + 1, '\\'); *cmd += '"'; ++i; }
        else { cmd->append(sl, '\\'); *cmd += arg[i]; ++i; }
    }
    *cmd += '"';
}

struct ProcResult { bool spawned = false; DWORD exit_code = 1; std::string out, err, spawn_error; };

static void read_pipe_fn(HANDLE pipe, std::string* sink) {
    char buf[8192];
    while (true) {
        DWORD got = 0;
        if (!ReadFile(pipe, buf, (DWORD)sizeof buf, &got, 0) || got == 0) break;
        sink->append(buf, got);
    }
}

static ProcResult run_lifter_fn(const std::vector<std::string>& argv) {
    ProcResult r;
    std::string cmd;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i > 0) cmd += ' ';
        append_quoted_fn(&cmd, argv[i]);
    }
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = 0; sa.bInheritHandle = TRUE;
    HANDLE out_r = 0, out_w = 0, err_r = 0, err_w = 0;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) { r.spawn_error = "CreatePipe(stdout) failed"; return r; }
    if (!CreatePipe(&err_r, &err_w, &sa, 0)) {
        CloseHandle(out_r); CloseHandle(out_w);
        r.spawn_error = "CreatePipe(stderr) failed"; return r;
    }
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si; memset(&si, 0, sizeof si);
    si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_w; si.hStdError = err_w; si.hStdInput = 0;
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof pi);
    std::vector<char> mc(cmd.begin(), cmd.end());
    mc.push_back('\0');
    BOOL started = CreateProcessA(0, &mc[0], 0, 0, TRUE, CREATE_NO_WINDOW, 0, 0, &si, &pi);
    CloseHandle(out_w); CloseHandle(err_w);
    if (!started) {
        DWORD e = GetLastError();
        CloseHandle(out_r); CloseHandle(err_r);
        std::ostringstream oss;
        oss << "cannot start " << argv[0] << " (Win32 error " << (unsigned long)e << ")";
        r.spawn_error = oss.str();
        return r;
    }
    std::thread t_out(read_pipe_fn, out_r, &r.out);
    std::thread t_err(read_pipe_fn, err_r, &r.err);
    DWORD wait = WaitForSingleObject(pi.hProcess, LIFTER_TIMEOUT_MS);
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        r.err += "\ndecompile timed out";
    }
    t_out.join(); t_err.join();
    CloseHandle(out_r); CloseHandle(err_r);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    r.spawned = true;
    r.exit_code = (wait == WAIT_TIMEOUT) ? 1 : code;
    return r;
}

static void append_option_args_fn(std::vector<std::string>* argv, const DecompileOptions& opt) {
    if (opt.dont_reuse_var) argv->push_back("--dont-reuse-var");
    if (opt.no_synth_helpers) argv->push_back("--no-synth-helpers");
    if (opt.assume_no_nan) argv->push_back("--assume-no-nan");
    if (opt.synthesize_arithmetic_loops) argv->push_back("--synthesize-arithmetic-loops");
    if (opt.control_flow_policy == 1) argv->push_back("--strict-no-synthetic-control");
}

static std::vector<BatchOutcome> run_folder_batch_fn(const std::vector<BatchInput>& inputs, const DecompileOptions& opt) {
    std::vector<BatchOutcome> out(inputs.size());
    for (size_t i = 0; i < out.size(); ++i) { out[i].ok = false; out[i].value = "not produced"; }
    if (inputs.empty()) return out;
    uint8_t key = inputs[0].key;
    TempDir root;
    if (!make_temp_dir_fn(&root.path)) {
        for (size_t i = 0; i < out.size(); ++i) out[i].value = "cannot create temp directory";
        return out;
    }
    root.valid = true;
    std::string in_dir = root.path + "\\in";
    std::string out_dir = root.path + "\\out";
    if (!CreateDirectoryA(in_dir.c_str(), 0)) {
        for (size_t i = 0; i < out.size(); ++i) out[i].value = "cannot create input directory";
        return out;
    }
    std::vector<size_t> mine;
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i].key != key) continue;
        char name[32]; sprintf_s(name, sizeof name, "%05u.lua", (unsigned)i);
        std::string label = inputs[i].script_name ? *inputs[i].script_name : std::string("script");
        if (!write_saved_bytecode_fn(in_dir + "\\" + name, inputs[i].bytecode, inputs[i].len, label)) {
            out[i].value = "cannot write temporary bytecode"; continue;
        }
        mine.push_back(i);
    }
    if (mine.empty()) return out;
    std::vector<std::string> argv;
    argv.push_back(lifter_path_fn());
    argv.push_back("decompile-folder");
    argv.push_back(in_dir); argv.push_back(out_dir);
    argv.push_back("--key"); argv.push_back(std::to_string((unsigned)key));
    argv.push_back("--output-extension"); argv.push_back("luau");
    append_option_args_fn(&argv, opt);
    ProcResult pr = run_lifter_fn(argv);
    if (!pr.spawned) {
        for (size_t k = 0; k < mine.size(); ++k) out[mine[k]].value = pr.spawn_error;
        return out;
    }
    std::string reason = trim_fn(pr.err);
    if (reason.size() > 500) reason = reason.substr(0, 500);
    if (reason.empty()) reason = trim_fn(pr.out);
    if (reason.empty()) {
        std::ostringstream oss;
        oss << "luau-lifter exited with code " << (unsigned long)pr.exit_code;
        reason = oss.str();
    }
    for (size_t k = 0; k < mine.size(); ++k) {
        size_t i = mine[k];
        char name[32]; sprintf_s(name, sizeof name, "%05u.luau", (unsigned)i);
        std::string source;
        if (read_file_fn(out_dir + "\\" + name, &source)) { out[i].ok = true; out[i].value = source; }
        else { out[i].ok = false; out[i].value = reason; }
    }
    std::vector<BatchInput> rest;
    std::vector<size_t> rest_index;
    for (size_t i = 0; i < inputs.size(); ++i)
        if (inputs[i].key != key) { rest.push_back(inputs[i]); rest_index.push_back(i); }
    if (!rest.empty()) {
        std::vector<BatchOutcome> more = run_folder_batch_fn(rest, opt);
        for (size_t k = 0; k < rest_index.size(); ++k) out[rest_index[k]] = more[k];
    }
    return out;
}

void install_quiet_panic_hook() {}

std::string try_decompile_bytecode_with_options(const uint8_t* data, size_t len, uint8_t key,
    const OptString& script_name, const DecompileOptions& opt) {
    if (len == 0) throw std::runtime_error("bad request: empty bytecode");
    std::vector<BatchInput> one(1);
    one[0].bytecode = data; one[0].len = len; one[0].key = key;
    one[0].script_name = (script_name.has && !script_name.value.empty()) ? &script_name.value : 0;
    std::vector<BatchOutcome> result = run_folder_batch_fn(one, opt);
    if (!result[0].ok) throw std::runtime_error("bad request: " + result[0].value);
    return result[0].value;
}

std::vector<BatchOutcome> decompile_batch_with_options(const std::vector<BatchInput>& inputs, const DecompileOptions& opt) {
    return run_folder_batch_fn(inputs, opt);
}

static std::string handle_single_fn(const HttpRequest& r, bool raw) {
    std::vector<uint8_t> code;
    if (!raw) {
        std::string decoded = base64_decode_fn(std::string(r.body.begin(), r.body.end()));
        code.assign(decoded.begin(), decoded.end());
    }
    else code = r.body;
    OptString name;
    std::string hn = get_header_fn(r, "x-script-name");
    if (!hn.empty()) { name.has = true; name.value = hn; }
    uint8_t key = raw ? parse_key_header_fn(r) : DEFAULT_KEY;
    DecompileOptions opt = parse_options_headers_fn(r);
    const uint8_t* ptr = code.empty() ? 0 : &code[0];
    std::string source = try_decompile_bytecode_with_options(ptr, code.size(), key, name, opt);
    log_success_fn(name.has ? name.value : r.path);
    return source;
}

static void handle_batch_fn(const HttpRequest& r, SOCKET fd) {
    DecompileOptions header_options = parse_options_headers_fn(r);
    std::vector<ParsedItem> items;
    if (is_json_content_type_fn(r)) items = parse_json_batch_fn(r.body, header_options);
    else items = parse_mdb1_batch_fn(r.body, header_options);
    std::vector<BatchInput> ready;
    DecompileOptions effective = header_options;
    bool first = true;
    for (size_t i = 0; i < items.size(); ++i) {
        if (!items[i].ready) continue;
        BatchInput in;
        in.bytecode = items[i].code.empty() ? 0 : &items[i].code[0];
        in.len = items[i].code.size();
        in.key = items[i].key;
        in.script_name = items[i].name.has ? &items[i].name.value : 0;
        ready.push_back(in);
        if (first) { effective = items[i].opt; first = false; }
    }
    std::vector<BatchOutcome> outcomes;
    if (!ready.empty()) outcomes = decompile_batch_with_options(ready, effective);
    size_t ok_count = 0, cursor = 0;
    std::vector<std::string> parts(items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        bool ok = false;
        std::string source, error;
        std::string label = display_name_fn(items[i].name, items[i].id, i);
        if (!items[i].ready) {
            error = items[i].error;
            log_error_fn(label, error);
        }
        else {
            const BatchOutcome& o = outcomes[cursor++];
            ok = o.ok;
            if (ok) { source = o.value; ++ok_count; log_success_fn(label); }
            else { error = o.value; log_error_fn(label, error); }
        }
        std::ostringstream oss;
        oss << "{\"index\":" << (unsigned long long)i;
        if (items[i].id.has) oss << ",\"id\":\"" << json_escape_fn(items[i].id.value) << "\"";
        if (items[i].name.has) oss << ",\"script_name\":\"" << json_escape_fn(items[i].name.value) << "\"";
        oss << ",\"ok\":" << (ok ? "true" : "false");
        if (ok) oss << ",\"decompilation\":\"" << json_escape_fn(source) << "\"";
        else oss << ",\"error\":\"" << json_escape_fn(error) << "\"";
        oss << "}";
        parts[i] = oss.str();
    }
    std::ostringstream oss;
    oss << "{\"count\":" << (unsigned long long)items.size();
    oss << ",\"ok_count\":" << (unsigned long long)ok_count << ",\"results\":[";
    for (size_t i = 0; i < parts.size(); ++i) { if (i > 0) oss << ","; oss << parts[i]; }
    oss << "]}";
    std::map<std::string, std::string> h;
    h["Content-Type"] = "application/json";
    send_resp_fn(fd, 200, "OK", h, oss.str());
}
static bool wait_readable_fn(SOCKET fd, int ms) {
    fd_set f; FD_ZERO(&f); FD_SET(fd, &f);
    timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &f, 0, 0, &tv) > 0;
}

static int read_request_fn(SOCKET fd, HttpRequest* out_r, size_t limit, std::chrono::seconds timeout) {
    HttpRequest r;
    std::string head;
    char buf[4096];
    clk::time_point deadline = clk::now() + timeout;
    size_t separator = std::string::npos;
    while (true) {
        separator = head.find("\r\n\r\n");
        if (separator != std::string::npos) break;
        if (clk::now() > deadline) return 1;
        if (!wait_readable_fn(fd, 100)) continue;
        int n = recv(fd, buf, (int)sizeof buf, 0);
        if (n <= 0) return 3;
        head.append(buf, (size_t)n);
        if (head.size() > (1u << 20)) return 3;
    }
    std::istringstream hs(head.substr(0, separator));
    std::string line;
    std::getline(hs, line);
    std::istringstream request_line(line);
    request_line >> r.method >> r.path;
    while (std::getline(hs, line)) {
        if (line == "\r" || line.empty()) break;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        r.headers[to_lower_fn(line.substr(0, colon))] = trim_fn(line.substr(colon + 1));
    }
    size_t length = 0;
    std::map<std::string, std::string>::iterator it = r.headers.find("content-length");
    if (it != r.headers.end()) {
        char* endp = 0;
        unsigned long long parsed = strtoull(it->second.c_str(), &endp, 10);
        if (endp == it->second.c_str()) { *out_r = r; return 3; }
        length = (size_t)parsed;
    }
    if (length > limit) { *out_r = r; return 2; }
    std::string rest = head.substr(separator + 4);
    r.body.assign(rest.begin(), rest.end());
    while (r.body.size() < length) {
        if (clk::now() > deadline) { *out_r = r; return 1; }
        if (!wait_readable_fn(fd, 100)) continue;
        size_t want = length - r.body.size();
        if (want > sizeof buf) want = sizeof buf;
        int n = recv(fd, buf, (int)want, 0);
        if (n <= 0) { *out_r = r; return 3; }
        r.body.insert(r.body.end(), buf, buf + n);
    }
    *out_r = r;
    return 0;
}

static void worker_fn(SOCKET fd) {
    AppState* st = &g_state;
    std::string refusal;
    bool admitted = false;
    bool has_place = st->queue->try_acquire();
    if (!has_place) refusal = "decompile queue full";
    else if (st->cpu->acquire_for(st->queue_timeout)) admitted = true;
    else { refusal = "timed out waiting for a decompile slot"; st->queue->release(); has_place = false; }

    HttpRequest rq;
    int read_result = read_request_fn(fd, &rq, BATCH_BODY_LIMIT, st->upload_timeout);
    size_t limit = LEGACY_BODY_LIMIT;
    if (rq.path == "/decompile/raw") limit = RAW_BODY_LIMIT;
    else if (rq.path == "/decompile/batch") limit = BATCH_BODY_LIMIT;

    std::string req_label = get_header_fn(rq, "x-script-name");
    if (req_label.empty()) req_label = rq.path.empty() ? "?" : rq.path;

    if (read_result != 0) {
        if (!admitted) {
            std::map<std::string, std::string> h;
            h["Retry-After"] = RETRY_AFTER_SECS;
            send_resp_fn(fd, 503, "Service Unavailable", h, refusal);
            if (has_place) st->queue->release();
            log_error_fn(req_label, refusal);
        }
        else if (read_result == 2) {
            send_resp_fn(fd, 413, "Payload Too Large", std::map<std::string, std::string>(), "payload too large");
            st->cpu->release(); st->queue->release();
            log_error_fn(req_label, "payload too large");
        }
        else if (read_result == 1) {
            std::map<std::string, std::string> h;
            h["Connection"] = "close";
            send_resp_fn(fd, 408, "Request Timeout", h, "request body upload timed out");
            st->cpu->release(); st->queue->release();
            log_error_fn(req_label, "request body upload timed out");
        }
        else {
            send_resp_fn(fd, 400, "Bad Request", std::map<std::string, std::string>(), "bad request: incomplete request body");
            st->cpu->release(); st->queue->release();
            log_error_fn(req_label, "incomplete request body");
        }
        closesocket(fd);
        return;
    }
    if (rq.body.size() > limit) {
        send_resp_fn(fd, 413, "Payload Too Large", std::map<std::string, std::string>(), "payload too large");
        st->cpu->release(); st->queue->release();
        log_error_fn(req_label, "payload too large");
        closesocket(fd);
        return;
    }
    if (!admitted) {
        std::map<std::string, std::string> h;
        h["Retry-After"] = RETRY_AFTER_SECS;
        send_resp_fn(fd, 503, "Service Unavailable", h, refusal);
        if (has_place) st->queue->release();
        log_error_fn(req_label, refusal);
        closesocket(fd);
        return;
    }

    try {
        if (rq.path == "/decompile" || rq.path == "/decompile/raw") {
            std::string source = handle_single_fn(rq, rq.path == "/decompile/raw");
            std::map<std::string, std::string> h;
            h["Content-Type"] = "text/plain; charset=utf-8";
            send_resp_fn(fd, 200, "OK", h, source);
        }
        else if (rq.path == "/decompile/batch") {
            handle_batch_fn(rq, fd);
        }
        else {
            send_resp_fn(fd, 404, "Not Found", std::map<std::string, std::string>(), "not found");
            log_error_fn(req_label, "not found: " + rq.path);
        }
    }
    catch (const std::exception& e) {
        std::string message = e.what();
        bool bad = message.compare(0, 11, "bad request") == 0 ||
            message.compare(0, 6, "base64") == 0 ||
            message.find("x-encode-key") != std::string::npos ||
            message.find("unsupported decompile flag") != std::string::npos ||
            message.find("compact annotations require") != std::string::npos;
        if (bad) send_resp_fn(fd, 400, "Bad Request", std::map<std::string, std::string>(), message);
        else send_resp_fn(fd, 500, "Internal Server Error", std::map<std::string, std::string>(), message);
        log_error_fn(req_label, message);
    }

    st->cpu->release();
    st->queue->release();
    closesocket(fd);
}
int main() {
    SetConsoleTitleA("ex:beta | decompiler (rat)");
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
    install_quiet_panic_hook();
    AppState st;
    st.cpu = std::shared_ptr<Semaphore>(new Semaphore((size_t)MAX_CONCURRENT_JOBS));
    size_t queue_limit = (size_t)DEFAULT_QUEUE_LIMIT;
    OptString env;
    env = env_var_fn(QUEUE_LIMIT_ENV);
    if (env.has) queue_limit = parse_queue_limit_fn(env.value);
    env = env_var_fn(QUEUE_TIMEOUT_ENV);
    if (env.has) st.queue_timeout = parse_seconds_fn(QUEUE_TIMEOUT_ENV, env.value);
    env = env_var_fn(UPLOAD_TIMEOUT_ENV);
    if (env.has) st.upload_timeout = parse_seconds_fn(UPLOAD_TIMEOUT_ENV, env.value);
    st.queue = std::shared_ptr<Semaphore>(new Semaphore((size_t)MAX_CONCURRENT_JOBS + queue_limit));
    g_state = st;

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { std::cerr << "socket failed" << std::endl; return 1; }
    BOOL reuse = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof reuse);
    sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BIND_PORT);
    inet_pton(AF_INET, BIND_ADDR, &addr.sin_addr);
    if (bind(listener, (sockaddr*)&addr, sizeof addr) == SOCKET_ERROR) {
        std::cerr << "bind " << BIND_ADDR << ":" << BIND_PORT << " failed" << std::endl;
        return 1;
    }
    if (listen(listener, 128) == SOCKET_ERROR) { std::cerr << "listen failed" << std::endl; return 1; }
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        WORD orig = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        if (GetConsoleScreenBufferInfo(h, &csbi)) orig = csbi.wAttributes;
        console_color_fn(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[ex:beta] Listening on http://" << BIND_ADDR << ":" << BIND_PORT << std::endl;
        console_color_fn(orig);
    }
    while (true) {
        SOCKET fd = accept(listener, 0, 0);
        if (fd == INVALID_SOCKET) continue;
        std::thread t(worker_fn, fd);
        t.detach();
    }
    return 0;
}
