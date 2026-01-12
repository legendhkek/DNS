/**
 * Stealth DNS Client Implementation
 * 
 * All internal names are obfuscated.
 * Communication is encrypted.
 * Looks like normal cloud sync traffic.
 */

#include "DnsBlockerClient.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <thread>
#include <random>
#include <array>

// Platform includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    using SockType = SOCKET;
    #define INVALID_SOCK INVALID_SOCKET
    #define CLOSE_SOCK closesocket
#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <arpa/inet.h>
    using SockType = int;
    #define INVALID_SOCK -1
    #define CLOSE_SOCK close
#endif

// OpenSSL
#ifndef CSYNC_NO_SSL
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/evp.h>
    #include <openssl/rand.h>
    #include <openssl/sha.h>
    #define USE_SSL 1
#else
    #define USE_SSL 0
#endif

namespace CloudSync {

// ==================== Result Messages ====================

const char* getResultMessage(ResultCode code) noexcept {
    switch (code) {
        case ResultCode::OK: return "OK";
        case ResultCode::CONN_ERROR: return "Connection error";
        case ResultCode::TIMEOUT: return "Timeout";
        case ResultCode::CRYPTO_ERROR: return "Crypto error";
        case ResultCode::INVALID_DATA: return "Invalid data";
        case ResultCode::AUTH_FAILED: return "Auth failed";
        case ResultCode::LIMIT_EXCEEDED: return "Limit exceeded";
        case ResultCode::INVALID_INPUT: return "Invalid input";
        case ResultCode::NET_ERROR: return "Network error";
        case ResultCode::PARSE_ERROR: return "Parse error";
        default: return "Unknown error";
    }
}

// ==================== Crypto ====================

namespace crypto {

#if USE_SSL

// Base64
static const char B64_TABLE[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::vector<uint8_t>& data) {
    std::string result;
    int val = 0, bits = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            result.push_back(B64_TABLE[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) {
        result.push_back(B64_TABLE[((val << 8) >> (bits + 8)) & 0x3F]);
    }
    while (result.size() % 4) {
        result.push_back('=');
    }
    return result;
}

std::vector<uint8_t> base64Decode(const std::string& data) {
    std::vector<uint8_t> result;
    std::array<int, 256> T{};
    std::fill(T.begin(), T.end(), -1);
    for (int i = 0; i < 64; i++) {
        T[static_cast<uint8_t>(B64_TABLE[i])] = i;
    }
    
    int val = 0, bits = -8;
    for (char c : data) {
        if (T[static_cast<uint8_t>(c)] == -1) break;
        val = (val << 6) + T[static_cast<uint8_t>(c)];
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

// SHA256 hash
std::vector<uint8_t> sha256(const std::string& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());
    return hash;
}

// AES-256-GCM encryption
std::string encrypt(const std::string& plaintext, const std::string& key) {
    auto keyHash = sha256(key);
    
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), 12);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    std::vector<uint8_t> tag(16);
    int len = 0, ciphertextLen = 0;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, keyHash.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    ciphertextLen = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertextLen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    
    // Format: iv(12) + tag(16) + ciphertext
    std::vector<uint8_t> result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertextLen);
    
    return base64Encode(result);
}

std::string decrypt(const std::string& encoded, const std::string& key) {
    auto raw = base64Decode(encoded);
    if (raw.size() < 28) return "";
    
    auto keyHash = sha256(key);
    
    std::vector<uint8_t> iv(raw.begin(), raw.begin() + 12);
    std::vector<uint8_t> tag(raw.begin() + 12, raw.begin() + 28);
    std::vector<uint8_t> ciphertext(raw.begin() + 28, raw.end());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len = 0, plaintextLen = 0;
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, keyHash.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintextLen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret <= 0) return "";
    plaintextLen += len;
    
    return std::string(plaintext.begin(), plaintext.begin() + plaintextLen);
}

#else

std::string base64Encode(const std::vector<uint8_t>& data) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    int v = 0, b = -6;
    for (uint8_t c : data) { v = (v << 8) + c; b += 8; while (b >= 0) { r += t[(v >> b) & 0x3F]; b -= 6; } }
    if (b > -6) r += t[((v << 8) >> (b + 8)) & 0x3F];
    while (r.size() % 4) r += '=';
    return r;
}

std::vector<uint8_t> base64Decode(const std::string& s) {
    std::vector<uint8_t> r;
    std::array<int, 256> T{}; std::fill(T.begin(), T.end(), -1);
    const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; i++) T[t[i]] = i;
    int v = 0, b = -8;
    for (char c : s) { if (T[c] == -1) break; v = (v << 6) + T[c]; b += 6; if (b >= 0) { r.push_back((v >> b) & 0xFF); b -= 8; } }
    return r;
}

std::string encrypt(const std::string& p, const std::string& k) {
    std::string r; size_t kl = k.size();
    for (size_t i = 0; i < p.size(); i++) r += p[i] ^ k[i % kl];
    return base64Encode(std::vector<uint8_t>(r.begin(), r.end()));
}

std::string decrypt(const std::string& e, const std::string& k) {
    auto d = base64Decode(e); std::string r; size_t kl = k.size();
    for (size_t i = 0; i < d.size(); i++) r += d[i] ^ k[i % kl];
    return r;
}

#endif

// XOR obfuscation for patterns
std::string xorDecode(const std::string& encoded) {
    auto decoded = base64Decode(encoded);
    return std::string(decoded.begin(), decoded.end());
}

} // namespace crypto

// ==================== JSON Parser ====================

namespace json {

class Value {
public:
    std::variant<std::nullptr_t, bool, int64_t, double, std::string,
                 std::vector<Value>, std::map<std::string, Value>> data;
    
    Value() : data(nullptr) {}
    Value(bool b) : data(b) {}
    Value(int64_t i) : data(i) {}
    Value(double d) : data(d) {}
    Value(const std::string& s) : data(s) {}
    
    bool getBool(bool def = false) const {
        if (std::holds_alternative<bool>(data)) return std::get<bool>(data);
        return def;
    }
    
    int64_t getInt(int64_t def = 0) const {
        if (std::holds_alternative<int64_t>(data)) return std::get<int64_t>(data);
        if (std::holds_alternative<double>(data)) return static_cast<int64_t>(std::get<double>(data));
        return def;
    }
    
    std::string getString(const std::string& def = "") const {
        if (std::holds_alternative<std::string>(data)) return std::get<std::string>(data);
        return def;
    }
    
    const std::vector<Value>& getArray() const {
        static std::vector<Value> empty;
        if (std::holds_alternative<std::vector<Value>>(data)) 
            return std::get<std::vector<Value>>(data);
        return empty;
    }
    
    const Value& operator[](const std::string& key) const {
        static Value null;
        if (std::holds_alternative<std::map<std::string, Value>>(data)) {
            const auto& obj = std::get<std::map<std::string, Value>>(data);
            auto it = obj.find(key);
            if (it != obj.end()) return it->second;
        }
        return null;
    }
};

class Parser {
public:
    static Value parse(const std::string& json) {
        size_t pos = 0;
        return parseValue(json, pos);
    }

private:
    static void skipWS(const std::string& s, size_t& p) {
        while (p < s.size() && std::isspace(s[p])) p++;
    }
    
    static Value parseValue(const std::string& s, size_t& p) {
        skipWS(s, p);
        if (p >= s.size()) return Value();
        char c = s[p];
        if (c == '"') return parseString(s, p);
        if (c == '{') return parseObject(s, p);
        if (c == '[') return parseArray(s, p);
        if (c == 't' || c == 'f') return parseBool(s, p);
        if (c == 'n') { p += 4; return Value(); }
        if (c == '-' || std::isdigit(c)) return parseNumber(s, p);
        return Value();
    }
    
    static Value parseString(const std::string& s, size_t& p) {
        p++; std::string r;
        while (p < s.size() && s[p] != '"') {
            if (s[p] == '\\' && p + 1 < s.size()) {
                p++; 
                switch (s[p]) {
                    case 'n': r += '\n'; break;
                    case 't': r += '\t'; break;
                    case 'r': r += '\r'; break;
                    default: r += s[p];
                }
            } else r += s[p];
            p++;
        }
        if (p < s.size()) p++;
        return Value(r);
    }
    
    static Value parseNumber(const std::string& s, size_t& p) {
        size_t start = p; bool isFloat = false;
        if (s[p] == '-') p++;
        while (p < s.size() && std::isdigit(s[p])) p++;
        if (p < s.size() && s[p] == '.') { isFloat = true; p++; while (p < s.size() && std::isdigit(s[p])) p++; }
        if (p < s.size() && (s[p] == 'e' || s[p] == 'E')) { isFloat = true; p++; if (p < s.size() && (s[p] == '+' || s[p] == '-')) p++; while (p < s.size() && std::isdigit(s[p])) p++; }
        std::string num = s.substr(start, p - start);
        if (isFloat) return Value(std::stod(num));
        return Value(std::stoll(num));
    }
    
    static Value parseBool(const std::string& s, size_t& p) {
        if (s.compare(p, 4, "true") == 0) { p += 4; return Value(true); }
        if (s.compare(p, 5, "false") == 0) { p += 5; return Value(false); }
        return Value();
    }
    
    static Value parseArray(const std::string& s, size_t& p) {
        p++; std::vector<Value> arr; skipWS(s, p);
        while (p < s.size() && s[p] != ']') {
            arr.push_back(parseValue(s, p));
            skipWS(s, p); if (p < s.size() && s[p] == ',') p++; skipWS(s, p);
        }
        if (p < s.size()) p++;
        Value v; v.data = std::move(arr); return v;
    }
    
    static Value parseObject(const std::string& s, size_t& p) {
        p++; std::map<std::string, Value> obj; skipWS(s, p);
        while (p < s.size() && s[p] != '}') {
            Value k = parseString(s, p); skipWS(s, p);
            if (p < s.size() && s[p] == ':') p++; skipWS(s, p);
            obj[k.getString()] = parseValue(s, p);
            skipWS(s, p); if (p < s.size() && s[p] == ',') p++; skipWS(s, p);
        }
        if (p < s.size()) p++;
        Value v; v.data = std::move(obj); return v;
    }
};

std::string escape(const std::string& s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            default: r += c;
        }
    }
    return r;
}

std::string buildObject(const std::map<std::string, std::string>& m) {
    std::ostringstream o; o << "{"; bool f = true;
    for (const auto& [k, v] : m) { if (!f) o << ","; o << "\"" << k << "\":" << v; f = false; }
    o << "}"; return o.str();
}

std::string buildArray(const std::vector<std::string>& a) {
    std::ostringstream o; o << "["; bool f = true;
    for (const auto& s : a) { if (!f) o << ","; o << "\"" << escape(s) << "\""; f = false; }
    o << "]"; return o.str();
}

} // namespace json

// ==================== HTTP Client ====================

class NetClient {
public:
    struct URL {
        std::string proto, host, path;
        int port; bool ssl;
    };
    
    struct Response {
        int status = 0;
        std::string body;
        std::map<std::string, std::string> headers;
        ResultCode code = ResultCode::OK;
        std::string error;
    };
    
    static URL parseUrl(const std::string& url) {
        URL r; r.ssl = false; r.port = 80;
        size_t p = 0, pe = url.find("://");
        if (pe != std::string::npos) {
            r.proto = url.substr(0, pe);
            if (r.proto == "https") { r.ssl = true; r.port = 443; }
            p = pe + 3;
        }
        size_t ps = url.find('/', p);
        std::string hp = (ps != std::string::npos) ? url.substr(p, ps - p) : url.substr(p);
        size_t cp = hp.find(':');
        if (cp != std::string::npos) {
            r.host = hp.substr(0, cp);
            r.port = std::stoi(hp.substr(cp + 1));
        } else r.host = hp;
        r.path = (ps != std::string::npos) ? url.substr(ps) : "/";
        return r;
    }
    
    static Response request(const std::string& method, const std::string& url,
                           const std::map<std::string, std::string>& headers,
                           const std::string& body, int timeout) {
        Response resp;
        URL u = parseUrl(url);
        
        #ifdef _WIN32
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
        #endif
        
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(u.host.c_str(), std::to_string(u.port).c_str(), &hints, &res) != 0) {
            resp.code = ResultCode::CONN_ERROR;
            resp.error = "DNS failed";
            return resp;
        }
        
        SockType sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == INVALID_SOCK) {
            freeaddrinfo(res);
            resp.code = ResultCode::NET_ERROR;
            return resp;
        }
        
        #ifdef _WIN32
        DWORD tv = timeout;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
        #else
        struct timeval tv; tv.tv_sec = timeout / 1000; tv.tv_usec = (timeout % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        #endif
        
        if (::connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            CLOSE_SOCK(sock); freeaddrinfo(res);
            resp.code = ResultCode::CONN_ERROR;
            return resp;
        }
        freeaddrinfo(res);
        
        #if USE_SSL
        SSL_CTX* ctx = nullptr; SSL* ssl = nullptr;
        if (u.ssl) {
            SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
            ctx = SSL_CTX_new(TLS_client_method());
            if (!ctx) { CLOSE_SOCK(sock); resp.code = ResultCode::CRYPTO_ERROR; return resp; }
            ssl = SSL_new(ctx); SSL_set_fd(ssl, sock);
            SSL_set_tlsext_host_name(ssl, u.host.c_str());
            if (SSL_connect(ssl) <= 0) {
                SSL_free(ssl); SSL_CTX_free(ctx); CLOSE_SOCK(sock);
                resp.code = ResultCode::CRYPTO_ERROR; return resp;
            }
        }
        #else
        if (u.ssl) { CLOSE_SOCK(sock); resp.code = ResultCode::CRYPTO_ERROR; resp.error = "No SSL"; return resp; }
        #endif
        
        // Build request
        std::ostringstream req;
        req << method << " " << u.path << " HTTP/1.1\r\n";
        req << "Host: " << u.host << "\r\n";
        req << "Connection: close\r\n";
        for (const auto& [k, v] : headers) req << k << ": " << v << "\r\n";
        if (!body.empty()) req << "Content-Length: " << body.size() << "\r\n";
        req << "\r\n" << body;
        
        std::string reqStr = req.str();
        
        // Send
        auto sendFn = [&](const char* d, size_t l) -> bool {
            #if USE_SSL
            if (ssl) return SSL_write(ssl, d, l) > 0;
            #endif
            return send(sock, d, l, 0) > 0;
        };
        
        if (!sendFn(reqStr.c_str(), reqStr.size())) {
            #if USE_SSL
            if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
            #endif
            CLOSE_SOCK(sock);
            resp.code = ResultCode::NET_ERROR;
            return resp;
        }
        
        // Receive
        std::string respData; char buf[4096];
        auto recvFn = [&](char* b, size_t l) -> int {
            #if USE_SSL
            if (ssl) return SSL_read(ssl, b, l);
            #endif
            return recv(sock, b, l, 0);
        };
        
        int n;
        while ((n = recvFn(buf, sizeof(buf) - 1)) > 0) {
            buf[n] = 0; respData += buf;
            if (respData.size() > MAX_RESPONSE_SIZE) break;
        }
        
        #if USE_SSL
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
        #endif
        CLOSE_SOCK(sock);
        #ifdef _WIN32
        WSACleanup();
        #endif
        
        // Parse response
        size_t he = respData.find("\r\n\r\n");
        if (he == std::string::npos) { resp.code = ResultCode::INVALID_DATA; return resp; }
        
        std::string hs = respData.substr(0, he);
        resp.body = respData.substr(he + 4);
        
        size_t se = hs.find("\r\n");
        if (se != std::string::npos) {
            std::string sl = hs.substr(0, se);
            size_t cs = sl.find(' ');
            if (cs != std::string::npos) resp.status = std::stoi(sl.substr(cs + 1));
        }
        
        return resp;
    }
};

// ==================== Implementation ====================

class SyncClient::Impl {
public:
    ClientConfig cfg;
    std::atomic<bool> sessionActive{false};
    std::string sessionToken;
    mutable std::string lastError;
    mutable ResultCode lastCode{ResultCode::OK};
    
    // Local filter
    std::unordered_set<std::string> localFilter;
    mutable std::shared_mutex filterMutex;
    
    // Cache
    std::unordered_map<std::string, std::pair<QueryResult, std::chrono::steady_clock::time_point>> cache;
    mutable std::shared_mutex cacheMutex;
    
    // Obfuscated patterns (base64 encoded)
    std::vector<std::string> encodedPatterns = {
        "ZG91YmxlY2xpY2s=", "Z29vZ2xlc3luZGljYXRpb24=", "Z29vZ2xlYWRzZXJ2aWNlcw==",
        "Z29vZ2xlLWFuYWx5dGljcw==", "Z29vZ2xldGFnbWFuYWdlcg==", "YWRzZXJ2aWNl",
        "cGFnZWFk", "YWRtb2I=", "YWRzZW5zZQ==", "YWRueHM=", "YWR2ZXJ0aXNpbmc=",
        "bW9wdWI=", "dW5pdHlhZHM=", "YXBwbG92aW4=", "dnVuZ2xl", "Y2hhcnRib29zdA==",
        "aXJvbnNyYw==", "aW5tb2Jp", "dGFwam95", "ZnliZXI=", "YW4uZmFjZWJvb2s=",
        "cGl4ZWwuZmFjZWJvb2s=", "YW5hbHl0aWNz", "dHJhY2tlcg==", "dHJhY2tpbmc=",
        "dGVsZW1ldHJ5", "bWl4cGFuZWw=", "c2VnbWVudC5jb20=", "YW1wbGl0dWRl",
        "YnJhbmNoLmlv", "YWRqdXN0LmNvbQ==", "YXBwc2ZseWVy", "a29jaGF2YQ==",
        "cG9wYWRz", "cG9wY2FzaA==", "cHJvcGVsbGVyYWRz", "dGFib29sYQ==",
        "b3V0YnJhaW4=", "cmV2Y29udGVudA==", "bWdpZA==", "Y3Jhc2hseXRpY3M=",
        "Zmx1cnJ5", "c2NvcmVjYXJkcmVzZWFyY2g=", "cXVhbnRzZXJ2ZQ=="
    };
    
    // Decoded patterns
    std::vector<std::string> patterns;
    
    // Random generators
    std::mt19937 rng{std::random_device{}()};
    
    // Stealth endpoint paths
    std::vector<std::string> initPaths = {"/i", "/init", "/start", "/handshake"};
    std::vector<std::string> queryPaths = {"/q", "/query", "/lookup", "/find"};
    std::vector<std::string> checkPaths = {"/c", "/check", "/verify"};
    std::vector<std::string> batchPaths = {"/b", "/batch", "/bulk"};
    
    // Fake user agents
    std::vector<std::string> userAgents = {
        "CloudSync/3.2.1 (Android 12; SDK 31)",
        "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36",
        "okhttp/4.9.3",
        "Dalvik/2.1.0 (Linux; U; Android 12)",
        "CloudKit/2.0 CFNetwork/1325.0.1 Darwin/21.1.0"
    };
    
    Impl(std::string_view endpoint, std::string_view secret) {
        cfg.endpoint = endpoint;
        cfg.secret = secret;
        if (!cfg.endpoint.empty() && cfg.endpoint.back() == '/') {
            cfg.endpoint.pop_back();
        }
        initPatterns();
    }
    
    Impl(const ClientConfig& c) : cfg(c) {
        if (!cfg.endpoint.empty() && cfg.endpoint.back() == '/') {
            cfg.endpoint.pop_back();
        }
        initPatterns();
    }
    
    void initPatterns() {
        // Decode obfuscated patterns
        for (const auto& enc : encodedPatterns) {
            patterns.push_back(crypto::xorDecode(enc));
        }
        
        // Add to local filter
        std::lock_guard lock(filterMutex);
        for (const auto& p : patterns) {
            localFilter.insert(p);
        }
    }
    
    std::string randomPath(const std::vector<std::string>& paths) {
        if (!cfg.randomizeEndpoints || paths.empty()) return paths[0];
        std::uniform_int_distribution<size_t> dist(0, paths.size() - 1);
        return paths[dist(rng)];
    }
    
    std::string randomUA() {
        if (!cfg.randomizeHeaders || userAgents.empty()) return userAgents[0];
        std::uniform_int_distribution<size_t> dist(0, userAgents.size() - 1);
        return userAgents[dist(rng)];
    }
    
    void addJitter() {
        if (cfg.requestJitterMs > 0) {
            std::uniform_int_distribution<int> dist(0, cfg.requestJitterMs);
            std::this_thread::sleep_for(std::chrono::milliseconds(dist(rng)));
        }
    }
    
    NetClient::Response makeRequest(const std::string& path, const std::string& method = "GET",
                                   const std::string& body = "") {
        addJitter();
        
        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["Accept"] = "application/json";
        headers["User-Agent"] = randomUA();
        
        if (!sessionToken.empty()) {
            // Randomize token header name
            std::vector<std::string> tokenHeaders = {"X-Token", "Authorization", "X-Session"};
            std::uniform_int_distribution<size_t> dist(0, tokenHeaders.size() - 1);
            std::string hdr = tokenHeaders[dist(rng)];
            headers[hdr] = (hdr == "Authorization") ? "Bearer " + sessionToken : sessionToken;
        }
        
        // Random request ID (looks like normal API)
        std::uniform_int_distribution<uint64_t> idDist;
        headers["X-Request-ID"] = std::to_string(idDist(rng));
        
        std::string url = cfg.endpoint + path;
        return NetClient::request(method, url, headers, body, cfg.timeoutMs);
    }
    
    std::string encryptBody(const std::map<std::string, std::string>& data) {
        if (!cfg.useEncryption) return json::buildObject(data);
        
        std::string jsonStr = json::buildObject(data);
        return crypto::encrypt(jsonStr, cfg.secret);
    }
    
    json::Value decryptResponse(const std::string& body) {
        auto root = json::Parser::parse(body);
        
        // Check if response contains encrypted data
        std::string encData = root["data"].getString();
        if (!encData.empty() && cfg.useEncryption) {
            std::string decrypted = crypto::decrypt(encData, cfg.secret);
            if (!decrypted.empty()) {
                return json::Parser::parse(decrypted);
            }
        }
        
        return root;
    }
    
    bool matchesPattern(const std::string& item) const {
        std::string lower = item;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        for (const auto& p : patterns) {
            if (lower.find(p) != std::string::npos) return true;
        }
        return false;
    }
    
    bool isInLocalFilter(const std::string& item) const {
        std::string normalized = normalizeTarget(item);
        
        std::shared_lock lock(filterMutex);
        
        // Exact match
        if (localFilter.count(normalized)) return true;
        
        // Pattern match
        if (matchesPattern(normalized)) return true;
        
        // Check parent domains
        size_t pos = 0;
        while ((pos = normalized.find('.', pos)) != std::string::npos) {
            std::string parent = normalized.substr(pos + 1);
            if (localFilter.count(parent)) return true;
            pos++;
        }
        
        return false;
    }
    
    std::optional<QueryResult> getFromCache(const std::string& item) const {
        if (!cfg.enableLocalCache) return std::nullopt;
        
        std::shared_lock lock(cacheMutex);
        auto it = cache.find(item);
        if (it != cache.end()) {
            if (std::chrono::steady_clock::now() < it->second.second) {
                return it->second.first;
            }
        }
        return std::nullopt;
    }
    
    void addToCache(const std::string& item, const QueryResult& result) {
        if (!cfg.enableLocalCache) return;
        
        std::lock_guard lock(cacheMutex);
        cache[item] = {
            result,
            std::chrono::steady_clock::now() + std::chrono::seconds(cfg.cacheTtlSec)
        };
    }
};

// ==================== Public Methods ====================

SyncClient::SyncClient(std::string_view endpoint, std::string_view secret)
    : m_impl(std::make_unique<Impl>(endpoint, secret)) {}

SyncClient::SyncClient(const ClientConfig& config)
    : m_impl(std::make_unique<Impl>(config)) {}

SyncClient::~SyncClient() = default;
SyncClient::SyncClient(SyncClient&&) noexcept = default;
SyncClient& SyncClient::operator=(SyncClient&&) noexcept = default;

SessionInfo SyncClient::initSession() {
    SessionInfo info;
    
    auto resp = m_impl->makeRequest(m_impl->randomPath(m_impl->initPaths));
    
    if (resp.code != ResultCode::OK || resp.status < 200 || resp.status >= 300) {
        info.error = resp.error.empty() ? "Connection failed" : resp.error;
        info.code = resp.code;
        m_impl->lastError = info.error;
        m_impl->lastCode = resp.code;
        return info;
    }
    
    auto data = m_impl->decryptResponse(resp.body);
    
    info.ok = data["ok"].getBool();
    if (info.ok) {
        m_impl->sessionActive = true;
        m_impl->sessionToken = data["token"].getString();
        info.token = m_impl->sessionToken;
        info.clientId = data["cid"].getString();
        info.timestamp = data["ts"].getInt();
        info.dataCount = static_cast<int>(data["cnt"].getInt());
    } else {
        info.error = "Init failed";
        info.code = ResultCode::AUTH_FAILED;
    }
    
    return info;
}

QueryResult SyncClient::query(std::string_view item) {
    QueryResult result;
    std::string itemStr(item);
    result.target = itemStr;
    
    if (!isValidTarget(item)) {
        result.valid = false;
        m_impl->lastCode = ResultCode::INVALID_INPUT;
        return result;
    }
    
    // Check local filter first (fast)
    if (m_impl->isInLocalFilter(itemStr)) {
        result.valid = true;
        result.flag = 1;
        result.addr = "0.0.0.0";
        result.addr6 = "::";
        return result;
    }
    
    // Check cache
    if (auto cached = m_impl->getFromCache(itemStr)) {
        return *cached;
    }
    
    // Remote query
    std::string path = m_impl->randomPath(m_impl->queryPaths) + "?d=" + itemStr;
    auto resp = m_impl->makeRequest(path);
    
    if (resp.code != ResultCode::OK || resp.status < 200 || resp.status >= 300) {
        m_impl->lastError = "Query failed";
        m_impl->lastCode = resp.code;
        return result;
    }
    
    auto data = m_impl->decryptResponse(resp.body);
    
    result.valid = data["ok"].getBool();
    result.flag = static_cast<int>(data["r"].getInt());
    result.addr = data["ip"].getString();
    result.addr6 = data["ip6"].getString();
    result.ttl = static_cast<int>(data["ttl"].getInt(300));
    
    m_impl->addToCache(itemStr, result);
    
    return result;
}

bool SyncClient::isFiltered(std::string_view item) {
    std::string itemStr(item);
    
    // Fast local check
    if (m_impl->isInLocalFilter(itemStr)) return true;
    
    // Check cache
    if (auto cached = m_impl->getFromCache(itemStr)) {
        return cached->flag == 1;
    }
    
    // Remote check
    std::string path = m_impl->randomPath(m_impl->checkPaths) + "?d=" + itemStr;
    auto resp = m_impl->makeRequest(path);
    
    if (resp.status < 200 || resp.status >= 300) {
        return m_impl->isInLocalFilter(itemStr);
    }
    
    auto data = m_impl->decryptResponse(resp.body);
    return data["r"].getInt() == 1;
}

std::map<std::string, QueryResult> SyncClient::queryBatch(const std::vector<std::string>& items) {
    std::map<std::string, QueryResult> results;
    std::vector<std::string> toQuery;
    
    // Check local and cache first
    for (const auto& item : items) {
        if (m_impl->isInLocalFilter(item)) {
            QueryResult r; r.target = item; r.valid = true; r.flag = 1; r.addr = "0.0.0.0";
            results[item] = r;
        } else if (auto cached = m_impl->getFromCache(item)) {
            results[item] = *cached;
        } else {
            toQuery.push_back(item);
        }
    }
    
    // Batch query remaining
    if (!toQuery.empty() && toQuery.size() <= MAX_BATCH_SIZE) {
        std::string body;
        if (m_impl->cfg.useEncryption) {
            std::string jsonData = "{\"d\":" + json::buildArray(toQuery) + "}";
            body = crypto::encrypt(jsonData, m_impl->cfg.secret);
        } else {
            body = "{\"d\":" + json::buildArray(toQuery) + "}";
        }
        
        auto resp = m_impl->makeRequest(m_impl->randomPath(m_impl->batchPaths), "POST", body);
        
        if (resp.status >= 200 && resp.status < 300) {
            auto data = m_impl->decryptResponse(resp.body);
            const auto& res = data["res"];
            
            for (const auto& item : toQuery) {
                const auto& r = res[item];
                QueryResult qr;
                qr.target = item;
                qr.valid = true;
                qr.flag = static_cast<int>(r["r"].getInt());
                qr.addr = r["ip"].getString();
                results[item] = qr;
                m_impl->addToCache(item, qr);
            }
        }
    }
    
    return results;
}

ServiceStatus SyncClient::getStatus() {
    ServiceStatus status;
    auto resp = m_impl->makeRequest("/status");
    
    if (resp.status >= 200 && resp.status < 300) {
        auto data = json::Parser::parse(resp.body);
        status.active = data["ok"].getBool();
        status.ver = data["version"].getString();
        status.timestamp = data["ts"].getInt();
    }
    
    return status;
}

std::vector<std::string> SyncClient::syncData() {
    auto resp = m_impl->makeRequest("/s");
    if (resp.status < 200 || resp.status >= 300) return {};
    
    auto data = m_impl->decryptResponse(resp.body);
    const auto& arr = data["data"].getArray();
    
    std::vector<std::string> result;
    for (const auto& v : arr) {
        std::string decoded = crypto::xorDecode(v.getString());
        if (!decoded.empty()) result.push_back(decoded);
    }
    return result;
}

// Async methods
std::future<SessionInfo> SyncClient::initSessionAsync() {
    return std::async(std::launch::async, [this]() { return initSession(); });
}

std::future<QueryResult> SyncClient::queryAsync(std::string_view item) {
    std::string i(item);
    return std::async(std::launch::async, [this, i]() { return query(i); });
}

void SyncClient::initSessionAsync(SessionCallback cb) {
    std::thread([this, cb]() { cb(initSession()); }).detach();
}

void SyncClient::queryAsync(std::string_view item, QueryCallback cb) {
    std::string i(item);
    std::thread([this, i, cb]() { cb(query(i)); }).detach();
}

// Local filter methods
bool SyncClient::checkLocal(std::string_view item) const {
    return m_impl->isInLocalFilter(std::string(item));
}

void SyncClient::addLocalFilter(std::string_view item) {
    std::lock_guard lock(m_impl->filterMutex);
    m_impl->localFilter.insert(std::string(normalizeTarget(item)));
}

void SyncClient::removeLocalFilter(std::string_view item) {
    std::lock_guard lock(m_impl->filterMutex);
    m_impl->localFilter.erase(std::string(normalizeTarget(item)));
}

bool SyncClient::loadFilterFile(std::string_view path) {
    std::ifstream f(std::string(path));
    if (!f) return false;
    
    std::lock_guard lock(m_impl->filterMutex);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        m_impl->localFilter.insert(normalizeTarget(line));
    }
    return true;
}

bool SyncClient::saveFilterFile(std::string_view path) const {
    std::ofstream f(std::string(path));
    if (!f) return false;
    
    std::shared_lock lock(m_impl->filterMutex);
    for (const auto& item : m_impl->localFilter) {
        f << item << "\n";
    }
    return true;
}

std::vector<std::string> SyncClient::getLocalFilter() const {
    std::shared_lock lock(m_impl->filterMutex);
    return {m_impl->localFilter.begin(), m_impl->localFilter.end()};
}

void SyncClient::clearLocalFilter() {
    std::lock_guard lock(m_impl->filterMutex);
    m_impl->localFilter.clear();
}

// Config methods
void SyncClient::setTimeout(int ms) { m_impl->cfg.timeoutMs = ms; }
int SyncClient::getTimeout() const { return m_impl->cfg.timeoutMs; }
void SyncClient::setCacheEnabled(bool e) { m_impl->cfg.enableLocalCache = e; }
void SyncClient::clearCache() { std::lock_guard l(m_impl->cacheMutex); m_impl->cache.clear(); }
std::string SyncClient::getLastError() const { return m_impl->lastError; }
ResultCode SyncClient::getLastResultCode() const { return m_impl->lastCode; }
bool SyncClient::isSessionActive() const { return m_impl->sessionActive; }
const ClientConfig& SyncClient::getConfig() const { return m_impl->cfg; }
std::string SyncClient::getSessionToken() const { return m_impl->sessionToken; }

// ==================== Utilities ====================

bool isValidTarget(std::string_view item) {
    if (item.empty() || item.length() > 253) return false;
    for (char c : item) {
        if (!std::isalnum(c) && c != '.' && c != '-') return false;
    }
    return true;
}

std::string normalizeTarget(std::string_view item) {
    std::string r(item);
    if (r.find("http://") == 0) r = r.substr(7);
    if (r.find("https://") == 0) r = r.substr(8);
    size_t s = r.find('/'); if (s != std::string::npos) r = r.substr(0, s);
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    while (!r.empty() && std::isspace(r.front())) r.erase(0, 1);
    while (!r.empty() && std::isspace(r.back())) r.pop_back();
    return r;
}

bool isNullAddress(std::string_view addr) {
    return addr == "0.0.0.0" || addr == "::" || addr == "127.0.0.1" || addr.empty();
}

std::vector<std::string> getBuiltinFilters() {
    return {"doubleclick", "googlesyndication", "googleadservices", "admob", "adsense"};
}

} // namespace CloudSync

// ==================== C API ====================

static std::string g_lastResult;

extern "C" {

CSyncHandle csync_create(const char* endpoint, const char* secret) {
    if (!endpoint || !secret) return nullptr;
    try { return new CloudSync::SyncClient(endpoint, secret); }
    catch (...) { return nullptr; }
}

void csync_destroy(CSyncHandle h) {
    delete static_cast<CloudSync::SyncClient*>(h);
}

int csync_init(CSyncHandle h) {
    if (!h) return 0;
    return static_cast<CloudSync::SyncClient*>(h)->initSession().ok ? 1 : 0;
}

int csync_check(CSyncHandle h, const char* item) {
    if (!h || !item) return 0;
    return static_cast<CloudSync::SyncClient*>(h)->isFiltered(item) ? 1 : 0;
}

const char* csync_query(CSyncHandle h, const char* item) {
    if (!h || !item) return "";
    auto r = static_cast<CloudSync::SyncClient*>(h)->query(item);
    g_lastResult = r.flag == 1 ? "0.0.0.0" : r.addr;
    return g_lastResult.c_str();
}

const char* csync_error(CSyncHandle h) {
    if (!h) return "Invalid handle";
    static std::string err;
    err = static_cast<CloudSync::SyncClient*>(h)->getLastError();
    return err.c_str();
}

void csync_timeout(CSyncHandle h, int ms) {
    if (h) static_cast<CloudSync::SyncClient*>(h)->setTimeout(ms);
}

void csync_add_filter(CSyncHandle h, const char* item) {
    if (h && item) static_cast<CloudSync::SyncClient*>(h)->addLocalFilter(item);
}

void csync_remove_filter(CSyncHandle h, const char* item) {
    if (h && item) static_cast<CloudSync::SyncClient*>(h)->removeLocalFilter(item);
}

int csync_check_local(CSyncHandle h, const char* item) {
    if (!h || !item) return 0;
    return static_cast<CloudSync::SyncClient*>(h)->checkLocal(item) ? 1 : 0;
}

const char* csync_token(CSyncHandle h) {
    if (!h) return "";
    static std::string t;
    t = static_cast<CloudSync::SyncClient*>(h)->getSessionToken();
    return t.c_str();
}

}
