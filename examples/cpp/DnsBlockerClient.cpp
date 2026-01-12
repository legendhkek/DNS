/**
 * DNS Blocker API Client Implementation
 * C++17 - Self-contained with minimal dependencies
 */

#include "DnsBlockerClient.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>
#include <shared_mutex>

// Platform-specific includes
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    using SocketType = SOCKET;
    #define INVALID_SOCK INVALID_SOCKET
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <arpa/inet.h>
    #include <errno.h>
    using SocketType = int;
    #define INVALID_SOCK -1
    #define CLOSE_SOCKET close
#endif

// OpenSSL for HTTPS (optional - can be disabled)
#ifndef DNS_BLOCKER_NO_SSL
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/x509v3.h>
    #define HAS_SSL 1
#else
    #define HAS_SSL 0
#endif

namespace DnsBlocker {

// ==================== Error Code Strings ====================

const char* errorCodeToString(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::OK: return "OK";
        case ErrorCode::CONNECTION_FAILED: return "Connection failed";
        case ErrorCode::TIMEOUT: return "Connection timeout";
        case ErrorCode::SSL_ERROR: return "SSL/TLS error";
        case ErrorCode::INVALID_RESPONSE: return "Invalid server response";
        case ErrorCode::UNAUTHORIZED: return "Unauthorized - invalid API key";
        case ErrorCode::RATE_LIMITED: return "Rate limited - too many requests";
        case ErrorCode::INVALID_DOMAIN: return "Invalid domain format";
        case ErrorCode::NETWORK_ERROR: return "Network error";
        case ErrorCode::PARSE_ERROR: return "Response parse error";
        case ErrorCode::UNKNOWN_ERROR: return "Unknown error";
        default: return "Unknown error";
    }
}

// ==================== JSON Parser (Minimal) ====================

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
    Value(std::string&& s) : data(std::move(s)) {}
    
    bool isNull() const { return std::holds_alternative<std::nullptr_t>(data); }
    bool isBool() const { return std::holds_alternative<bool>(data); }
    bool isInt() const { return std::holds_alternative<int64_t>(data); }
    bool isDouble() const { return std::holds_alternative<double>(data); }
    bool isString() const { return std::holds_alternative<std::string>(data); }
    bool isArray() const { return std::holds_alternative<std::vector<Value>>(data); }
    bool isObject() const { return std::holds_alternative<std::map<std::string, Value>>(data); }
    
    bool getBool(bool def = false) const {
        if (isBool()) return std::get<bool>(data);
        return def;
    }
    
    int64_t getInt(int64_t def = 0) const {
        if (isInt()) return std::get<int64_t>(data);
        if (isDouble()) return static_cast<int64_t>(std::get<double>(data));
        return def;
    }
    
    std::string getString(const std::string& def = "") const {
        if (isString()) return std::get<std::string>(data);
        return def;
    }
    
    const std::vector<Value>& getArray() const {
        static std::vector<Value> empty;
        if (isArray()) return std::get<std::vector<Value>>(data);
        return empty;
    }
    
    const Value& operator[](const std::string& key) const {
        static Value null;
        if (isObject()) {
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
    static void skipWhitespace(const std::string& s, size_t& pos) {
        while (pos < s.size() && std::isspace(s[pos])) pos++;
    }
    
    static Value parseValue(const std::string& s, size_t& pos) {
        skipWhitespace(s, pos);
        if (pos >= s.size()) return Value();
        
        char c = s[pos];
        if (c == '"') return parseString(s, pos);
        if (c == '{') return parseObject(s, pos);
        if (c == '[') return parseArray(s, pos);
        if (c == 't' || c == 'f') return parseBool(s, pos);
        if (c == 'n') return parseNull(s, pos);
        if (c == '-' || std::isdigit(c)) return parseNumber(s, pos);
        
        return Value();
    }
    
    static Value parseString(const std::string& s, size_t& pos) {
        pos++; // skip opening quote
        std::string result;
        while (pos < s.size() && s[pos] != '"') {
            if (s[pos] == '\\' && pos + 1 < s.size()) {
                pos++;
                switch (s[pos]) {
                    case 'n': result += '\n'; break;
                    case 't': result += '\t'; break;
                    case 'r': result += '\r'; break;
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    default: result += s[pos];
                }
            } else {
                result += s[pos];
            }
            pos++;
        }
        if (pos < s.size()) pos++; // skip closing quote
        return Value(std::move(result));
    }
    
    static Value parseNumber(const std::string& s, size_t& pos) {
        size_t start = pos;
        bool isFloat = false;
        
        if (s[pos] == '-') pos++;
        while (pos < s.size() && std::isdigit(s[pos])) pos++;
        if (pos < s.size() && s[pos] == '.') {
            isFloat = true;
            pos++;
            while (pos < s.size() && std::isdigit(s[pos])) pos++;
        }
        if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
            isFloat = true;
            pos++;
            if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) pos++;
            while (pos < s.size() && std::isdigit(s[pos])) pos++;
        }
        
        std::string numStr = s.substr(start, pos - start);
        if (isFloat) {
            return Value(std::stod(numStr));
        }
        return Value(std::stoll(numStr));
    }
    
    static Value parseBool(const std::string& s, size_t& pos) {
        if (s.compare(pos, 4, "true") == 0) {
            pos += 4;
            return Value(true);
        }
        if (s.compare(pos, 5, "false") == 0) {
            pos += 5;
            return Value(false);
        }
        return Value();
    }
    
    static Value parseNull(const std::string& s, size_t& pos) {
        if (s.compare(pos, 4, "null") == 0) {
            pos += 4;
        }
        return Value();
    }
    
    static Value parseArray(const std::string& s, size_t& pos) {
        pos++; // skip [
        std::vector<Value> arr;
        skipWhitespace(s, pos);
        
        while (pos < s.size() && s[pos] != ']') {
            arr.push_back(parseValue(s, pos));
            skipWhitespace(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
            skipWhitespace(s, pos);
        }
        if (pos < s.size()) pos++; // skip ]
        
        Value v;
        v.data = std::move(arr);
        return v;
    }
    
    static Value parseObject(const std::string& s, size_t& pos) {
        pos++; // skip {
        std::map<std::string, Value> obj;
        skipWhitespace(s, pos);
        
        while (pos < s.size() && s[pos] != '}') {
            // Parse key
            Value keyVal = parseString(s, pos);
            std::string key = keyVal.getString();
            
            skipWhitespace(s, pos);
            if (pos < s.size() && s[pos] == ':') pos++;
            skipWhitespace(s, pos);
            
            // Parse value
            obj[key] = parseValue(s, pos);
            
            skipWhitespace(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
            skipWhitespace(s, pos);
        }
        if (pos < s.size()) pos++; // skip }
        
        Value v;
        v.data = std::move(obj);
        return v;
    }
};

// JSON builder
std::string escape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

std::string buildArray(const std::vector<std::string>& arr) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < arr.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << escape(arr[i]) << "\"";
    }
    oss << "]";
    return oss.str();
}

} // namespace json

// ==================== HTTP Client ====================

class HttpClient {
public:
    struct URL {
        std::string protocol;
        std::string host;
        int port;
        std::string path;
        bool isHttps;
    };
    
    static URL parseUrl(const std::string& url) {
        URL result;
        result.isHttps = false;
        result.port = 80;
        
        size_t pos = 0;
        
        // Protocol
        size_t protoEnd = url.find("://");
        if (protoEnd != std::string::npos) {
            result.protocol = url.substr(0, protoEnd);
            if (result.protocol == "https") {
                result.isHttps = true;
                result.port = 443;
            }
            pos = protoEnd + 3;
        }
        
        // Host and port
        size_t pathStart = url.find('/', pos);
        std::string hostPort = (pathStart != std::string::npos) 
            ? url.substr(pos, pathStart - pos) 
            : url.substr(pos);
        
        size_t colonPos = hostPort.find(':');
        if (colonPos != std::string::npos) {
            result.host = hostPort.substr(0, colonPos);
            result.port = std::stoi(hostPort.substr(colonPos + 1));
        } else {
            result.host = hostPort;
        }
        
        // Path
        result.path = (pathStart != std::string::npos) ? url.substr(pathStart) : "/";
        
        return result;
    }
    
    static HttpResponse request(
        const std::string& method,
        const std::string& url,
        const std::map<std::string, std::string>& headers,
        const std::string& body,
        int timeoutMs
    ) {
        HttpResponse response;
        URL parsedUrl = parseUrl(url);
        
        #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            response.errorCode = ErrorCode::NETWORK_ERROR;
            response.errorMessage = "WSAStartup failed";
            return response;
        }
        #endif
        
        // Resolve hostname
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        
        std::string portStr = std::to_string(parsedUrl.port);
        if (getaddrinfo(parsedUrl.host.c_str(), portStr.c_str(), &hints, &result) != 0) {
            response.errorCode = ErrorCode::CONNECTION_FAILED;
            response.errorMessage = "DNS resolution failed for " + parsedUrl.host;
            return response;
        }
        
        // Create socket
        SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCK) {
            freeaddrinfo(result);
            response.errorCode = ErrorCode::NETWORK_ERROR;
            response.errorMessage = "Socket creation failed";
            return response;
        }
        
        // Set timeout
        #ifdef _WIN32
        DWORD timeout = timeoutMs;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        #else
        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        #endif
        
        // Connect
        if (::connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) < 0) {
            CLOSE_SOCKET(sock);
            freeaddrinfo(result);
            response.errorCode = ErrorCode::CONNECTION_FAILED;
            response.errorMessage = "Connection failed to " + parsedUrl.host;
            return response;
        }
        freeaddrinfo(result);
        
        #if HAS_SSL
        SSL_CTX* sslCtx = nullptr;
        SSL* ssl = nullptr;
        
        if (parsedUrl.isHttps) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            
            sslCtx = SSL_CTX_new(TLS_client_method());
            if (!sslCtx) {
                CLOSE_SOCKET(sock);
                response.errorCode = ErrorCode::SSL_ERROR;
                response.errorMessage = "SSL context creation failed";
                return response;
            }
            
            ssl = SSL_new(sslCtx);
            SSL_set_fd(ssl, static_cast<int>(sock));
            SSL_set_tlsext_host_name(ssl, parsedUrl.host.c_str());
            
            if (SSL_connect(ssl) <= 0) {
                SSL_free(ssl);
                SSL_CTX_free(sslCtx);
                CLOSE_SOCKET(sock);
                response.errorCode = ErrorCode::SSL_ERROR;
                response.errorMessage = "SSL handshake failed";
                return response;
            }
        }
        #else
        if (parsedUrl.isHttps) {
            CLOSE_SOCKET(sock);
            response.errorCode = ErrorCode::SSL_ERROR;
            response.errorMessage = "HTTPS not supported (compiled without SSL)";
            return response;
        }
        #endif
        
        // Build HTTP request
        std::ostringstream req;
        req << method << " " << parsedUrl.path << " HTTP/1.1\r\n";
        req << "Host: " << parsedUrl.host << "\r\n";
        req << "Connection: close\r\n";
        
        for (const auto& [key, value] : headers) {
            req << key << ": " << value << "\r\n";
        }
        
        if (!body.empty()) {
            req << "Content-Length: " << body.size() << "\r\n";
        }
        req << "\r\n";
        
        if (!body.empty()) {
            req << body;
        }
        
        std::string requestStr = req.str();
        
        // Send request
        auto sendData = [&](const char* data, size_t len) -> bool {
            #if HAS_SSL
            if (ssl) {
                return SSL_write(ssl, data, static_cast<int>(len)) > 0;
            }
            #endif
            return send(sock, data, static_cast<int>(len), 0) > 0;
        };
        
        if (!sendData(requestStr.c_str(), requestStr.size())) {
            #if HAS_SSL
            if (ssl) { SSL_free(ssl); SSL_CTX_free(sslCtx); }
            #endif
            CLOSE_SOCKET(sock);
            response.errorCode = ErrorCode::NETWORK_ERROR;
            response.errorMessage = "Failed to send request";
            return response;
        }
        
        // Receive response
        std::string responseData;
        char buffer[4096];
        
        auto recvData = [&](char* buf, size_t len) -> int {
            #if HAS_SSL
            if (ssl) {
                return SSL_read(ssl, buf, static_cast<int>(len));
            }
            #endif
            return recv(sock, buf, static_cast<int>(len), 0);
        };
        
        int bytesRead;
        while ((bytesRead = recvData(buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytesRead] = '\0';
            responseData += buffer;
            if (responseData.size() > MAX_RESPONSE_SIZE) break;
        }
        
        // Cleanup
        #if HAS_SSL
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(sslCtx);
        }
        #endif
        CLOSE_SOCKET(sock);
        
        #ifdef _WIN32
        WSACleanup();
        #endif
        
        // Parse response
        size_t headerEnd = responseData.find("\r\n\r\n");
        if (headerEnd == std::string::npos) {
            response.errorCode = ErrorCode::INVALID_RESPONSE;
            response.errorMessage = "Invalid HTTP response";
            return response;
        }
        
        std::string headerSection = responseData.substr(0, headerEnd);
        response.body = responseData.substr(headerEnd + 4);
        
        // Parse status line
        size_t statusEnd = headerSection.find("\r\n");
        if (statusEnd != std::string::npos) {
            std::string statusLine = headerSection.substr(0, statusEnd);
            size_t codeStart = statusLine.find(' ');
            if (codeStart != std::string::npos) {
                response.statusCode = std::stoi(statusLine.substr(codeStart + 1));
            }
        }
        
        // Parse headers
        size_t pos = statusEnd + 2;
        while (pos < headerSection.size()) {
            size_t lineEnd = headerSection.find("\r\n", pos);
            if (lineEnd == std::string::npos) break;
            
            std::string line = headerSection.substr(pos, lineEnd - pos);
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                // Trim
                while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                response.headers[key] = value;
            }
            pos = lineEnd + 2;
        }
        
        response.errorCode = ErrorCode::OK;
        return response;
    }
};

// ==================== Cache ====================

struct CacheEntry {
    ResolveResult result;
    std::chrono::steady_clock::time_point expiry;
};

// ==================== Client Implementation ====================

class Client::Impl {
public:
    ClientConfig config;
    std::atomic<bool> connected{false};
    mutable std::string lastError;
    mutable ErrorCode lastErrorCode{ErrorCode::OK};
    
    // Local blocklist
    std::unordered_set<std::string> localBlocklist;
    mutable std::shared_mutex blocklistMutex;
    
    // Cache
    std::unordered_map<std::string, CacheEntry> cache;
    mutable std::shared_mutex cacheMutex;
    
    // Default blocklist patterns
    std::vector<std::string> defaultPatterns = {
        "doubleclick", "googlesyndication", "googleadservices",
        "google-analytics", "googletagmanager", "adservice",
        "pagead", "admob", "adsense", "adnxs", "advertising",
        "adform", "adsrvr", "adtechus", "mopub", "unityads",
        "applovin", "vungle", "chartboost", "ironsrc", "inmobi",
        "startapp", "tapjoy", "fyber", "facebook.com/ads",
        "an.facebook", "pixel.facebook", "analytics", "tracker",
        "tracking", "telemetry", "mixpanel", "segment.com",
        "amplitude", "branch.io", "adjust.com", "appsflyer",
        "kochava", "popads", "popcash", "propellerads",
        "taboola", "outbrain", "revcontent", "mgid"
    };
    
    Impl(std::string_view serverUrl, std::string_view apiKey) {
        config.serverUrl = serverUrl;
        config.apiKey = apiKey;
        
        // Remove trailing slash
        if (!config.serverUrl.empty() && config.serverUrl.back() == '/') {
            config.serverUrl.pop_back();
        }
        
        // Initialize default local blocklist
        initDefaultBlocklist();
    }
    
    Impl(const ClientConfig& cfg) : config(cfg) {
        if (!config.serverUrl.empty() && config.serverUrl.back() == '/') {
            config.serverUrl.pop_back();
        }
        
        for (const auto& domain : config.localBlocklist) {
            localBlocklist.insert(normalizeDomain(domain));
        }
        
        initDefaultBlocklist();
    }
    
    void initDefaultBlocklist() {
        // Add common ad domains to local blocklist for fast blocking
        std::vector<std::string> defaultDomains = {
            "doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "google-analytics.com", "googletagmanager.com", "adservice.google.com",
            "admob.com", "adsense.google.com", "adnxs.com", "advertising.com",
            "mopub.com", "unityads.unity3d.com", "applovin.com", "vungle.com",
            "chartboost.com", "ironsrc.com", "inmobi.com", "tapjoy.com",
            "an.facebook.com", "pixel.facebook.com", "analytics.facebook.com",
            "popads.net", "popcash.net", "taboola.com", "outbrain.com"
        };
        
        std::lock_guard lock(blocklistMutex);
        for (const auto& domain : defaultDomains) {
            localBlocklist.insert(domain);
        }
    }
    
    HttpResponse makeRequest(const std::string& endpoint, 
                            const std::string& method = "GET",
                            const std::string& body = "") {
        std::map<std::string, std::string> headers;
        headers["X-API-Key"] = config.apiKey;
        headers["Content-Type"] = "application/json";
        headers["Accept"] = "application/json";
        headers["User-Agent"] = "DnsBlocker-CPP/" + std::string(VERSION);
        
        std::string url = config.serverUrl + endpoint;
        
        HttpResponse response = HttpClient::request(method, url, headers, body, config.timeoutMs);
        
        if (response.errorCode != ErrorCode::OK) {
            lastError = response.errorMessage;
            lastErrorCode = response.errorCode;
        } else if (response.statusCode == 401) {
            lastError = "Unauthorized - invalid API key";
            lastErrorCode = ErrorCode::UNAUTHORIZED;
        } else if (response.statusCode == 429) {
            lastError = "Rate limited";
            lastErrorCode = ErrorCode::RATE_LIMITED;
        } else if (!response.isSuccess()) {
            lastError = "HTTP error: " + std::to_string(response.statusCode);
            lastErrorCode = ErrorCode::INVALID_RESPONSE;
        }
        
        return response;
    }
    
    bool matchesPattern(const std::string& domain) const {
        std::string lowerDomain = domain;
        std::transform(lowerDomain.begin(), lowerDomain.end(), 
                      lowerDomain.begin(), ::tolower);
        
        for (const auto& pattern : defaultPatterns) {
            if (lowerDomain.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    
    bool isInLocalBlocklist(const std::string& domain) const {
        std::string normalized = normalizeDomain(domain);
        
        std::shared_lock lock(blocklistMutex);
        
        // Exact match
        if (localBlocklist.count(normalized)) {
            return true;
        }
        
        // Check parent domains
        size_t pos = 0;
        while ((pos = normalized.find('.', pos)) != std::string::npos) {
            std::string parent = normalized.substr(pos + 1);
            if (localBlocklist.count(parent)) {
                return true;
            }
            pos++;
        }
        
        return matchesPattern(normalized);
    }
    
    std::optional<ResolveResult> getFromCache(const std::string& domain) const {
        if (!config.enableCache) return std::nullopt;
        
        std::shared_lock lock(cacheMutex);
        auto it = cache.find(domain);
        if (it != cache.end()) {
            if (std::chrono::steady_clock::now() < it->second.expiry) {
                return it->second.result;
            }
        }
        return std::nullopt;
    }
    
    void addToCache(const std::string& domain, const ResolveResult& result) {
        if (!config.enableCache) return;
        
        std::lock_guard lock(cacheMutex);
        cache[domain] = {
            result,
            std::chrono::steady_clock::now() + 
                std::chrono::seconds(config.cacheTtlSeconds)
        };
    }
};

// ==================== Client Public Methods ====================

Client::Client(std::string_view serverUrl, std::string_view apiKey)
    : pImpl(std::make_unique<Impl>(serverUrl, apiKey)) {}

Client::Client(const ClientConfig& config)
    : pImpl(std::make_unique<Impl>(config)) {}

Client::~Client() = default;

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

ConnectionInfo Client::connect() {
    ConnectionInfo info;
    
    auto response = pImpl->makeRequest("/connect");
    if (response.errorCode != ErrorCode::OK || !response.isSuccess()) {
        info.error = pImpl->lastError;
        info.errorCode = pImpl->lastErrorCode;
        return info;
    }
    
    auto json = json::Parser::parse(response.body);
    
    info.success = json["success"].getBool();
    if (info.success) {
        pImpl->connected = true;
        info.clientIp = json["client_ip"].getString();
        info.serverTime = json["server_time"].getInt();
        info.blockedDomainsCount = static_cast<int>(json["blocked_domains_count"].getInt());
        info.message = json["message"].getString();
    } else {
        info.error = json["error"].getString();
        info.errorCode = ErrorCode::UNAUTHORIZED;
    }
    
    return info;
}

ResolveResult Client::resolve(std::string_view domain) {
    ResolveResult result;
    std::string domainStr(domain);
    result.domain = domainStr;
    
    // Validate domain
    if (!isValidDomain(domain)) {
        result.errorCode = ErrorCode::INVALID_DOMAIN;
        return result;
    }
    
    // Check local blocklist first (fast)
    if (pImpl->isInLocalBlocklist(domainStr)) {
        result.success = true;
        result.blocked = true;
        result.ipv4 = "0.0.0.0";
        result.ipv6 = "::";
        result.reason = "local_blocklist";
        return result;
    }
    
    // Check cache
    auto cached = pImpl->getFromCache(domainStr);
    if (cached) {
        return *cached;
    }
    
    // Remote resolve
    auto response = pImpl->makeRequest("/resolve?domain=" + domainStr);
    if (response.errorCode != ErrorCode::OK || !response.isSuccess()) {
        result.errorCode = pImpl->lastErrorCode;
        return result;
    }
    
    auto json = json::Parser::parse(response.body);
    
    result.success = json["success"].getBool();
    result.blocked = json["blocked"].getBool();
    result.ipv4 = json["ip"].getString();
    result.ipv6 = json["ipv6"].getString();
    result.ttl = static_cast<int>(json["ttl"].getInt(300));
    result.reason = json["reason"].getString();
    
    // Cache the result
    pImpl->addToCache(domainStr, result);
    
    return result;
}

bool Client::isBlocked(std::string_view domain) {
    std::string domainStr(domain);
    
    // Fast local check
    if (pImpl->isInLocalBlocklist(domainStr)) {
        return true;
    }
    
    // Check cache
    auto cached = pImpl->getFromCache(domainStr);
    if (cached) {
        return cached->blocked;
    }
    
    // Remote check
    auto response = pImpl->makeRequest("/check?domain=" + domainStr);
    if (response.errorCode != ErrorCode::OK || !response.isSuccess()) {
        return pImpl->isInLocalBlocklist(domainStr);
    }
    
    auto json = json::Parser::parse(response.body);
    return json["blocked"].getBool();
}

std::map<std::string, ResolveResult> Client::bulkResolve(
    const std::vector<std::string>& domains) {
    
    std::map<std::string, ResolveResult> results;
    std::vector<std::string> toResolve;
    
    // Check local blocklist and cache first
    for (const auto& domain : domains) {
        if (pImpl->isInLocalBlocklist(domain)) {
            ResolveResult result;
            result.domain = domain;
            result.success = true;
            result.blocked = true;
            result.ipv4 = "0.0.0.0";
            results[domain] = result;
        } else if (auto cached = pImpl->getFromCache(domain)) {
            results[domain] = *cached;
        } else {
            toResolve.push_back(domain);
        }
    }
    
    // Bulk resolve remaining domains
    if (!toResolve.empty() && toResolve.size() <= MAX_DOMAINS_BULK) {
        std::string body = "{\"domains\":" + json::buildArray(toResolve) + "}";
        auto response = pImpl->makeRequest("/bulk-resolve", "POST", body);
        
        if (response.isSuccess()) {
            auto json = json::Parser::parse(response.body);
            const auto& resultsJson = json["results"];
            
            for (const auto& domain : toResolve) {
                const auto& domainResult = resultsJson[domain];
                ResolveResult result;
                result.domain = domain;
                result.success = true;
                result.blocked = domainResult["blocked"].getBool();
                result.ipv4 = domainResult["ip"].getString();
                results[domain] = result;
                
                pImpl->addToCache(domain, result);
            }
        }
    }
    
    return results;
}

ApiStatus Client::getStatus() {
    ApiStatus status;
    
    auto response = pImpl->makeRequest("/status");
    if (!response.isSuccess()) {
        return status;
    }
    
    auto json = json::Parser::parse(response.body);
    
    status.online = (json["status"].getString() == "online");
    status.version = json["version"].getString();
    status.blockedDomainsCount = static_cast<int>(json["blocked_domains"].getInt());
    status.serverTime = json["server_time"].getString();
    status.uptime = json["uptime"].getString();
    
    return status;
}

std::vector<std::string> Client::getBlocklist() {
    auto response = pImpl->makeRequest("/blocklist");
    if (!response.isSuccess()) {
        return {};
    }
    
    auto json = json::Parser::parse(response.body);
    const auto& domains = json["domains"].getArray();
    
    std::vector<std::string> result;
    for (const auto& d : domains) {
        result.push_back(d.getString());
    }
    return result;
}

bool Client::addToBlocklist(const std::vector<std::string>& domains) {
    std::string body = "{\"add\":" + json::buildArray(domains) + "}";
    auto response = pImpl->makeRequest("/blocklist", "POST", body);
    return response.isSuccess();
}

bool Client::removeFromBlocklist(const std::vector<std::string>& domains) {
    std::string body = "{\"remove\":" + json::buildArray(domains) + "}";
    auto response = pImpl->makeRequest("/blocklist", "POST", body);
    return response.isSuccess();
}

// Async methods
std::future<ConnectionInfo> Client::connectAsync() {
    return std::async(std::launch::async, [this]() { return connect(); });
}

std::future<ResolveResult> Client::resolveAsync(std::string_view domain) {
    std::string d(domain);
    return std::async(std::launch::async, [this, d]() { return resolve(d); });
}

void Client::connectAsync(ConnectCallback callback) {
    std::thread([this, callback]() {
        callback(connect());
    }).detach();
}

void Client::resolveAsync(std::string_view domain, ResolveCallback callback) {
    std::string d(domain);
    std::thread([this, d, callback]() {
        callback(resolve(d));
    }).detach();
}

void Client::getStatusAsync(StatusCallback callback) {
    std::thread([this, callback]() {
        callback(getStatus());
    }).detach();
}

// Local blocklist methods
void Client::addLocalBlock(std::string_view domain) {
    std::lock_guard lock(pImpl->blocklistMutex);
    pImpl->localBlocklist.insert(std::string(normalizeDomain(domain)));
}

void Client::removeLocalBlock(std::string_view domain) {
    std::lock_guard lock(pImpl->blocklistMutex);
    pImpl->localBlocklist.erase(std::string(normalizeDomain(domain)));
}

bool Client::isLocallyBlocked(std::string_view domain) const {
    return pImpl->isInLocalBlocklist(std::string(domain));
}

bool Client::loadLocalBlocklist(std::string_view filepath) {
    std::ifstream file(std::string(filepath));
    if (!file) return false;
    
    std::lock_guard lock(pImpl->blocklistMutex);
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        pImpl->localBlocklist.insert(normalizeDomain(line));
    }
    return true;
}

bool Client::saveLocalBlocklist(std::string_view filepath) const {
    std::ofstream file(std::string(filepath));
    if (!file) return false;
    
    std::shared_lock lock(pImpl->blocklistMutex);
    file << "# DNS Blocker Local Blocklist\n";
    for (const auto& domain : pImpl->localBlocklist) {
        file << domain << "\n";
    }
    return true;
}

std::vector<std::string> Client::getLocalBlocklist() const {
    std::shared_lock lock(pImpl->blocklistMutex);
    return {pImpl->localBlocklist.begin(), pImpl->localBlocklist.end()};
}

void Client::clearLocalBlocklist() {
    std::lock_guard lock(pImpl->blocklistMutex);
    pImpl->localBlocklist.clear();
}

// Configuration methods
void Client::setTimeout(int timeoutMs) {
    pImpl->config.timeoutMs = timeoutMs;
}

int Client::getTimeout() const {
    return pImpl->config.timeoutMs;
}

void Client::setCacheEnabled(bool enabled) {
    pImpl->config.enableCache = enabled;
}

void Client::clearCache() {
    std::lock_guard lock(pImpl->cacheMutex);
    pImpl->cache.clear();
}

std::string Client::getLastError() const {
    return pImpl->lastError;
}

ErrorCode Client::getLastErrorCode() const {
    return pImpl->lastErrorCode;
}

bool Client::isConnected() const {
    return pImpl->connected;
}

const ClientConfig& Client::getConfig() const {
    return pImpl->config;
}

// ==================== Utility Functions ====================

bool isValidDomain(std::string_view domain) {
    if (domain.empty() || domain.length() > 253) return false;
    
    // Simple validation
    for (char c : domain) {
        if (!std::isalnum(c) && c != '.' && c != '-') {
            return false;
        }
    }
    return true;
}

std::string normalizeDomain(std::string_view domain) {
    std::string result(domain);
    
    // Remove protocol
    if (result.find("http://") == 0) result = result.substr(7);
    if (result.find("https://") == 0) result = result.substr(8);
    
    // Remove path
    size_t slashPos = result.find('/');
    if (slashPos != std::string::npos) {
        result = result.substr(0, slashPos);
    }
    
    // Lowercase
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    
    // Trim
    while (!result.empty() && std::isspace(result.front())) result.erase(0, 1);
    while (!result.empty() && std::isspace(result.back())) result.pop_back();
    
    return result;
}

bool isBlockedIP(std::string_view ip) {
    return ip == "0.0.0.0" || ip == "::" || ip == "127.0.0.1" || ip.empty();
}

std::vector<std::string> getDefaultBlocklist() {
    return {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "google-analytics.com", "googletagmanager.com", "adservice.google.com",
        "admob.com", "adsense.google.com", "adnxs.com", "advertising.com",
        "mopub.com", "unityads.unity3d.com", "applovin.com", "vungle.com",
        "chartboost.com", "ironsrc.com", "inmobi.com", "tapjoy.com",
        "an.facebook.com", "pixel.facebook.com", "analytics.facebook.com",
        "popads.net", "popcash.net", "taboola.com", "outbrain.com",
        "crashlytics.com", "mixpanel.com", "amplitude.com", "segment.com"
    };
}

} // namespace DnsBlocker

// ==================== C API Implementation ====================

static std::string g_lastResolveResult;

extern "C" {

DnsBlockerHandle dns_blocker_create(const char* server_url, const char* api_key) {
    if (!server_url || !api_key) return nullptr;
    try {
        auto* client = new DnsBlocker::Client(server_url, api_key);
        return static_cast<DnsBlockerHandle>(client);
    } catch (...) {
        return nullptr;
    }
}

void dns_blocker_destroy(DnsBlockerHandle handle) {
    if (handle) {
        delete static_cast<DnsBlocker::Client*>(handle);
    }
}

int dns_blocker_connect(DnsBlockerHandle handle) {
    if (!handle) return 0;
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    auto info = client->connect();
    return info.success ? 1 : 0;
}

int dns_blocker_is_blocked(DnsBlockerHandle handle, const char* domain) {
    if (!handle || !domain) return 0;
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    return client->isBlocked(domain) ? 1 : 0;
}

const char* dns_blocker_resolve(DnsBlockerHandle handle, const char* domain) {
    if (!handle || !domain) return "";
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    auto result = client->resolve(domain);
    g_lastResolveResult = result.blocked ? "0.0.0.0" : result.ipv4;
    return g_lastResolveResult.c_str();
}

const char* dns_blocker_get_error(DnsBlockerHandle handle) {
    if (!handle) return "Invalid handle";
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    static std::string error;
    error = client->getLastError();
    return error.c_str();
}

void dns_blocker_set_timeout(DnsBlockerHandle handle, int timeout_ms) {
    if (!handle) return;
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    client->setTimeout(timeout_ms);
}

void dns_blocker_add_local_block(DnsBlockerHandle handle, const char* domain) {
    if (!handle || !domain) return;
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    client->addLocalBlock(domain);
}

void dns_blocker_remove_local_block(DnsBlockerHandle handle, const char* domain) {
    if (!handle || !domain) return;
    auto* client = static_cast<DnsBlocker::Client*>(handle);
    client->removeLocalBlock(domain);
}

} // extern "C"
