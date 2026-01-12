/**
 * DNS Blocker API Client for C++17
 * 
 * A lightweight, self-contained HTTP client for DNS Blocker API
 * Designed for use as a library in Android APK via NDK/JNI
 * 
 * Features:
 * - No external dependencies (uses system sockets)
 * - C++17 compatible
 * - Thread-safe design
 * - JNI ready for Android integration
 * - SSL/TLS support via OpenSSL (optional)
 * 
 * Build as library:
 *   g++ -std=c++17 -shared -fPIC -o libdnsblocker.so DnsBlockerClient.cpp -lssl -lcrypto -pthread
 * 
 * Build static:
 *   g++ -std=c++17 -c DnsBlockerClient.cpp -o DnsBlockerClient.o
 *   ar rcs libdnsblocker.a DnsBlockerClient.o
 */

#ifndef DNS_BLOCKER_CLIENT_HPP
#define DNS_BLOCKER_CLIENT_HPP

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <optional>
#include <variant>
#include <mutex>
#include <atomic>
#include <chrono>
#include <future>

namespace DnsBlocker {

// Version info
constexpr const char* VERSION = "2.0.0";
constexpr int VERSION_MAJOR = 2;
constexpr int VERSION_MINOR = 0;
constexpr int VERSION_PATCH = 0;

// Configuration constants
constexpr int DEFAULT_TIMEOUT_MS = 10000;
constexpr int DEFAULT_PORT_HTTP = 80;
constexpr int DEFAULT_PORT_HTTPS = 443;
constexpr size_t MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB
constexpr size_t MAX_DOMAINS_BULK = 50;

/**
 * Error codes
 */
enum class ErrorCode {
    OK = 0,
    CONNECTION_FAILED,
    TIMEOUT,
    SSL_ERROR,
    INVALID_RESPONSE,
    UNAUTHORIZED,
    RATE_LIMITED,
    INVALID_DOMAIN,
    NETWORK_ERROR,
    PARSE_ERROR,
    UNKNOWN_ERROR
};

/**
 * Convert error code to string
 */
[[nodiscard]] const char* errorCodeToString(ErrorCode code) noexcept;

/**
 * DNS Resolution result
 */
struct ResolveResult {
    std::string domain;
    std::string ipv4;
    std::string ipv6;
    bool blocked = false;
    bool success = false;
    int ttl = 300;
    std::string reason;
    ErrorCode errorCode = ErrorCode::OK;
    
    [[nodiscard]] bool isBlocked() const noexcept { return blocked; }
    [[nodiscard]] bool isValid() const noexcept { return success; }
    [[nodiscard]] const std::string& getIP() const noexcept { return ipv4; }
};

/**
 * API Status
 */
struct ApiStatus {
    bool online = false;
    std::string version;
    int blockedDomainsCount = 0;
    std::string serverTime;
    std::string uptime;
    
    [[nodiscard]] bool isOnline() const noexcept { return online; }
};

/**
 * Connection info
 */
struct ConnectionInfo {
    bool success = false;
    std::string clientIp;
    int64_t serverTime = 0;
    int blockedDomainsCount = 0;
    std::string message;
    std::string error;
    ErrorCode errorCode = ErrorCode::OK;
    
    [[nodiscard]] bool isConnected() const noexcept { return success; }
};

/**
 * HTTP Response
 */
struct HttpResponse {
    int statusCode = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    ErrorCode errorCode = ErrorCode::OK;
    std::string errorMessage;
    
    [[nodiscard]] bool isSuccess() const noexcept { 
        return statusCode >= 200 && statusCode < 300; 
    }
};

/**
 * Client configuration
 */
struct ClientConfig {
    std::string serverUrl;
    std::string apiKey;
    int timeoutMs = DEFAULT_TIMEOUT_MS;
    bool useSSL = true;
    bool verifyCert = true;
    int maxRetries = 3;
    int retryDelayMs = 1000;
    bool enableCache = true;
    int cacheTtlSeconds = 300;
    
    // Local blocklist for offline/fast blocking
    std::vector<std::string> localBlocklist;
};

/**
 * Async callback types
 */
using ConnectCallback = std::function<void(const ConnectionInfo&)>;
using ResolveCallback = std::function<void(const ResolveResult&)>;
using StatusCallback = std::function<void(const ApiStatus&)>;
using BlocklistCallback = std::function<void(const std::vector<std::string>&)>;

/**
 * DNS Blocker API Client
 * 
 * Thread-safe client for DNS blocking API
 */
class Client {
public:
    /**
     * Constructor with URL and API key
     */
    explicit Client(std::string_view serverUrl, std::string_view apiKey);
    
    /**
     * Constructor with config
     */
    explicit Client(const ClientConfig& config);
    
    /**
     * Destructor
     */
    ~Client();
    
    // Disable copy
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    
    // Enable move
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;
    
    // ==================== Synchronous API ====================
    
    /**
     * Connect to DNS Blocker API
     */
    [[nodiscard]] ConnectionInfo connect();
    
    /**
     * Resolve a domain with ad blocking
     */
    [[nodiscard]] ResolveResult resolve(std::string_view domain);
    
    /**
     * Check if a domain is blocked (fast local + remote check)
     */
    [[nodiscard]] bool isBlocked(std::string_view domain);
    
    /**
     * Resolve multiple domains at once
     */
    [[nodiscard]] std::map<std::string, ResolveResult> bulkResolve(
        const std::vector<std::string>& domains);
    
    /**
     * Get API status
     */
    [[nodiscard]] ApiStatus getStatus();
    
    /**
     * Get blocklist from server
     */
    [[nodiscard]] std::vector<std::string> getBlocklist();
    
    /**
     * Add domains to remote blocklist
     */
    bool addToBlocklist(const std::vector<std::string>& domains);
    
    /**
     * Remove domains from remote blocklist
     */
    bool removeFromBlocklist(const std::vector<std::string>& domains);
    
    // ==================== Asynchronous API ====================
    
    /**
     * Async connect
     */
    std::future<ConnectionInfo> connectAsync();
    
    /**
     * Async resolve
     */
    std::future<ResolveResult> resolveAsync(std::string_view domain);
    
    /**
     * Async with callback
     */
    void connectAsync(ConnectCallback callback);
    void resolveAsync(std::string_view domain, ResolveCallback callback);
    void getStatusAsync(StatusCallback callback);
    
    // ==================== Local Blocklist ====================
    
    /**
     * Add domain to local blocklist (instant blocking, no network)
     */
    void addLocalBlock(std::string_view domain);
    
    /**
     * Remove domain from local blocklist
     */
    void removeLocalBlock(std::string_view domain);
    
    /**
     * Check if domain is in local blocklist
     */
    [[nodiscard]] bool isLocallyBlocked(std::string_view domain) const;
    
    /**
     * Load local blocklist from file
     */
    bool loadLocalBlocklist(std::string_view filepath);
    
    /**
     * Save local blocklist to file
     */
    bool saveLocalBlocklist(std::string_view filepath) const;
    
    /**
     * Get local blocklist
     */
    [[nodiscard]] std::vector<std::string> getLocalBlocklist() const;
    
    /**
     * Clear local blocklist
     */
    void clearLocalBlocklist();
    
    // ==================== Configuration ====================
    
    /**
     * Set connection timeout
     */
    void setTimeout(int timeoutMs);
    
    /**
     * Get connection timeout
     */
    [[nodiscard]] int getTimeout() const;
    
    /**
     * Enable/disable response caching
     */
    void setCacheEnabled(bool enabled);
    
    /**
     * Clear response cache
     */
    void clearCache();
    
    /**
     * Get last error message
     */
    [[nodiscard]] std::string getLastError() const;
    
    /**
     * Get last error code
     */
    [[nodiscard]] ErrorCode getLastErrorCode() const;
    
    /**
     * Check if connected
     */
    [[nodiscard]] bool isConnected() const;
    
    /**
     * Get client configuration
     */
    [[nodiscard]] const ClientConfig& getConfig() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ==================== Utility Functions ====================

/**
 * Validate domain format
 */
[[nodiscard]] bool isValidDomain(std::string_view domain);

/**
 * Normalize domain (lowercase, trim, remove protocol)
 */
[[nodiscard]] std::string normalizeDomain(std::string_view domain);

/**
 * Check if IP is a blocked response (0.0.0.0, ::, etc.)
 */
[[nodiscard]] bool isBlockedIP(std::string_view ip);

/**
 * Get default ad blocklist
 */
[[nodiscard]] std::vector<std::string> getDefaultBlocklist();

} // namespace DnsBlocker

// ==================== C API for JNI/FFI ====================

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
typedef void* DnsBlockerHandle;

// C API functions
DnsBlockerHandle dns_blocker_create(const char* server_url, const char* api_key);
void dns_blocker_destroy(DnsBlockerHandle handle);
int dns_blocker_connect(DnsBlockerHandle handle);
int dns_blocker_is_blocked(DnsBlockerHandle handle, const char* domain);
const char* dns_blocker_resolve(DnsBlockerHandle handle, const char* domain);
const char* dns_blocker_get_error(DnsBlockerHandle handle);
void dns_blocker_set_timeout(DnsBlockerHandle handle, int timeout_ms);
void dns_blocker_add_local_block(DnsBlockerHandle handle, const char* domain);
void dns_blocker_remove_local_block(DnsBlockerHandle handle, const char* domain);

#ifdef __cplusplus
}
#endif

#endif // DNS_BLOCKER_CLIENT_HPP
