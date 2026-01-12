/**
 * Stealth DNS Client - C++17
 * 
 * Features:
 * - Encrypted communication (AES-256-GCM)
 * - Obfuscated API calls
 * - Binary protocol support
 * - Anti-detection measures
 * - Looks like normal cloud sync traffic
 * 
 * Build:
 *   g++ -std=c++17 -shared -fPIC -o libcloudsync.so DnsBlockerClient.cpp -lssl -lcrypto -pthread
 */

#ifndef CLOUD_SYNC_CLIENT_HPP
#define CLOUD_SYNC_CLIENT_HPP

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <future>
#include <random>

// Obfuscated namespace (looks like cloud service)
namespace CloudSync {

// Version (obfuscated)
constexpr const char* LIB_VERSION = "3.2.1";
constexpr int PROTOCOL_VERSION = 2;

// Timing constants
constexpr int DEFAULT_TIMEOUT_MS = 10000;
constexpr size_t MAX_RESPONSE_SIZE = 1024 * 1024;
constexpr size_t MAX_BATCH_SIZE = 50;

/**
 * Result codes (generic names)
 */
enum class ResultCode {
    OK = 0,
    CONN_ERROR,
    TIMEOUT,
    CRYPTO_ERROR,
    INVALID_DATA,
    AUTH_FAILED,
    LIMIT_EXCEEDED,
    INVALID_INPUT,
    NET_ERROR,
    PARSE_ERROR,
    UNKNOWN
};

[[nodiscard]] const char* getResultMessage(ResultCode code) noexcept;

/**
 * Query result (obfuscated field names)
 */
struct QueryResult {
    std::string target;      // domain
    std::string addr;        // ipv4
    std::string addr6;       // ipv6
    int flag = 0;            // 0=allow, 1=block
    bool valid = false;
    int ttl = 300;
    
    [[nodiscard]] bool isFiltered() const noexcept { return flag == 1; }
    [[nodiscard]] bool isOk() const noexcept { return valid; }
};

/**
 * Service status
 */
struct ServiceStatus {
    bool active = false;
    std::string ver;
    int dataCount = 0;
    int64_t timestamp = 0;
};

/**
 * Session info
 */
struct SessionInfo {
    bool ok = false;
    std::string token;
    std::string clientId;
    int64_t timestamp = 0;
    int dataCount = 0;
    std::string error;
    ResultCode code = ResultCode::OK;
};

/**
 * Client configuration
 */
struct ClientConfig {
    std::string endpoint;        // server URL
    std::string secret;          // encryption key
    int timeoutMs = DEFAULT_TIMEOUT_MS;
    bool useEncryption = true;
    bool useBinaryProtocol = false;
    bool enableLocalCache = true;
    int cacheTtlSec = 300;
    
    // Stealth options
    bool randomizeHeaders = true;
    bool randomizeEndpoints = true;
    int requestJitterMs = 0;     // Random delay 0-N ms
};

// Callback types
using SessionCallback = std::function<void(const SessionInfo&)>;
using QueryCallback = std::function<void(const QueryResult&)>;
using StatusCallback = std::function<void(const ServiceStatus&)>;

/**
 * Cloud Sync Client (Stealth DNS Blocker)
 * 
 * All method and class names are obfuscated to look like
 * a generic cloud synchronization service.
 */
class SyncClient {
public:
    /**
     * Create client with endpoint and secret key
     */
    explicit SyncClient(std::string_view endpoint, std::string_view secret);
    
    /**
     * Create client with config
     */
    explicit SyncClient(const ClientConfig& config);
    
    ~SyncClient();
    
    // No copy
    SyncClient(const SyncClient&) = delete;
    SyncClient& operator=(const SyncClient&) = delete;
    
    // Move OK
    SyncClient(SyncClient&&) noexcept;
    SyncClient& operator=(SyncClient&&) noexcept;
    
    // ==================== Core API ====================
    
    /**
     * Initialize session (connect)
     */
    [[nodiscard]] SessionInfo initSession();
    
    /**
     * Query single item (resolve domain)
     */
    [[nodiscard]] QueryResult query(std::string_view item);
    
    /**
     * Quick check if item is filtered (blocked)
     */
    [[nodiscard]] bool isFiltered(std::string_view item);
    
    /**
     * Batch query multiple items
     */
    [[nodiscard]] std::map<std::string, QueryResult> queryBatch(
        const std::vector<std::string>& items);
    
    /**
     * Get service status
     */
    [[nodiscard]] ServiceStatus getStatus();
    
    /**
     * Sync filter data from server
     */
    [[nodiscard]] std::vector<std::string> syncData();
    
    // ==================== Async API ====================
    
    std::future<SessionInfo> initSessionAsync();
    std::future<QueryResult> queryAsync(std::string_view item);
    void initSessionAsync(SessionCallback callback);
    void queryAsync(std::string_view item, QueryCallback callback);
    
    // ==================== Local Filter ====================
    
    /**
     * Check local filter only (very fast, no network)
     */
    [[nodiscard]] bool checkLocal(std::string_view item) const;
    
    /**
     * Add item to local filter
     */
    void addLocalFilter(std::string_view item);
    
    /**
     * Remove item from local filter
     */
    void removeLocalFilter(std::string_view item);
    
    /**
     * Load filter from file
     */
    bool loadFilterFile(std::string_view path);
    
    /**
     * Save filter to file
     */
    bool saveFilterFile(std::string_view path) const;
    
    /**
     * Get local filter list
     */
    [[nodiscard]] std::vector<std::string> getLocalFilter() const;
    
    /**
     * Clear local filter
     */
    void clearLocalFilter();
    
    // ==================== Configuration ====================
    
    void setTimeout(int ms);
    [[nodiscard]] int getTimeout() const;
    void setCacheEnabled(bool enabled);
    void clearCache();
    [[nodiscard]] std::string getLastError() const;
    [[nodiscard]] ResultCode getLastResultCode() const;
    [[nodiscard]] bool isSessionActive() const;
    [[nodiscard]] const ClientConfig& getConfig() const;
    [[nodiscard]] std::string getSessionToken() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ==================== Utility ====================

[[nodiscard]] bool isValidTarget(std::string_view item);
[[nodiscard]] std::string normalizeTarget(std::string_view item);
[[nodiscard]] bool isNullAddress(std::string_view addr);
[[nodiscard]] std::vector<std::string> getBuiltinFilters();

} // namespace CloudSync

// ==================== C API (for JNI/FFI) ====================

#ifdef __cplusplus
extern "C" {
#endif

typedef void* CSyncHandle;

CSyncHandle csync_create(const char* endpoint, const char* secret);
void csync_destroy(CSyncHandle h);
int csync_init(CSyncHandle h);
int csync_check(CSyncHandle h, const char* item);
const char* csync_query(CSyncHandle h, const char* item);
const char* csync_error(CSyncHandle h);
void csync_timeout(CSyncHandle h, int ms);
void csync_add_filter(CSyncHandle h, const char* item);
void csync_remove_filter(CSyncHandle h, const char* item);
int csync_check_local(CSyncHandle h, const char* item);
const char* csync_token(CSyncHandle h);

#ifdef __cplusplus
}
#endif

// Backward compatibility aliases
namespace DnsBlocker = CloudSync;
using DnsBlockerClient = CloudSync::SyncClient;

#endif // CLOUD_SYNC_CLIENT_HPP
