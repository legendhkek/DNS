/**
 * Game Config Manager
 * Lightweight data sync module
 */

#ifndef GAME_CONFIG_MGR_HPP
#define GAME_CONFIG_MGR_HPP

#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <functional>
#include <future>

namespace GameConfig {

// Result structure
struct DataResult {
    std::string key;
    std::string value;
    int status = 0;  // 0=ok, 1=filtered
    bool valid = false;
};

// Session info
struct SessionData {
    bool active = false;
    int64_t timestamp = 0;
    int count = 0;
};

// Callback
using ResultCallback = std::function<void(const DataResult&)>;

/**
 * Config Manager - handles data sync
 */
class ConfigMgr {
public:
    // Create with server endpoint
    explicit ConfigMgr(const std::string& endpoint);
    ~ConfigMgr();
    
    // No copy
    ConfigMgr(const ConfigMgr&) = delete;
    ConfigMgr& operator=(const ConfigMgr&) = delete;
    
    // Connect to server
    bool init();
    
    // Check if key is filtered
    bool check(const std::string& key);
    
    // Query key
    DataResult query(const std::string& key);
    
    // Batch query
    std::map<std::string, DataResult> queryBatch(const std::vector<std::string>& keys);
    
    // Local check (fast, no network)
    bool checkLocal(const std::string& key) const;
    
    // Add to local filter
    void addFilter(const std::string& key);
    
    // Remove from local filter  
    void removeFilter(const std::string& key);
    
    // Async query
    void queryAsync(const std::string& key, ResultCallback cb);
    std::future<DataResult> queryFuture(const std::string& key);
    
    // Settings
    void setTimeout(int ms);
    bool isActive() const;
    std::string getError() const;

private:
    class Impl;
    std::unique_ptr<Impl> m;
};

// Helper functions
std::string normalize(const std::string& s);
bool isFiltered(const std::string& s);

} // namespace GameConfig

// C API
#ifdef __cplusplus
extern "C" {
#endif

void* gcfg_create(const char* url);
void gcfg_destroy(void* h);
int gcfg_init(void* h);
int gcfg_check(void* h, const char* key);
const char* gcfg_query(void* h, const char* key);
int gcfg_check_local(void* h, const char* key);
void gcfg_add(void* h, const char* key);
void gcfg_timeout(void* h, int ms);

#ifdef __cplusplus
}
#endif

#endif
