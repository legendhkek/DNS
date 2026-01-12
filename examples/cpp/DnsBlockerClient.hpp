/**
 * DNS Blocker API Client for C++
 * 
 * Modern C++ wrapper for the DNS Blocker API
 * 
 * Dependencies: libcurl
 * Compile: g++ -std=c++17 -o myapp main.cpp DnsBlockerClient.cpp -lcurl
 * 
 * Usage:
 *   DnsBlockerClient client("https://your-server.com/Dns.php", "your-api-key");
 *   
 *   if (client.connect()) {
 *       auto result = client.resolve("doubleclick.net");
 *       if (result.blocked) {
 *           std::cout << "Ad blocked!" << std::endl;
 *       }
 *   }
 */

#ifndef DNS_BLOCKER_CLIENT_HPP
#define DNS_BLOCKER_CLIENT_HPP

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <optional>

namespace DnsBlocker {

// DNS Resolution result
struct ResolveResult {
    std::string domain;
    std::string ip;
    std::string ipv6;
    bool blocked = false;
    bool success = false;
    int ttl = 300;
    std::string reason;
};

// API Status
struct ApiStatus {
    bool online = false;
    std::string version;
    int blockedDomainsCount = 0;
    std::string serverTime;
};

// Connection info
struct ConnectionInfo {
    bool success = false;
    std::string clientIp;
    int serverTime = 0;
    int blockedDomainsCount = 0;
    std::string message;
    std::string error;
};

/**
 * DNS Blocker API Client
 */
class Client {
public:
    /**
     * Constructor
     * @param serverUrl API server URL
     * @param apiKey Your API key
     */
    Client(const std::string& serverUrl, const std::string& apiKey);
    
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
    
    /**
     * Connect to DNS Blocker API
     * @return Connection info
     */
    ConnectionInfo connect();
    
    /**
     * Resolve a domain with ad blocking
     * @param domain Domain to resolve
     * @return Resolution result
     */
    ResolveResult resolve(const std::string& domain);
    
    /**
     * Check if a domain is blocked
     * @param domain Domain to check
     * @return true if blocked
     */
    bool isBlocked(const std::string& domain);
    
    /**
     * Resolve multiple domains at once
     * @param domains Vector of domains
     * @return Map of domain -> result
     */
    std::map<std::string, ResolveResult> bulkResolve(const std::vector<std::string>& domains);
    
    /**
     * Get API status
     * @return API status
     */
    ApiStatus getStatus();
    
    /**
     * Get blocklist
     * @return Vector of blocked domains
     */
    std::vector<std::string> getBlocklist();
    
    /**
     * Add domains to blocklist
     * @param domains Domains to add
     * @return true on success
     */
    bool addToBlocklist(const std::vector<std::string>& domains);
    
    /**
     * Remove domains from blocklist
     * @param domains Domains to remove
     * @return true on success
     */
    bool removeFromBlocklist(const std::vector<std::string>& domains);
    
    /**
     * Set connection timeout
     * @param timeoutMs Timeout in milliseconds
     */
    void setTimeout(int timeoutMs);
    
    /**
     * Get last error message
     * @return Error message
     */
    std::string getLastError() const;
    
    /**
     * Check if connected
     * @return true if connected
     */
    bool isConnected() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace DnsBlocker

#endif // DNS_BLOCKER_CLIENT_HPP
