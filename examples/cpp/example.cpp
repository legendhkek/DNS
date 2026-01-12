/**
 * DNS Blocker Client Example - C++
 * 
 * Compile:
 *   g++ -std=c++17 -o dns_example example.cpp DnsBlockerClient.cpp -lcurl
 * 
 * Run:
 *   ./dns_example
 */

#include <iostream>
#include <iomanip>
#include "DnsBlockerClient.hpp"

int main() {
    // Configuration - CHANGE THESE VALUES
    const std::string serverUrl = "https://your-server.com/Dns.php";
    const std::string apiKey = "your-api-key-here";
    
    std::cout << "=== DNS Blocker Client Example (C++) ===\n\n";
    
    // Create client
    DnsBlocker::Client client(serverUrl, apiKey);
    
    std::cout << "Connecting to DNS Blocker API...\n";
    
    // Connect
    auto connInfo = client.connect();
    if (!connInfo.success) {
        std::cerr << "Connection failed: " << connInfo.error << "\n";
        return 1;
    }
    
    std::cout << "Connected successfully!\n";
    std::cout << "  Client IP: " << connInfo.clientIp << "\n";
    std::cout << "  Blocked domains: " << connInfo.blockedDomainsCount << "\n\n";
    
    // Get status
    auto status = client.getStatus();
    std::cout << "Server Status:\n";
    std::cout << "  - Online: " << (status.online ? "Yes" : "No") << "\n";
    std::cout << "  - Version: " << status.version << "\n";
    std::cout << "  - Server time: " << status.serverTime << "\n\n";
    
    // Test domains
    std::vector<std::string> testDomains = {
        "google.com",            // Should NOT be blocked
        "doubleclick.net",       // Should be blocked (ad network)
        "github.com",            // Should NOT be blocked
        "googlesyndication.com", // Should be blocked (ads)
        "facebook.com",          // Should NOT be blocked
        "an.facebook.com",       // Should be blocked (FB ads)
    };
    
    std::cout << "Testing domain resolution:\n";
    std::cout << std::string(50, '-') << "\n";
    
    for (const auto& domain : testDomains) {
        auto result = client.resolve(domain);
        
        if (result.success) {
            if (result.blocked) {
                std::cout << "  [BLOCKED] " << std::setw(25) << std::left << domain 
                         << " -> 0.0.0.0 (ad/tracker)\n";
            } else {
                std::cout << "  [ALLOWED] " << std::setw(25) << std::left << domain 
                         << " -> " << (result.ip.empty() ? "N/A" : result.ip) << "\n";
            }
        } else {
            std::cout << "  [ERROR] " << domain << ": " << client.getLastError() << "\n";
        }
    }
    
    std::cout << "\n";
    
    // Bulk resolve example
    std::cout << "Bulk resolve example:\n";
    auto bulkResults = client.bulkResolve({"amazon.com", "adnxs.com", "microsoft.com"});
    for (const auto& [domain, result] : bulkResults) {
        std::cout << "  " << domain << ": " << (result.blocked ? "BLOCKED" : "allowed") << "\n";
    }
    
    std::cout << "\n";
    
    // Quick check
    std::cout << "Quick block check:\n";
    std::cout << "  ads.google.com: " << (client.isBlocked("ads.google.com") ? "BLOCKED" : "allowed") << "\n";
    std::cout << "  stackoverflow.com: " << (client.isBlocked("stackoverflow.com") ? "BLOCKED" : "allowed") << "\n";
    
    std::cout << "\nDone!\n";
    return 0;
}
