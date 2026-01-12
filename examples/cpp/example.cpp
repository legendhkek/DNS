/**
 * Example usage
 * 
 * Build:
 *   g++ -std=c++17 -DNO_SSL -o test example.cpp DnsBlockerClient.cpp -pthread
 * 
 * With SSL:
 *   g++ -std=c++17 -o test example.cpp DnsBlockerClient.cpp -lssl -lcrypto -pthread
 */

#include <iostream>
#include "DnsBlockerClient.hpp"

int main() {
    // Your server URL
    std::string url = "https://your-server.com/Dns.php";
    
    // Create manager
    GameConfig::ConfigMgr mgr(url);
    
    // Init (connect to server)
    if (mgr.init()) {
        std::cout << "Connected\n";
    }
    
    // Test domains
    const char* tests[] = {
        "google.com",
        "doubleclick.net",
        "github.com", 
        "admob.com",
        "facebook.com",
        nullptr
    };
    
    for (int i = 0; tests[i]; i++) {
        // Fast local check (no network)
        if (mgr.checkLocal(tests[i])) {
            std::cout << tests[i] << " -> FILTERED (local)\n";
            continue;
        }
        
        // Full check
        auto r = mgr.query(tests[i]);
        if (r.status == 1) {
            std::cout << tests[i] << " -> FILTERED\n";
        } else {
            std::cout << tests[i] << " -> " << r.value << "\n";
        }
    }
    
    // Add custom filter
    mgr.addFilter("custom-ads.com");
    std::cout << "custom-ads.com filtered: " << (mgr.checkLocal("custom-ads.com") ? "yes" : "no") << "\n";
    
    return 0;
}
