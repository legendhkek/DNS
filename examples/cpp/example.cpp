/**
 * DNS Blocker Client Example - C++17
 * 
 * Build:
 *   mkdir build && cd build
 *   cmake ..
 *   make
 *   ./dns_example
 * 
 * Or manually:
 *   g++ -std=c++17 -o dns_example example.cpp DnsBlockerClient.cpp -lssl -lcrypto -pthread
 *   
 * Without SSL:
 *   g++ -std=c++17 -DDNS_BLOCKER_NO_SSL -o dns_example example.cpp DnsBlockerClient.cpp -pthread
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include "DnsBlockerClient.hpp"

using namespace DnsBlocker;

void printHeader(const std::string& title) {
    std::cout << "\n" << std::string(50, '=') << "\n";
    std::cout << " " << title << "\n";
    std::cout << std::string(50, '=') << "\n\n";
}

void printResult(const std::string& domain, const ResolveResult& result) {
    std::cout << std::setw(30) << std::left << domain << " -> ";
    if (result.blocked) {
        std::cout << "\033[31m[BLOCKED]\033[0m " << result.ipv4;
        if (!result.reason.empty()) {
            std::cout << " (" << result.reason << ")";
        }
    } else if (result.success) {
        std::cout << "\033[32m[ALLOWED]\033[0m " << result.ipv4;
    } else {
        std::cout << "\033[33m[ERROR]\033[0m";
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    // Configuration - CHANGE THESE VALUES
    std::string serverUrl = "https://your-server.com/Dns.php";
    std::string apiKey = "your-api-key-here";
    
    // Allow command line override
    if (argc >= 3) {
        serverUrl = argv[1];
        apiKey = argv[2];
    }
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════╗\n";
    std::cout << "║         DNS Blocker Client v" << VERSION << "              ║\n";
    std::cout << "║       Ad Blocking Made Simple                    ║\n";
    std::cout << "╚══════════════════════════════════════════════════╝\n";
    
    // Create client
    ClientConfig config;
    config.serverUrl = serverUrl;
    config.apiKey = apiKey;
    config.timeoutMs = 10000;
    config.enableCache = true;
    config.cacheTtlSeconds = 300;
    
    Client client(config);
    
    // ==================== Local Blocking (Fast, No Network) ====================
    
    printHeader("Local Blocking (Instant, No Network)");
    
    std::vector<std::string> localTestDomains = {
        "doubleclick.net",
        "googlesyndication.com",
        "google.com",
        "admob.com",
        "github.com",
        "facebook-ads.example.com"
    };
    
    std::cout << "Testing local blocklist (built-in ad domains):\n\n";
    
    for (const auto& domain : localTestDomains) {
        bool blocked = client.isLocallyBlocked(domain);
        std::cout << std::setw(30) << std::left << domain << " -> ";
        if (blocked) {
            std::cout << "\033[31m[BLOCKED]\033[0m (local)\n";
        } else {
            std::cout << "\033[32m[ALLOWED]\033[0m\n";
        }
    }
    
    // Add custom domain to local blocklist
    std::cout << "\nAdding 'custom-ads.example.com' to local blocklist...\n";
    client.addLocalBlock("custom-ads.example.com");
    
    std::cout << "Is 'custom-ads.example.com' blocked? " 
              << (client.isLocallyBlocked("custom-ads.example.com") ? "Yes" : "No") << "\n";
    
    // ==================== API Connection ====================
    
    printHeader("Connecting to API");
    
    std::cout << "Server: " << serverUrl << "\n";
    std::cout << "Connecting...\n\n";
    
    auto connInfo = client.connect();
    
    if (connInfo.success) {
        std::cout << "\033[32m✓ Connected successfully!\033[0m\n\n";
        std::cout << "  Client IP:       " << connInfo.clientIp << "\n";
        std::cout << "  Server time:     " << connInfo.serverTime << "\n";
        std::cout << "  Blocked domains: " << connInfo.blockedDomainsCount << "\n";
        std::cout << "  Message:         " << connInfo.message << "\n";
    } else {
        std::cout << "\033[33m⚠ Connection failed: " << connInfo.error << "\033[0m\n";
        std::cout << "\nContinuing with local blocking only...\n";
    }
    
    // ==================== Remote Resolution ====================
    
    if (client.isConnected()) {
        printHeader("Remote DNS Resolution with Ad Blocking");
        
        std::vector<std::string> testDomains = {
            "google.com",
            "doubleclick.net",
            "github.com",
            "googlesyndication.com",
            "stackoverflow.com",
            "admob.com",
            "microsoft.com",
            "ads.google.com",
            "amazon.com",
            "taboola.com"
        };
        
        for (const auto& domain : testDomains) {
            auto result = client.resolve(domain);
            printResult(domain, result);
        }
        
        // ==================== Bulk Resolution ====================
        
        printHeader("Bulk Resolution");
        
        std::vector<std::string> bulkDomains = {
            "apple.com", "facebook.com", "an.facebook.com",
            "twitter.com", "analytics.twitter.com"
        };
        
        std::cout << "Resolving " << bulkDomains.size() << " domains in one request...\n\n";
        
        auto bulkResults = client.bulkResolve(bulkDomains);
        for (const auto& [domain, result] : bulkResults) {
            printResult(domain, result);
        }
        
        // ==================== API Status ====================
        
        printHeader("API Status");
        
        auto status = client.getStatus();
        std::cout << "  Online:          " << (status.online ? "Yes" : "No") << "\n";
        std::cout << "  Version:         " << status.version << "\n";
        std::cout << "  Blocked domains: " << status.blockedDomainsCount << "\n";
        std::cout << "  Server time:     " << status.serverTime << "\n";
        std::cout << "  Uptime:          " << status.uptime << "\n";
    }
    
    // ==================== Async Example ====================
    
    printHeader("Async Resolution Example");
    
    std::cout << "Resolving 'example.com' asynchronously...\n";
    
    auto future = client.resolveAsync("example.com");
    
    std::cout << "Doing other work while waiting...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    auto asyncResult = future.get();
    std::cout << "Async result: ";
    printResult("example.com", asyncResult);
    
    // ==================== Performance Test ====================
    
    printHeader("Performance Test");
    
    const int iterations = 1000;
    std::cout << "Testing " << iterations << " local block checks...\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        client.isLocallyBlocked("doubleclick.net");
        client.isLocallyBlocked("google.com");
        client.isLocallyBlocked("random-domain.com");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "  Total time:    " << duration.count() << " μs\n";
    std::cout << "  Per check:     " << (duration.count() / (iterations * 3.0)) << " μs\n";
    std::cout << "  Checks/second: " << (iterations * 3 * 1000000.0 / duration.count()) << "\n";
    
    // ==================== Summary ====================
    
    printHeader("Summary");
    
    std::cout << "DNS Blocker provides:\n\n";
    std::cout << "  ✓ Fast local blocking (no network latency)\n";
    std::cout << "  ✓ Remote API for comprehensive ad blocking\n";
    std::cout << "  ✓ Response caching for performance\n";
    std::cout << "  ✓ Async operations for non-blocking usage\n";
    std::cout << "  ✓ Thread-safe design\n";
    std::cout << "  ✓ Easy integration via JNI for Android\n";
    
    std::cout << "\nDone!\n\n";
    
    return 0;
}
