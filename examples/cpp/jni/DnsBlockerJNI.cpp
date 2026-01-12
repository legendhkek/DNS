/**
 * JNI Wrapper for DNS Blocker Client
 * 
 * This file provides Java/Kotlin bindings for Android APK integration.
 * 
 * Build with Android NDK:
 *   ndk-build
 * 
 * Or with CMake:
 *   cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
 *         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 ..
 *   make
 */

#include <jni.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>

#include "../DnsBlockerClient.hpp"

// Store client instances
static std::unordered_map<jlong, std::unique_ptr<DnsBlocker::Client>> g_clients;
static std::mutex g_clientsMutex;
static jlong g_nextHandle = 1;

// Helper to get client from handle
static DnsBlocker::Client* getClient(jlong handle) {
    std::lock_guard<std::mutex> lock(g_clientsMutex);
    auto it = g_clients.find(handle);
    return (it != g_clients.end()) ? it->second.get() : nullptr;
}

// Helper to convert jstring to std::string
static std::string jstringToString(JNIEnv* env, jstring jstr) {
    if (!jstr) return "";
    const char* chars = env->GetStringUTFChars(jstr, nullptr);
    std::string result(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

// Helper to create jstring from std::string
static jstring stringToJstring(JNIEnv* env, const std::string& str) {
    return env->NewStringUTF(str.c_str());
}

extern "C" {

// Package: com.dnsblocker.client
// Class: DnsBlockerNative

/**
 * Create a new DNS Blocker client
 * 
 * @param serverUrl API server URL
 * @param apiKey API key for authentication
 * @return Native handle (0 on failure)
 */
JNIEXPORT jlong JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeCreate(
    JNIEnv* env,
    jclass clazz,
    jstring serverUrl,
    jstring apiKey
) {
    std::string url = jstringToString(env, serverUrl);
    std::string key = jstringToString(env, apiKey);
    
    if (url.empty() || key.empty()) {
        return 0;
    }
    
    try {
        auto client = std::make_unique<DnsBlocker::Client>(url, key);
        
        std::lock_guard<std::mutex> lock(g_clientsMutex);
        jlong handle = g_nextHandle++;
        g_clients[handle] = std::move(client);
        return handle;
    } catch (...) {
        return 0;
    }
}

/**
 * Destroy a DNS Blocker client
 */
JNIEXPORT void JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeDestroy(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    std::lock_guard<std::mutex> lock(g_clientsMutex);
    g_clients.erase(handle);
}

/**
 * Connect to DNS Blocker API
 * 
 * @return true on success
 */
JNIEXPORT jboolean JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeConnect(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    auto* client = getClient(handle);
    if (!client) return JNI_FALSE;
    
    auto info = client->connect();
    return info.success ? JNI_TRUE : JNI_FALSE;
}

/**
 * Check if domain is blocked
 * 
 * @param domain Domain to check
 * @return true if blocked
 */
JNIEXPORT jboolean JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeIsBlocked(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring domain
) {
    auto* client = getClient(handle);
    if (!client) return JNI_FALSE;
    
    std::string domainStr = jstringToString(env, domain);
    return client->isBlocked(domainStr) ? JNI_TRUE : JNI_FALSE;
}

/**
 * Resolve domain with ad blocking
 * 
 * @param domain Domain to resolve
 * @return IP address (0.0.0.0 if blocked, empty on error)
 */
JNIEXPORT jstring JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeResolve(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring domain
) {
    auto* client = getClient(handle);
    if (!client) return stringToJstring(env, "");
    
    std::string domainStr = jstringToString(env, domain);
    auto result = client->resolve(domainStr);
    
    if (result.blocked) {
        return stringToJstring(env, "0.0.0.0");
    }
    return stringToJstring(env, result.ipv4);
}

/**
 * Get resolve result as JSON
 */
JNIEXPORT jstring JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeResolveJson(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring domain
) {
    auto* client = getClient(handle);
    if (!client) return stringToJstring(env, "{}");
    
    std::string domainStr = jstringToString(env, domain);
    auto result = client->resolve(domainStr);
    
    // Build JSON response
    std::ostringstream json;
    json << "{";
    json << "\"domain\":\"" << result.domain << "\",";
    json << "\"ip\":\"" << result.ipv4 << "\",";
    json << "\"ipv6\":\"" << result.ipv6 << "\",";
    json << "\"blocked\":" << (result.blocked ? "true" : "false") << ",";
    json << "\"success\":" << (result.success ? "true" : "false") << ",";
    json << "\"ttl\":" << result.ttl;
    json << "}";
    
    return stringToJstring(env, json.str());
}

/**
 * Check if locally blocked (fast, no network)
 */
JNIEXPORT jboolean JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeIsLocallyBlocked(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring domain
) {
    auto* client = getClient(handle);
    if (!client) return JNI_FALSE;
    
    std::string domainStr = jstringToString(env, domain);
    return client->isLocallyBlocked(domainStr) ? JNI_TRUE : JNI_FALSE;
}

/**
 * Add domain to local blocklist
 */
JNIEXPORT void JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeAddLocalBlock(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring domain
) {
    auto* client = getClient(handle);
    if (!client) return;
    
    std::string domainStr = jstringToString(env, domain);
    client->addLocalBlock(domainStr);
}

/**
 * Remove domain from local blocklist
 */
JNIEXPORT void JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeRemoveLocalBlock(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring domain
) {
    auto* client = getClient(handle);
    if (!client) return;
    
    std::string domainStr = jstringToString(env, domain);
    client->removeLocalBlock(domainStr);
}

/**
 * Set connection timeout
 */
JNIEXPORT void JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeSetTimeout(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jint timeoutMs
) {
    auto* client = getClient(handle);
    if (!client) return;
    client->setTimeout(timeoutMs);
}

/**
 * Get last error message
 */
JNIEXPORT jstring JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeGetError(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    auto* client = getClient(handle);
    if (!client) return stringToJstring(env, "Invalid client handle");
    return stringToJstring(env, client->getLastError());
}

/**
 * Check if connected
 */
JNIEXPORT jboolean JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeIsConnected(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    auto* client = getClient(handle);
    if (!client) return JNI_FALSE;
    return client->isConnected() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Clear cache
 */
JNIEXPORT void JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeClearCache(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    auto* client = getClient(handle);
    if (!client) return;
    client->clearCache();
}

/**
 * Load blocklist from file
 */
JNIEXPORT jboolean JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeLoadBlocklist(
    JNIEnv* env,
    jclass clazz,
    jlong handle,
    jstring filepath
) {
    auto* client = getClient(handle);
    if (!client) return JNI_FALSE;
    
    std::string path = jstringToString(env, filepath);
    return client->loadLocalBlocklist(path) ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get API status as JSON
 */
JNIEXPORT jstring JNICALL
Java_com_dnsblocker_client_DnsBlockerNative_nativeGetStatus(
    JNIEnv* env,
    jclass clazz,
    jlong handle
) {
    auto* client = getClient(handle);
    if (!client) return stringToJstring(env, "{}");
    
    auto status = client->getStatus();
    
    std::ostringstream json;
    json << "{";
    json << "\"online\":" << (status.online ? "true" : "false") << ",";
    json << "\"version\":\"" << status.version << "\",";
    json << "\"blockedDomainsCount\":" << status.blockedDomainsCount << ",";
    json << "\"serverTime\":\"" << status.serverTime << "\"";
    json << "}";
    
    return stringToJstring(env, json.str());
}

} // extern "C"
