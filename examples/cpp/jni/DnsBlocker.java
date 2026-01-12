package com.dnsblocker.client;

import android.util.Log;
import org.json.JSONObject;

/**
 * DNS Blocker Client for Android
 * 
 * High-level Java wrapper around the native C++ library.
 * Blocks ads and trackers for your Android app.
 * 
 * Usage:
 *   DnsBlocker blocker = new DnsBlocker("https://your-server.com/Dns.php", "your-api-key");
 *   
 *   // Connect to API
 *   blocker.connectAsync(success -> {
 *       if (success) {
 *           Log.d("DNS", "Connected!");
 *       }
 *   });
 *   
 *   // Check if URL should be blocked (fast, synchronous)
 *   if (blocker.isBlocked("doubleclick.net")) {
 *       // Don't load this URL - it's an ad
 *   }
 *   
 *   // Or use async version
 *   blocker.isBlockedAsync("some-domain.com", blocked -> {
 *       if (blocked) {
 *           // Handle blocked domain
 *       }
 *   });
 */
public class DnsBlocker {
    
    private static final String TAG = "DnsBlocker";
    
    private long nativeHandle;
    private boolean destroyed = false;
    
    /**
     * Create DNS Blocker client
     * 
     * @param serverUrl Your DNS Blocker API server URL
     * @param apiKey Your API key for authentication
     */
    public DnsBlocker(String serverUrl, String apiKey) {
        nativeHandle = DnsBlockerNative.nativeCreate(serverUrl, apiKey);
        if (nativeHandle == 0) {
            throw new RuntimeException("Failed to create DNS Blocker client");
        }
    }
    
    /**
     * Connect to DNS Blocker API (synchronous)
     * 
     * @return true if connected successfully
     */
    public synchronized boolean connect() {
        checkDestroyed();
        return DnsBlockerNative.nativeConnect(nativeHandle);
    }
    
    /**
     * Connect to DNS Blocker API (asynchronous)
     */
    public void connectAsync(final ConnectCallback callback) {
        new Thread(() -> {
            boolean success = connect();
            if (callback != null) {
                callback.onResult(success);
            }
        }).start();
    }
    
    /**
     * Check if domain is blocked (fast local + remote check)
     * 
     * @param domain Domain to check
     * @return true if domain is an ad/tracker
     */
    public synchronized boolean isBlocked(String domain) {
        checkDestroyed();
        return DnsBlockerNative.nativeIsBlocked(nativeHandle, domain);
    }
    
    /**
     * Check if domain is blocked (asynchronous)
     */
    public void isBlockedAsync(final String domain, final BlockedCallback callback) {
        new Thread(() -> {
            boolean blocked = isBlocked(domain);
            if (callback != null) {
                callback.onResult(blocked);
            }
        }).start();
    }
    
    /**
     * Check if domain is in local blocklist (very fast, no network)
     * 
     * @param domain Domain to check
     * @return true if locally blocked
     */
    public synchronized boolean isLocallyBlocked(String domain) {
        checkDestroyed();
        return DnsBlockerNative.nativeIsLocallyBlocked(nativeHandle, domain);
    }
    
    /**
     * Resolve domain with ad blocking
     * 
     * @param domain Domain to resolve
     * @return ResolveResult with IP and blocked status
     */
    public synchronized ResolveResult resolve(String domain) {
        checkDestroyed();
        String json = DnsBlockerNative.nativeResolveJson(nativeHandle, domain);
        return ResolveResult.fromJson(json);
    }
    
    /**
     * Resolve domain (asynchronous)
     */
    public void resolveAsync(final String domain, final ResolveCallback callback) {
        new Thread(() -> {
            ResolveResult result = resolve(domain);
            if (callback != null) {
                callback.onResult(result);
            }
        }).start();
    }
    
    /**
     * Add domain to local blocklist (instant blocking, no network)
     */
    public synchronized void addLocalBlock(String domain) {
        checkDestroyed();
        DnsBlockerNative.nativeAddLocalBlock(nativeHandle, domain);
    }
    
    /**
     * Remove domain from local blocklist
     */
    public synchronized void removeLocalBlock(String domain) {
        checkDestroyed();
        DnsBlockerNative.nativeRemoveLocalBlock(nativeHandle, domain);
    }
    
    /**
     * Set connection timeout
     * 
     * @param timeoutMs Timeout in milliseconds
     */
    public synchronized void setTimeout(int timeoutMs) {
        checkDestroyed();
        DnsBlockerNative.nativeSetTimeout(nativeHandle, timeoutMs);
    }
    
    /**
     * Get last error message
     */
    public synchronized String getLastError() {
        checkDestroyed();
        return DnsBlockerNative.nativeGetError(nativeHandle);
    }
    
    /**
     * Check if connected to API
     */
    public synchronized boolean isConnected() {
        checkDestroyed();
        return DnsBlockerNative.nativeIsConnected(nativeHandle);
    }
    
    /**
     * Clear response cache
     */
    public synchronized void clearCache() {
        checkDestroyed();
        DnsBlockerNative.nativeClearCache(nativeHandle);
    }
    
    /**
     * Load blocklist from file
     * 
     * @param filepath Path to blocklist file (one domain per line)
     * @return true if loaded successfully
     */
    public synchronized boolean loadBlocklist(String filepath) {
        checkDestroyed();
        return DnsBlockerNative.nativeLoadBlocklist(nativeHandle, filepath);
    }
    
    /**
     * Get API status
     */
    public synchronized ApiStatus getStatus() {
        checkDestroyed();
        String json = DnsBlockerNative.nativeGetStatus(nativeHandle);
        return ApiStatus.fromJson(json);
    }
    
    /**
     * Destroy client and free resources
     */
    public synchronized void destroy() {
        if (!destroyed && nativeHandle != 0) {
            DnsBlockerNative.nativeDestroy(nativeHandle);
            nativeHandle = 0;
            destroyed = true;
        }
    }
    
    @Override
    protected void finalize() throws Throwable {
        destroy();
        super.finalize();
    }
    
    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("DnsBlocker has been destroyed");
        }
    }
    
    // ==================== Callbacks ====================
    
    public interface ConnectCallback {
        void onResult(boolean success);
    }
    
    public interface BlockedCallback {
        void onResult(boolean blocked);
    }
    
    public interface ResolveCallback {
        void onResult(ResolveResult result);
    }
    
    // ==================== Data Classes ====================
    
    public static class ResolveResult {
        public String domain;
        public String ip;
        public String ipv6;
        public boolean blocked;
        public boolean success;
        public int ttl;
        
        public static ResolveResult fromJson(String json) {
            ResolveResult result = new ResolveResult();
            try {
                JSONObject obj = new JSONObject(json);
                result.domain = obj.optString("domain", "");
                result.ip = obj.optString("ip", "");
                result.ipv6 = obj.optString("ipv6", "");
                result.blocked = obj.optBoolean("blocked", false);
                result.success = obj.optBoolean("success", false);
                result.ttl = obj.optInt("ttl", 300);
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse resolve result: " + e.getMessage());
            }
            return result;
        }
    }
    
    public static class ApiStatus {
        public boolean online;
        public String version;
        public int blockedDomainsCount;
        public String serverTime;
        
        public static ApiStatus fromJson(String json) {
            ApiStatus status = new ApiStatus();
            try {
                JSONObject obj = new JSONObject(json);
                status.online = obj.optBoolean("online", false);
                status.version = obj.optString("version", "");
                status.blockedDomainsCount = obj.optInt("blockedDomainsCount", 0);
                status.serverTime = obj.optString("serverTime", "");
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse API status: " + e.getMessage());
            }
            return status;
        }
    }
}
