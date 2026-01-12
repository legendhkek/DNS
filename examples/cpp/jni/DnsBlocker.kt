package com.dnsblocker.client

import android.util.Log
import kotlinx.coroutines.*
import org.json.JSONObject

/**
 * DNS Blocker Client for Android (Kotlin)
 * 
 * Modern Kotlin wrapper with coroutine support for ad blocking.
 * 
 * Usage:
 * ```kotlin
 * val blocker = DnsBlockerKt("https://your-server.com/Dns.php", "your-api-key")
 * 
 * // Connect (suspend function)
 * lifecycleScope.launch {
 *     if (blocker.connect()) {
 *         Log.d("DNS", "Connected!")
 *     }
 * }
 * 
 * // Check if URL should be blocked (fast, synchronous)
 * if (blocker.isBlocked("doubleclick.net")) {
 *     // Don't load this URL - it's an ad
 * }
 * 
 * // Or use coroutines
 * lifecycleScope.launch {
 *     val result = blocker.resolveAsync("some-domain.com")
 *     if (result.blocked) {
 *         // Handle blocked domain
 *     }
 * }
 * ```
 */
class DnsBlockerKt(
    serverUrl: String,
    apiKey: String
) {
    companion object {
        private const val TAG = "DnsBlocker"
        
        init {
            System.loadLibrary("dnsblocker")
        }
    }
    
    private var nativeHandle: Long = 0
    private var destroyed = false
    
    init {
        nativeHandle = DnsBlockerNative.nativeCreate(serverUrl, apiKey)
        if (nativeHandle == 0L) {
            throw RuntimeException("Failed to create DNS Blocker client")
        }
    }
    
    /**
     * Connect to DNS Blocker API
     */
    @Synchronized
    fun connect(): Boolean {
        checkDestroyed()
        return DnsBlockerNative.nativeConnect(nativeHandle)
    }
    
    /**
     * Connect to DNS Blocker API (coroutine)
     */
    suspend fun connectAsync(): Boolean = withContext(Dispatchers.IO) {
        connect()
    }
    
    /**
     * Check if domain is blocked (fast local + remote check)
     */
    @Synchronized
    fun isBlocked(domain: String): Boolean {
        checkDestroyed()
        return DnsBlockerNative.nativeIsBlocked(nativeHandle, domain)
    }
    
    /**
     * Check if domain is blocked (coroutine)
     */
    suspend fun isBlockedAsync(domain: String): Boolean = withContext(Dispatchers.IO) {
        isBlocked(domain)
    }
    
    /**
     * Check if domain is in local blocklist (very fast, no network)
     */
    @Synchronized
    fun isLocallyBlocked(domain: String): Boolean {
        checkDestroyed()
        return DnsBlockerNative.nativeIsLocallyBlocked(nativeHandle, domain)
    }
    
    /**
     * Resolve domain with ad blocking
     */
    @Synchronized
    fun resolve(domain: String): ResolveResult {
        checkDestroyed()
        val json = DnsBlockerNative.nativeResolveJson(nativeHandle, domain)
        return ResolveResult.fromJson(json)
    }
    
    /**
     * Resolve domain (coroutine)
     */
    suspend fun resolveAsync(domain: String): ResolveResult = withContext(Dispatchers.IO) {
        resolve(domain)
    }
    
    /**
     * Add domain to local blocklist (instant blocking, no network)
     */
    @Synchronized
    fun addLocalBlock(domain: String) {
        checkDestroyed()
        DnsBlockerNative.nativeAddLocalBlock(nativeHandle, domain)
    }
    
    /**
     * Remove domain from local blocklist
     */
    @Synchronized
    fun removeLocalBlock(domain: String) {
        checkDestroyed()
        DnsBlockerNative.nativeRemoveLocalBlock(nativeHandle, domain)
    }
    
    /**
     * Set connection timeout
     */
    @Synchronized
    fun setTimeout(timeoutMs: Int) {
        checkDestroyed()
        DnsBlockerNative.nativeSetTimeout(nativeHandle, timeoutMs)
    }
    
    /**
     * Get last error message
     */
    @Synchronized
    fun getLastError(): String {
        checkDestroyed()
        return DnsBlockerNative.nativeGetError(nativeHandle)
    }
    
    /**
     * Check if connected to API
     */
    @Synchronized
    fun isConnected(): Boolean {
        checkDestroyed()
        return DnsBlockerNative.nativeIsConnected(nativeHandle)
    }
    
    /**
     * Clear response cache
     */
    @Synchronized
    fun clearCache() {
        checkDestroyed()
        DnsBlockerNative.nativeClearCache(nativeHandle)
    }
    
    /**
     * Load blocklist from file
     */
    @Synchronized
    fun loadBlocklist(filepath: String): Boolean {
        checkDestroyed()
        return DnsBlockerNative.nativeLoadBlocklist(nativeHandle, filepath)
    }
    
    /**
     * Get API status
     */
    @Synchronized
    fun getStatus(): ApiStatus {
        checkDestroyed()
        val json = DnsBlockerNative.nativeGetStatus(nativeHandle)
        return ApiStatus.fromJson(json)
    }
    
    /**
     * Get API status (coroutine)
     */
    suspend fun getStatusAsync(): ApiStatus = withContext(Dispatchers.IO) {
        getStatus()
    }
    
    /**
     * Destroy client and free resources
     */
    @Synchronized
    fun destroy() {
        if (!destroyed && nativeHandle != 0L) {
            DnsBlockerNative.nativeDestroy(nativeHandle)
            nativeHandle = 0
            destroyed = true
        }
    }
    
    protected fun finalize() {
        destroy()
    }
    
    private fun checkDestroyed() {
        if (destroyed) {
            throw IllegalStateException("DnsBlocker has been destroyed")
        }
    }
    
    // ==================== Data Classes ====================
    
    data class ResolveResult(
        val domain: String = "",
        val ip: String = "",
        val ipv6: String = "",
        val blocked: Boolean = false,
        val success: Boolean = false,
        val ttl: Int = 300
    ) {
        companion object {
            fun fromJson(json: String): ResolveResult {
                return try {
                    val obj = JSONObject(json)
                    ResolveResult(
                        domain = obj.optString("domain", ""),
                        ip = obj.optString("ip", ""),
                        ipv6 = obj.optString("ipv6", ""),
                        blocked = obj.optBoolean("blocked", false),
                        success = obj.optBoolean("success", false),
                        ttl = obj.optInt("ttl", 300)
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse resolve result: ${e.message}")
                    ResolveResult()
                }
            }
        }
    }
    
    data class ApiStatus(
        val online: Boolean = false,
        val version: String = "",
        val blockedDomainsCount: Int = 0,
        val serverTime: String = ""
    ) {
        companion object {
            fun fromJson(json: String): ApiStatus {
                return try {
                    val obj = JSONObject(json)
                    ApiStatus(
                        online = obj.optBoolean("online", false),
                        version = obj.optString("version", ""),
                        blockedDomainsCount = obj.optInt("blockedDomainsCount", 0),
                        serverTime = obj.optString("serverTime", "")
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse API status: ${e.message}")
                    ApiStatus()
                }
            }
        }
    }
}

/**
 * Extension function for WebView ad blocking
 */
fun android.webkit.WebView.enableAdBlocking(blocker: DnsBlockerKt) {
    webViewClient = object : android.webkit.WebViewClient() {
        override fun shouldInterceptRequest(
            view: android.webkit.WebView?,
            request: android.webkit.WebResourceRequest?
        ): android.webkit.WebResourceResponse? {
            val url = request?.url?.host ?: return null
            
            if (blocker.isLocallyBlocked(url)) {
                // Return empty response for blocked domains
                return android.webkit.WebResourceResponse(
                    "text/plain",
                    "UTF-8",
                    null
                )
            }
            
            return super.shouldInterceptRequest(view, request)
        }
    }
}
