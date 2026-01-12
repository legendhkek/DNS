package com.dnsblocker.client;

/**
 * Native JNI bindings for DNS Blocker Client
 * 
 * Usage:
 *   DnsBlocker blocker = new DnsBlocker("https://your-server.com/Dns.php", "your-api-key");
 *   
 *   if (blocker.connect()) {
 *       if (blocker.isBlocked("doubleclick.net")) {
 *           // Block the ad request
 *       }
 *   }
 */
public class DnsBlockerNative {
    
    static {
        System.loadLibrary("dnsblocker");
    }
    
    // Native methods
    private static native long nativeCreate(String serverUrl, String apiKey);
    private static native void nativeDestroy(long handle);
    private static native boolean nativeConnect(long handle);
    private static native boolean nativeIsBlocked(long handle, String domain);
    private static native String nativeResolve(long handle, String domain);
    private static native String nativeResolveJson(long handle, String domain);
    private static native boolean nativeIsLocallyBlocked(long handle, String domain);
    private static native void nativeAddLocalBlock(long handle, String domain);
    private static native void nativeRemoveLocalBlock(long handle, String domain);
    private static native void nativeSetTimeout(long handle, int timeoutMs);
    private static native String nativeGetError(long handle);
    private static native boolean nativeIsConnected(long handle);
    private static native void nativeClearCache(long handle);
    private static native boolean nativeLoadBlocklist(long handle, String filepath);
    private static native String nativeGetStatus(long handle);
}
