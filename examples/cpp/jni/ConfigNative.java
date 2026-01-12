package com.game.config;

/**
 * Native config module
 */
public class ConfigNative {
    
    static {
        System.loadLibrary("gameconfig");
    }
    
    public static native long create(String url);
    public static native void destroy(long h);
    public static native boolean init(long h);
    public static native boolean check(long h, String key);
    public static native String query(long h, String key);
    public static native boolean checkLocal(long h, String key);
    public static native void addFilter(long h, String key);
    public static native void setTimeout(long h, int ms);
    public static native boolean isActive(long h);
}
