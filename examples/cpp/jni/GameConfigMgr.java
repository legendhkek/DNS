package com.game.config;

/**
 * Game Config Manager
 * Use this to filter network requests
 */
public class GameConfigMgr {
    
    private long handle;
    private boolean destroyed = false;
    
    public GameConfigMgr(String serverUrl) {
        handle = ConfigNative.create(serverUrl);
        if (handle == 0) {
            throw new RuntimeException("Failed to create config manager");
        }
    }
    
    public synchronized boolean init() {
        checkState();
        return ConfigNative.init(handle);
    }
    
    public synchronized boolean check(String key) {
        checkState();
        return ConfigNative.check(handle, key);
    }
    
    public synchronized String query(String key) {
        checkState();
        return ConfigNative.query(handle, key);
    }
    
    public synchronized boolean checkLocal(String key) {
        checkState();
        return ConfigNative.checkLocal(handle, key);
    }
    
    public synchronized void addFilter(String key) {
        checkState();
        ConfigNative.addFilter(handle, key);
    }
    
    public synchronized void setTimeout(int ms) {
        checkState();
        ConfigNative.setTimeout(handle, ms);
    }
    
    public synchronized boolean isActive() {
        checkState();
        return ConfigNative.isActive(handle);
    }
    
    public void checkAsync(String key, CheckCallback cb) {
        new Thread(() -> {
            boolean r = check(key);
            if (cb != null) cb.onResult(r);
        }).start();
    }
    
    public synchronized void destroy() {
        if (!destroyed && handle != 0) {
            ConfigNative.destroy(handle);
            handle = 0;
            destroyed = true;
        }
    }
    
    @Override
    protected void finalize() throws Throwable {
        destroy();
        super.finalize();
    }
    
    private void checkState() {
        if (destroyed) throw new IllegalStateException("Manager destroyed");
    }
    
    public interface CheckCallback {
        void onResult(boolean filtered);
    }
}
