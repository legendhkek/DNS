package com.dnsblock.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * DNS Blocker API Client for Android
 * 
 * Usage:
 *   DnsBlockerClient client = new DnsBlockerClient("https://your-server.com/Dns.php", "your-api-key");
 *   client.connect(new DnsBlockerClient.Callback() {
 *       @Override
 *       public void onSuccess(JSONObject response) {
 *           // Connected successfully
 *       }
 *       @Override
 *       public void onError(String error) {
 *           // Handle error
 *       }
 *   });
 */
public class DnsBlockerClient {
    
    private static final String TAG = "DnsBlockerClient";
    private static final int TIMEOUT = 10000; // 10 seconds
    
    private String serverUrl;
    private String apiKey;
    private boolean isConnected = false;
    private ExecutorService executor;
    
    public interface Callback {
        void onSuccess(JSONObject response);
        void onError(String error);
    }
    
    public interface ResolveCallback {
        void onResolved(String domain, String ip, boolean blocked);
        void onError(String error);
    }
    
    /**
     * Initialize DNS Blocker Client
     * @param serverUrl Your DNS Blocker API server URL (e.g., "https://example.com/Dns.php")
     * @param apiKey Your API key for authentication
     */
    public DnsBlockerClient(String serverUrl, String apiKey) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.apiKey = apiKey;
        this.executor = Executors.newCachedThreadPool();
    }
    
    /**
     * Connect to DNS Blocker API
     */
    public void connect(final Callback callback) {
        executor.execute(() -> {
            try {
                JSONObject response = makeRequest("/connect", "GET", null);
                if (response.optBoolean("success", false)) {
                    isConnected = true;
                    callback.onSuccess(response);
                } else {
                    callback.onError(response.optString("error", "Connection failed"));
                }
            } catch (Exception e) {
                callback.onError("Connection error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Check if a domain should be blocked (ad/tracker)
     */
    public void checkDomain(final String domain, final ResolveCallback callback) {
        executor.execute(() -> {
            try {
                JSONObject response = makeRequest("/check?domain=" + domain, "GET", null);
                if (response.optBoolean("success", false)) {
                    boolean blocked = response.optBoolean("blocked", false);
                    callback.onResolved(domain, blocked ? "0.0.0.0" : "", blocked);
                } else {
                    callback.onError(response.optString("error", "Check failed"));
                }
            } catch (Exception e) {
                callback.onError("Error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Resolve a domain with ad blocking
     */
    public void resolve(final String domain, final ResolveCallback callback) {
        executor.execute(() -> {
            try {
                JSONObject response = makeRequest("/resolve?domain=" + domain, "GET", null);
                if (response.optBoolean("success", false)) {
                    boolean blocked = response.optBoolean("blocked", false);
                    String ip = response.optString("ip", "");
                    callback.onResolved(domain, ip, blocked);
                } else {
                    callback.onError(response.optString("error", "Resolve failed"));
                }
            } catch (Exception e) {
                callback.onError("Error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Resolve multiple domains at once
     */
    public void bulkResolve(final String[] domains, final Callback callback) {
        executor.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                JSONArray domainsArray = new JSONArray();
                for (String domain : domains) {
                    domainsArray.put(domain);
                }
                body.put("domains", domainsArray);
                
                JSONObject response = makeRequest("/bulk-resolve", "POST", body.toString());
                callback.onSuccess(response);
            } catch (Exception e) {
                callback.onError("Error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Get blocklist
     */
    public void getBlocklist(final Callback callback) {
        executor.execute(() -> {
            try {
                JSONObject response = makeRequest("/blocklist", "GET", null);
                callback.onSuccess(response);
            } catch (Exception e) {
                callback.onError("Error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Check API status
     */
    public void checkStatus(final Callback callback) {
        executor.execute(() -> {
            try {
                JSONObject response = makeRequest("/status", "GET", null);
                callback.onSuccess(response);
            } catch (Exception e) {
                callback.onError("Error: " + e.getMessage());
            }
        });
    }
    
    /**
     * Make HTTP request to API
     */
    private JSONObject makeRequest(String endpoint, String method, String body) throws Exception {
        URL url = new URL(serverUrl + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod(method);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("X-API-Key", apiKey);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            
            if (body != null && !body.isEmpty()) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    byte[] input = body.getBytes("utf-8");
                    os.write(input, 0, input.length);
                }
            }
            
            int responseCode = conn.getResponseCode();
            BufferedReader reader;
            
            if (responseCode >= 200 && responseCode < 300) {
                reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
            } else {
                reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "utf-8"));
            }
            
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
            return new JSONObject(response.toString());
            
        } finally {
            conn.disconnect();
        }
    }
    
    /**
     * Check if connected to API
     */
    public boolean isConnected() {
        return isConnected;
    }
    
    /**
     * Shutdown the client
     */
    public void shutdown() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
        }
    }
}
