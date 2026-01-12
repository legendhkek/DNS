package com.dnsblock.example;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.dnsblock.client.DnsBlockerClient;

import org.json.JSONObject;

/**
 * Example Android Activity showing DNS Blocker Client usage
 * 
 * Add to AndroidManifest.xml:
 *   <uses-permission android:name="android.permission.INTERNET" />
 */
public class MainActivity extends AppCompatActivity {
    
    private static final String TAG = "DnsBlockerExample";
    
    // CHANGE THESE VALUES
    private static final String SERVER_URL = "https://your-server.com/Dns.php";
    private static final String API_KEY = "your-api-key-here";
    
    private DnsBlockerClient dnsClient;
    private TextView statusText;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Simple layout with status text
        statusText = new TextView(this);
        statusText.setPadding(32, 32, 32, 32);
        statusText.setTextSize(14);
        setContentView(statusText);
        
        appendStatus("DNS Blocker Client Example\n");
        appendStatus("==========================\n\n");
        
        // Initialize client
        dnsClient = new DnsBlockerClient(SERVER_URL, API_KEY);
        
        // Connect and test
        connectAndTest();
    }
    
    private void connectAndTest() {
        appendStatus("Connecting to DNS Blocker API...\n");
        
        dnsClient.connect(new DnsBlockerClient.Callback() {
            @Override
            public void onSuccess(JSONObject response) {
                runOnUiThread(() -> {
                    try {
                        appendStatus("✓ Connected successfully!\n");
                        appendStatus("  Client IP: " + response.optString("client_ip") + "\n");
                        appendStatus("  Blocked domains: " + response.optInt("blocked_domains_count") + "\n\n");
                        
                        // Test some domains
                        testDomains();
                        
                    } catch (Exception e) {
                        appendStatus("Error: " + e.getMessage() + "\n");
                    }
                });
            }
            
            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    appendStatus("✗ Connection failed: " + error + "\n");
                    Toast.makeText(MainActivity.this, "Connection failed", Toast.LENGTH_SHORT).show();
                });
            }
        });
    }
    
    private void testDomains() {
        appendStatus("Testing domain resolution:\n");
        appendStatus("-------------------------\n");
        
        String[] testDomains = {
            "google.com",           // Should NOT be blocked
            "doubleclick.net",      // Should be blocked
            "github.com",           // Should NOT be blocked
            "admob.com",            // Should be blocked
        };
        
        for (String domain : testDomains) {
            testDomain(domain);
        }
    }
    
    private void testDomain(String domain) {
        dnsClient.resolve(domain, new DnsBlockerClient.ResolveCallback() {
            @Override
            public void onResolved(String resolvedDomain, String ip, boolean blocked) {
                runOnUiThread(() -> {
                    if (blocked) {
                        appendStatus("  [BLOCKED] " + resolvedDomain + " -> 0.0.0.0\n");
                    } else {
                        appendStatus("  [ALLOWED] " + resolvedDomain + " -> " + ip + "\n");
                    }
                });
            }
            
            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    appendStatus("  [ERROR] " + domain + ": " + error + "\n");
                });
            }
        });
    }
    
    private void appendStatus(String text) {
        statusText.append(text);
        Log.d(TAG, text);
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (dnsClient != null) {
            dnsClient.shutdown();
        }
    }
}
