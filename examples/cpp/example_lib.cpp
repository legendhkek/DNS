// Example: How to use Protect.h in your libbgmi.so source
// Compile: ndk-build or clang++ -shared -fPIC -o libbgmi.so example_lib.cpp

#include "Protect.h"
#include "GameConfig.h"  // DNS blocking
#include <android/log.h>

// ============ SET YOUR API URL HERE ============
#define MY_API "http://your-server.com/api.php"

// Auto-initialize when library loads
PROTECT_INIT(MY_API)

// ============ YOUR FUNCTIONS ============

// BGMI cannot see this function name or its strings
PROTECTED void my_secret_function() {
    // Anti-debug check
    CHECK_DEBUG();
    
    // These strings are ENCRYPTED in the binary
    // BGMI scanning cannot find them
    const char* msg = CSTR("This string is hidden from BGMI");
    const char* url = CSTR("http://my-server.com/data");
    
    __android_log_print(ANDROID_LOG_INFO, CSTR("MyMod"), "%s", msg);
}

// Hidden memory hack function
PROTECTED void modify_memory(void* addr, int value) {
    CHECK_DEBUG();
    
    // Unprotect memory
    _p::_m0(addr, sizeof(int));
    
    // Write value
    *(int*)addr = value;
}

// Hidden hook function
PROTECTED void* my_hook(void* original) {
    CHECK_DEBUG_EXIT();
    
    // Your hook code here
    return original;
}

// Block game telemetry
PROTECTED bool block_analytics(const char* url) {
    // Uses your API to check if URL should be blocked
    return API_BLOCK(url);
}

// ============ EXPORTED FUNCTIONS ============
// Only export what you need - use obfuscated names

extern "C" {
    // Exported with hidden name
    __attribute__((visibility("default")))
    void _x0() {
        my_secret_function();
    }
    
    // Memory function with obfuscated export
    __attribute__((visibility("default")))
    void _m(void* a, int v) {
        modify_memory(a, v);
    }
    
    // JNI entry point (if using JNI)
    __attribute__((visibility("default")))
    jint JNI_OnLoad(JavaVM* vm, void* reserved) {
        // Check for debugger first
        if (_p::_c0()) return -1;
        
        // Initialize API connection
        _api::Init(OBF(MY_API));
        
        // Hide from /proc/self/maps
        _p::_h0();
        
        return JNI_VERSION_1_6;
    }
}

// ============ AUTO CONSTRUCTOR ============
// Runs when .so is loaded

__attribute__((constructor))
static void on_load() {
    // Check debug
    if (_p::_c0()) {
        _exit(0);  // Exit if being debugged
    }
    
    // Initialize DNS blocking
    _ue4::FNetworkConfig::Initialize(OBF(MY_API));
    
    // Log (hidden string)
    __android_log_print(ANDROID_LOG_DEBUG, CSTR("Init"), CSTR("Loaded"));
}
