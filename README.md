# .SO Library Protection API

Obfuscate your `.so` libraries so they cannot be easily read or detected.

## Quick Start

### 1. Host the API

```bash
# Start PHP server
php -S 0.0.0.0:8080

# Or use Apache/Nginx with PHP
```

### 2. Obfuscate a Library

**Method 1 - URL Parameter:**
```
http://yourserver:8080/?connect=libbgmi.so
http://yourserver:8080/?connect=libs/mylib.so&key=mysecretkey
```

**Method 2 - File Upload:**
```bash
curl -F "file=@libbgmi.so" http://yourserver:8080/ -o protected.so
curl -F "file=@libbgmi.so" -F "key=mysecretkey" http://yourserver:8080/ -o protected.so
```

**Method 3 - CLI:**
```bash
php obfuscate.php libbgmi.so output.protected mykey
```

## Directory Structure

```
/workspace/
├── index.php          # Main API endpoint with web UI
├── api.php            # Simple API (obfuscated code)
├── obfuscate.php      # Full obfuscator class
├── Dns.php            # DNS filtering module
├── libs/              # Put your .so files here
│   └── libbgmi.so
└── examples/
    └── cpp/
        ├── GameConfig.h   # DNS/Network filtering
        └── SoLoader.h     # C++ loader for protected libs
```

## Usage in C++ (Android/Game)

```cpp
#include "SoLoader.h"

// Load protected library
void* handle = SO_LOAD_PROTECTED("/path/to/lib.protected");

// Or with custom key
void* handle = SO_LOAD_PROTECTED_KEY("/path/to/lib.protected", "mykey");

// Get function pointer
typedef void (*MyFunc)();
MyFunc func = (MyFunc)SO_GET_FUNC("function_name");
func();

// Cleanup
SO_UNLOAD();
```

## Protection Layers

1. **XOR Encryption** - Key-based XOR on entire file
2. **Block XOR** - Position-based block transformation (DEADBEEF)
3. **RC4 Stream Cipher** - Additional encryption layer
4. **ELF Header Obfuscation** - Mangles ELF headers (restorable at runtime)
5. **IV Wrapping** - Random IV + SHA256 integrity check
6. **Anti-Tampering** - CRC32 + size verification

## API Response

When requesting a library:
- Returns obfuscated binary with `application/octet-stream` content type
- Headers include:
  - `X-Original-Size` - Original file size
  - `X-Protected-Size` - Protected file size

## Security Notes

- Key rotates hourly by default (based on `YmdH` format)
- Custom keys are hashed with SHA256
- Protected format: `\x00PROTECT\x00` + metadata + encrypted data

## File Placement

Put your `.so` files in these locations for automatic detection:
- `./` (current directory)
- `./libs/`
- `./lib/`

Then access via: `?connect=filename.so`
