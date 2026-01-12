APP_ABI := arm64-v8a armeabi-v7a
APP_PLATFORM := android-21
APP_STL := c++_static
APP_OPTIM := release

# Extra flags for obfuscation
APP_CFLAGS := -O2 -DNDEBUG -fvisibility=hidden
APP_CPPFLAGS := -fvisibility=hidden -fvisibility-inlines-hidden
