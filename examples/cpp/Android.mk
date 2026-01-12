LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := bgmi
LOCAL_SRC_FILES := example_lib.cpp

# Hide symbols - BGMI cannot read function names
LOCAL_CFLAGS := -fvisibility=hidden -ffunction-sections -fdata-sections
LOCAL_CPPFLAGS := -fvisibility=hidden -fvisibility-inlines-hidden -std=c++17

# Strip all symbols
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,-s -Wl,--strip-all

# Link libraries
LOCAL_LDLIBS := -llog -landroid

include $(BUILD_SHARED_LIBRARY)
