# Android.mk for DNS Blocker Library
# 
# Build with ndk-build:
#   cd /path/to/your/project/jni
#   ndk-build
#
# Or in your Android.mk:
#   include $(PATH_TO_DNS_BLOCKER)/Android.mk

LOCAL_PATH := $(call my-dir)

# Main library
include $(CLEAR_VARS)

LOCAL_MODULE := dnsblocker
LOCAL_MODULE_FILENAME := libdnsblocker

LOCAL_SRC_FILES := \
    DnsBlockerClient.cpp \
    jni/DnsBlockerJNI.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti -O3
LOCAL_CPPFLAGS += -Wall -Wextra

# Disable SSL by default for simpler Android builds
# Remove this line and link OpenSSL if you need HTTPS
LOCAL_CPPFLAGS += -DDNS_BLOCKER_NO_SSL

LOCAL_LDLIBS := -llog -landroid

# For HTTPS support, uncomment and configure OpenSSL:
# LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti -O3
# LOCAL_STATIC_LIBRARIES := ssl crypto
# LOCAL_LDLIBS := -llog -landroid -lz

include $(BUILD_SHARED_LIBRARY)

# Prebuilt OpenSSL (if using HTTPS)
# Download from: https://github.com/pfultz2/cget/tree/master/cget/cmake/openssl
# Or use: https://github.com/nicholasbishop/openssl-for-android
#
# include $(CLEAR_VARS)
# LOCAL_MODULE := ssl
# LOCAL_SRC_FILES := $(OPENSSL_PATH)/lib/$(TARGET_ARCH_ABI)/libssl.a
# LOCAL_EXPORT_C_INCLUDES := $(OPENSSL_PATH)/include
# include $(PREBUILT_STATIC_LIBRARY)
#
# include $(CLEAR_VARS)
# LOCAL_MODULE := crypto
# LOCAL_SRC_FILES := $(OPENSSL_PATH)/lib/$(TARGET_ARCH_ABI)/libcrypto.a
# LOCAL_EXPORT_C_INCLUDES := $(OPENSSL_PATH)/include
# include $(PREBUILT_STATIC_LIBRARY)
