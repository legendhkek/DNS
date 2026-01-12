LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := gameconfig
LOCAL_MODULE_FILENAME := libgameconfig

LOCAL_SRC_FILES := \
    DnsBlockerClient.cpp \
    jni/DnsBlockerJNI.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CPPFLAGS := -std=c++17 -fexceptions -frtti -O3 -fvisibility=hidden
LOCAL_CPPFLAGS += -DNO_SSL

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
