cmake_minimum_required(VERSION 3.14)
project(GameConfig VERSION 2.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_SHARED "Build shared lib" ON)
option(BUILD_STATIC "Build static lib" ON)
option(BUILD_JNI "Build JNI for Android" OFF)
option(NO_SSL "Disable SSL" OFF)

if(ANDROID)
    set(BUILD_JNI ON)
endif()

set(SOURCES DnsBlockerClient.cpp)
set(HEADERS DnsBlockerClient.hpp)

if(NOT NO_SSL)
    find_package(OpenSSL QUIET)
endif()

if(NO_SSL OR NOT OPENSSL_FOUND)
    add_compile_definitions(NO_SSL)
endif()

# Shared library
if(BUILD_SHARED)
    add_library(gameconfig SHARED ${SOURCES})
    target_include_directories(gameconfig PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    if(OPENSSL_FOUND)
        target_link_libraries(gameconfig PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(UNIX AND NOT APPLE AND NOT ANDROID)
        target_link_libraries(gameconfig PRIVATE pthread)
    endif()
    if(WIN32)
        target_link_libraries(gameconfig PRIVATE ws2_32)
    endif()
endif()

# Static library
if(BUILD_STATIC)
    add_library(gameconfig_static STATIC ${SOURCES})
    target_include_directories(gameconfig_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    if(OPENSSL_FOUND)
        target_link_libraries(gameconfig_static PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(UNIX AND NOT APPLE AND NOT ANDROID)
        target_link_libraries(gameconfig_static PRIVATE pthread)
    endif()
    if(WIN32)
        target_link_libraries(gameconfig_static PRIVATE ws2_32)
    endif()
endif()

# JNI for Android
if(BUILD_JNI)
    add_library(gameconfig_jni SHARED
        ${SOURCES}
        jni/DnsBlockerJNI.cpp
    )
    target_include_directories(gameconfig_jni PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(OPENSSL_FOUND)
        target_link_libraries(gameconfig_jni PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(ANDROID)
        target_link_libraries(gameconfig_jni PRIVATE log)
    endif()
    set_target_properties(gameconfig_jni PROPERTIES
        OUTPUT_NAME gameconfig
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/jniLibs/${ANDROID_ABI}
    )
endif()
