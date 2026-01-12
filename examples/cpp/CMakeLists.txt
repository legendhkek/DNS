cmake_minimum_required(VERSION 3.14)
project(DnsBlocker VERSION 2.0.0 LANGUAGES CXX)

# C++17 required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(DNS_BLOCKER_BUILD_SHARED "Build shared library" ON)
option(DNS_BLOCKER_BUILD_STATIC "Build static library" ON)
option(DNS_BLOCKER_BUILD_JNI "Build JNI wrapper for Android" OFF)
option(DNS_BLOCKER_BUILD_EXAMPLE "Build example application" ON)
option(DNS_BLOCKER_NO_SSL "Disable SSL/TLS support" OFF)

# Platform detection
if(ANDROID)
    set(DNS_BLOCKER_BUILD_JNI ON)
    set(DNS_BLOCKER_BUILD_EXAMPLE OFF)
endif()

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-O3)
    endif()
endif()

# Source files
set(DNS_BLOCKER_SOURCES
    DnsBlockerClient.cpp
)

set(DNS_BLOCKER_HEADERS
    DnsBlockerClient.hpp
)

# Find OpenSSL (optional)
if(NOT DNS_BLOCKER_NO_SSL)
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    else()
        message(WARNING "OpenSSL not found - HTTPS support disabled")
        set(DNS_BLOCKER_NO_SSL ON)
    endif()
endif()

# Compile definitions
if(DNS_BLOCKER_NO_SSL)
    add_compile_definitions(DNS_BLOCKER_NO_SSL)
endif()

# Shared library
if(DNS_BLOCKER_BUILD_SHARED)
    add_library(dnsblocker SHARED ${DNS_BLOCKER_SOURCES})
    target_include_directories(dnsblocker PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    
    if(OPENSSL_FOUND)
        target_link_libraries(dnsblocker PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    
    if(UNIX AND NOT APPLE AND NOT ANDROID)
        target_link_libraries(dnsblocker PRIVATE pthread)
    endif()
    
    if(WIN32)
        target_link_libraries(dnsblocker PRIVATE ws2_32)
    endif()
    
    set_target_properties(dnsblocker PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER "${DNS_BLOCKER_HEADERS}"
    )
endif()

# Static library
if(DNS_BLOCKER_BUILD_STATIC)
    add_library(dnsblocker_static STATIC ${DNS_BLOCKER_SOURCES})
    target_include_directories(dnsblocker_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    
    if(OPENSSL_FOUND)
        target_link_libraries(dnsblocker_static PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    
    if(UNIX AND NOT APPLE AND NOT ANDROID)
        target_link_libraries(dnsblocker_static PRIVATE pthread)
    endif()
    
    if(WIN32)
        target_link_libraries(dnsblocker_static PRIVATE ws2_32)
    endif()
    
    set_target_properties(dnsblocker_static PROPERTIES
        OUTPUT_NAME dnsblocker
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
endif()

# JNI wrapper for Android
if(DNS_BLOCKER_BUILD_JNI)
    find_package(JNI QUIET)
    
    add_library(dnsblocker_jni SHARED
        ${DNS_BLOCKER_SOURCES}
        jni/DnsBlockerJNI.cpp
    )
    
    target_include_directories(dnsblocker_jni PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${JNI_INCLUDE_DIRS}
    )
    
    if(OPENSSL_FOUND)
        target_link_libraries(dnsblocker_jni PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    
    if(ANDROID)
        target_link_libraries(dnsblocker_jni PRIVATE log android)
    endif()
    
    set_target_properties(dnsblocker_jni PROPERTIES
        OUTPUT_NAME dnsblocker
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/jniLibs/${ANDROID_ABI}
    )
endif()

# Example application
if(DNS_BLOCKER_BUILD_EXAMPLE)
    add_executable(dns_example example.cpp)
    target_link_libraries(dns_example PRIVATE dnsblocker_static)
    
    if(OPENSSL_FOUND)
        target_link_libraries(dns_example PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    
    if(UNIX AND NOT APPLE)
        target_link_libraries(dns_example PRIVATE pthread)
    endif()
    
    if(WIN32)
        target_link_libraries(dns_example PRIVATE ws2_32)
    endif()
endif()

# Installation
include(GNUInstallDirs)

if(DNS_BLOCKER_BUILD_SHARED)
    install(TARGETS dnsblocker
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dnsblocker
    )
endif()

if(DNS_BLOCKER_BUILD_STATIC)
    install(TARGETS dnsblocker_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

install(FILES ${DNS_BLOCKER_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dnsblocker
)

# Package config
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/DnsBlockerConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Print configuration summary
message(STATUS "")
message(STATUS "DNS Blocker Configuration:")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Shared lib:     ${DNS_BLOCKER_BUILD_SHARED}")
message(STATUS "  Static lib:     ${DNS_BLOCKER_BUILD_STATIC}")
message(STATUS "  JNI wrapper:    ${DNS_BLOCKER_BUILD_JNI}")
message(STATUS "  Example:        ${DNS_BLOCKER_BUILD_EXAMPLE}")
message(STATUS "  SSL support:    ${OPENSSL_FOUND}")
message(STATUS "")
