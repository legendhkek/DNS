# Application.mk for DNS Blocker Library
#
# Configure target ABIs and platform settings

# Target all common Android ABIs
APP_ABI := armeabi-v7a arm64-v8a x86 x86_64

# Minimum Android API level
APP_PLATFORM := android-21

# Use C++17
APP_STL := c++_shared

# Optimization
APP_OPTIM := release

# Enable exceptions and RTTI
APP_CPPFLAGS := -std=c++17 -fexceptions -frtti
