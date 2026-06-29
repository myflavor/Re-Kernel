cmake_minimum_required(VERSION 3.22.1)
project("ReKernelX")

add_library(ReKernelX SHARED rekernel_jni.cpp)

# 16 KB page size alignment for Android 15+ compatibility.
target_link_options(ReKernelX PRIVATE "-Wl,-z,max-page-size=16384")

find_library(log-lib log)
target_link_libraries(ReKernelX ${log-lib})
