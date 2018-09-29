cmake_minimum_required(VERSION 2.8)
project(chunk-io)

option(CIO_LIB_STATIC "Enable static library build"  On)
option(CIO_LIB_SHARED "Enable shared library build"  Off)

include_directories(include)
add_subdirectory(src)

add_subdirectory(tools)
