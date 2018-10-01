cmake_minimum_required(VERSION 2.8)
project(chunk-io)

# Set __FILENAME__
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")
endif()

# ChunkIO options
option(CIO_LIB_STATIC "Enable static library build"  On)
option(CIO_LIB_SHARED "Enable shared library build"  Off)

include_directories(
  include
  deps/monkey/include
  )

add_subdirectory(src)
add_subdirectory(tools)
