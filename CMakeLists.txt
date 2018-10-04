cmake_minimum_required(VERSION 2.8)
project(chunk-io)

# Set __FILENAME__
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")
endif()

# ChunkIO options
option(CIO_LIB_STATIC        "Enable static library build"  On)
option(CIO_LIB_SHARED        "Enable shared library build"  Off)
option(CIO_SANITIZE_ADDRESS  "Enable address sanitizer"     Off)

# Check if Address Sanitizer is enabled
if(CIO_SANITIZE_ADDRESS OR SANITIZE_ADDRESS)
  set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})
  add_definitions(-DSANITIZE_ADDRESS=On)
  find_package(Sanitizers)

  # Note that this package don't define Sanitizers_FOUND:
  # https://github.com/arsenm/sanitizers-cmake/issues/16
  if (NOT DEFINED SANITIZE_LINK_STATIC)
    message(FATAL_ERROR "CMake Sanitizer not found")
  else()
    message(STATUS "Enabling address sanitizer")
  endif()
endif()

include_directories(
  include
  deps/monkey/include
  )

add_subdirectory(src)
add_subdirectory(tools)
