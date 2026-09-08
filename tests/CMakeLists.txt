include_directories(lib/acutest)

set(UNIT_TESTS_FILES
  context.c
  memfs.c
  stream.c
  )
if(CIO_BACKEND_FILESYSTEM)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    fs.c
    metadata_update.c
    fluent_bit_storage.c
    allocation.c
    caller_allocation.c
    )
endif()

# Windows-specific inconsistency tests
if(WIN32 AND CIO_BACKEND_FILESYSTEM)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    fs_windows.c
    )
endif()

set(CIO_TESTS_DATA_PATH ${CMAKE_CURRENT_SOURCE_DIR}/)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cio_tests_internal.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/cio_tests_internal.h"
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cio-test-${source_file_we})
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we} chunkio-static)

  # Observe expensive operations without adding instrumentation to the library.
  if(source_file STREQUAL "fluent_bit_storage.c" AND
     CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
     CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_definitions(${source_file_we} PRIVATE CIO_TEST_FILE_CALLS)
    target_link_options(${source_file_we} PRIVATE
      "-Wl,--wrap=cio_file_native_resize"
      "-Wl,--wrap=cio_file_native_sync")
  endif()

  if(source_file STREQUAL "allocation.c" AND
     CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
     CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_definitions(${source_file_we} PRIVATE CIO_TEST_ALLOCATION_CALLS)
    target_link_options(${source_file_we} PRIVATE
      "-Wl,--wrap=cio_file_native_resize"
      "-Wl,--wrap=cio_file_native_remap"
      "-Wl,--wrap=cio_file_native_get_size"
      "-Wl,--wrap=mmap"
      "-Wl,--wrap=mremap"
      "-Wl,--wrap=realloc")
  endif()

  if(source_file STREQUAL "caller_allocation.c" AND
     CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
     CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_definitions(${source_file_we} PRIVATE CIO_TEST_CALLER_CALLS)
    target_link_options(${source_file_we} PRIVATE
      "-Wl,--wrap=cio_file_native_resize"
      "-Wl,--wrap=cio_file_native_map"
      "-Wl,--wrap=cio_file_native_remap")
  endif()

  if (CIO_SANITIZE_ADDRESS)
    add_sanitizers(${source_file_we})
  endif()

  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
endforeach()

# Perf tests for dev purposes: note these tests are not registered, they need to
# be executed manually
set(UNIT_PERF_TESTS
  fs_perf.c
  fs_fragmentation.c
  )
foreach(source_file ${UNIT_PERF_TESTS})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cio-${source_file_we})
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we} chunkio-static)

  if (CIO_SANITIZE_ADDRESS)
    add_sanitizers(${source_file_we})
  endif()
  #add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
endforeach()
