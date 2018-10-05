set(src
  cio_os.c
  cio_log.c
  cio_file.c
  cio_sha1.c
  cio_scan.c
  cio_stream.c
  chunkio.c
  )

if(CIO_LIB_STATIC)
  add_library(chunkio-static STATIC ${src})
  target_link_libraries(chunkio-static cio-sha1)
  if(CIO_SANITIZE_ADDRESS)
    add_sanitizers(chunkio-static)
  endif()
endif()

if (CIO_LIB_SHARED)
  add_library(chunkio-shared SHARED ${src})
  target_link_libraries(chunkio-static cio-sha1)
  if(CIO_SANITIZE_ADDRESS)
    add_sanitizers(chunkio-shared)
  endif()
endif()

if (NOT CIO_LIB_STATIC AND NOT CIO_LIB_SHARED)
  message(FATAL_ERROR "What are you doing?, you should build something")
endif()
