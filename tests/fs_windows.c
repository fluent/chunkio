/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <edsiper@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Windows File Handling Inconsistency Tests
 * ==========================================
 *
 * This test suite highlights inconsistencies between Windows and Unix
 * implementations of file handling in chunkio:
 *
 * 1. Delete while open/mapped: Windows allows deletion of open/mapped files
 *    while Unix correctly rejects it
 *
 * 2. Sync without mapping: Windows accesses cf->map without checking if it's
 *    NULL, which can cause crashes
 *
 * 3. File mapping size mismatch: CreateFileMapping uses current file size
 *    but MapViewOfFile may request a larger size, causing potential issues
 *
 * 4. File descriptor check: cio_file.c uses Unix-specific cf->fd check
 *    instead of platform-agnostic cio_file_native_is_open()
 *
 * These tests are designed to demonstrate the issues and verify behavior.
 */

#ifdef _WIN32

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_chunk.h>

#include "cio_tests_internal.h"

#define CIO_ENV "tmp"

/* Logging callback */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;
    (void) level;

    printf("[cio-test-win32] %-60s => %s:%i\n", str, file, line);
    return 0;
}

/*
 * ISSUE #1: Test deleting a file that is open/mapped
 *
 * Expected behavior: Should fail with CIO_ERROR (as Unix does)
 * Current behavior:  Succeeds and may cause resource leaks
 */
static void test_win32_delete_while_open()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: Delete file while open ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open and map a file */
    chunk = cio_chunk_open(ctx, stream, "test-file-open", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Verify file is open */
    TEST_CHECK(cio_file_native_is_open(cf) == 1);

    /* Try to delete while open - THIS SHOULD FAIL but currently doesn't on Windows */
    ret = cio_file_native_delete(cf);
    printf("Result of delete while open: %d (expected: CIO_ERROR=%d)\n",
           ret, CIO_ERROR);

    /* On Unix this returns CIO_ERROR, on Windows it currently succeeds */
    /* This highlights the inconsistency */
    if (ret == CIO_ERROR) {
        printf("PASS: Delete correctly failed while file is open\n");
    }
    else {
        printf("ISSUE DETECTED: Delete succeeded while file is open (inconsistent with Unix)\n");
    }

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * ISSUE #2: Test deleting a file that is mapped
 *
 * Expected behavior: Should fail with CIO_ERROR (as Unix does)
 * Current behavior:  Succeeds and may cause crashes
 */
static void test_win32_delete_while_mapped()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: Delete file while mapped ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open and map a file */
    chunk = cio_chunk_open(ctx, stream, "test-file-mapped", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Write some data to ensure mapping */
    ret = cio_chunk_write(chunk, "test data", 9);
    TEST_CHECK(ret == 0);

    /* Verify file is mapped */
    TEST_CHECK(cio_file_native_is_mapped(cf) == 1);

    /* Try to delete while mapped - THIS SHOULD FAIL but currently doesn't on Windows */
    ret = cio_file_native_delete(cf);
    printf("Result of delete while mapped: %d (expected: CIO_ERROR=%d)\n",
           ret, CIO_ERROR);

    /* On Unix this returns CIO_ERROR, on Windows it currently succeeds */
    /* This highlights the inconsistency */
    if (ret == CIO_ERROR) {
        printf("PASS: Delete correctly failed while file is mapped\n");
    }
    else {
        printf("ISSUE DETECTED: Delete succeeded while file is mapped (inconsistent with Unix)\n");
        printf("WARNING: This can cause crashes when accessing the mapped memory\n");
    }

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * ISSUE #3: Test syncing a file that is not mapped
 *
 * Expected behavior: Should check if mapped before accessing cf->map
 * Current behavior:  Accesses cf->map without checking, may crash
 */
static void test_win32_sync_without_map()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: Sync file without mapping ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open a file but don't map it */
    chunk = cio_chunk_open(ctx, stream, "test-file-sync", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Manually unmap if it was auto-mapped */
    if (cio_file_native_is_mapped(cf)) {
        ret = cio_file_native_unmap(cf);
        TEST_CHECK(ret == CIO_OK);
    }

    /* Verify file is not mapped */
    TEST_CHECK(cio_file_native_is_mapped(cf) == 0);

    /* Verify cf->map is actually NULL (this is the issue) */
    TEST_CHECK(cf->map == NULL);
    printf("Verified: cf->map is NULL\n");

    /* Try to sync without mapping - THIS SHOULD CHECK FIRST */
    /* On Windows, cio_file_native_sync accesses cf->map directly without checking */
    /* This will likely cause a crash or access violation because FlushViewOfFile
     * is called with a NULL pointer */
    printf("Attempting sync on unmapped file (cf->map is NULL)...\n");
    printf("WARNING: cio_file_native_sync will call FlushViewOfFile(cf->map, ...)\n");
    printf("         which will fail or crash if cf->map is NULL\n");

    /* This test is designed to highlight the issue - on Windows it may crash */
    /* We catch this to demonstrate the problem exists */
    ret = cio_file_native_sync(cf, 0);
    printf("Result of sync without map: %d\n", ret);

    if (ret == CIO_ERROR) {
        printf("PASS: Sync correctly failed when file is not mapped\n");
    }
    else {
        printf("ISSUE DETECTED: Sync returned unexpected result or crashed\n");
        printf("Expected: CIO_ERROR due to NULL map pointer\n");
    }

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * ISSUE #4: Test file mapping size mismatch
 *
 * Expected behavior: CreateFileMapping should use map_size, not current file size
 * Current behavior:  Creates mapping based on file size, then tries to map larger view
 */
static void test_win32_map_size_mismatch()
{
    int ret;
    int err;
    size_t file_size;
    size_t map_size;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: File mapping size mismatch ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Create a small file first */
    chunk = cio_chunk_open(ctx, stream, "test-file-size", CIO_OPEN, 1024, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Write minimal data */
    ret = cio_chunk_write(chunk, "test", 4);
    TEST_CHECK(ret == 0);

    /* Sync to ensure file is written */
    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == 0);

    /* Get actual file size */
    ret = cio_file_native_get_size(cf, &file_size);
    TEST_CHECK(ret == CIO_OK);
    printf("Actual file size: %zu bytes\n", file_size);

    /* Close the chunk to unmap */
    cio_chunk_close(chunk, CIO_FALSE);

    /* Reopen file */
    chunk = cio_chunk_open(ctx, stream, "test-file-size", CIO_OPEN_RD, 0, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Try to map with a size larger than the file */
    map_size = file_size + 4096; /* Request 4KB more than file size */
    printf("Attempting to map %zu bytes (file is %zu bytes)\n", map_size, file_size);

    /* Open file */
    ret = cio_file_native_open(cf);
    TEST_CHECK(ret == CIO_OK);

    /* This is where the issue occurs: CreateFileMapping uses current file size,
     * but MapViewOfFile tries to map a larger size */
    ret = cio_file_native_map(cf, map_size);
    printf("Result of mapping %zu bytes to %zu byte file: %d\n",
           map_size, file_size, ret);

    if (ret == CIO_OK) {
        printf("WARNING: Mapping succeeded, but may only provide access to file_size bytes\n");
        printf("Accessing beyond file_size may cause undefined behavior\n");

        /* Verify what was actually mapped */
        if (cio_file_native_is_mapped(cf)) {
            printf("File is mapped, alloc_size: %zu\n", cf->alloc_size);
        }

        ret = cio_file_native_unmap(cf);
        TEST_CHECK(ret == CIO_OK);
    }
    else {
        printf("Mapping failed as expected when size mismatch occurs\n");
    }

    cio_file_native_close(cf);
    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * Test accessing file descriptor check inconsistency
 * This tests the issue in cio_file.c line 804 where it checks cf->fd > 0
 * instead of using cio_file_native_is_open(cf)
 */
static void test_win32_fd_check_inconsistency()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: File descriptor check inconsistency ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open a file */
    chunk = cio_chunk_open(ctx, stream, "test-file-fd", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Verify file is open using the proper macro */
    ret = cio_file_native_is_open(cf);
    TEST_CHECK(ret == 1);
    printf("cio_file_native_is_open(cf): %d\n", ret);

    /* Check cf->fd value on Windows (should be -1 or not set properly) */
    printf("cf->fd value: %d\n", cf->fd);
    printf("cf->fd > 0 check: %d\n", (cf->fd > 0));
    printf("cio_file_native_is_open(cf): %d\n", cio_file_native_is_open(cf));

    /* This highlights that cf->fd > 0 doesn't work on Windows */
    if (cf->fd <= 0 && cio_file_native_is_open(cf)) {
        printf("ISSUE DETECTED: cf->fd check (%d) doesn't match cio_file_native_is_open (%d)\n",
               (cf->fd > 0), cio_file_native_is_open(cf));
        printf("WARNING: cio_file.c line 804 uses cf->fd > 0 which is Unix-specific\n");
    }

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

TEST_LIST = {
    {"win32_delete_while_open",       test_win32_delete_while_open},
    {"win32_delete_while_mapped",     test_win32_delete_while_mapped},
    {"win32_sync_without_map",         test_win32_sync_without_map},
    {"win32_map_size_mismatch",        test_win32_map_size_mismatch},
    {"win32_fd_check_inconsistency",  test_win32_fd_check_inconsistency},
    {NULL, NULL}
};

#else /* _WIN32 */

/* Empty test list for non-Windows platforms */
TEST_LIST = {
    {NULL, NULL}
};

#endif /* _WIN32 */

