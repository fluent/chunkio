/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#include <sys/mman.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_sha1.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_stream.h>

#include "cio_tests_internal.h"

#define CIO_ENV           "/tmp/cio-fs-test/"
#define CIO_FILE_400KB    CIO_TESTS_DATA_PATH "/data/400kb.txt"

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, const char *file, int line,
                  char *str)
{
    (void) ctx;

    printf("[cio-test-fs] %-60s => %s:%i\n",  str, file, line);
    return 0;
}

static int read_file(const char *path, char **buf, size_t *size)
{
    int fd;
    int ret;
    char *data;
    struct stat st;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    ret = fstat(fd, &st);
    if (ret == -1) {
        perror("fstat");
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    close(fd);

    *buf = data;
    *size = st.st_size;

    return 0;
}

/* Test API generating files to the file system and then scanning them back */
static void test_fs_write()
{
    int i;
    int ret;
    char *in_data;
    size_t in_size;
    char tmp[255];
    unsigned char hash_sha1[20];
    unsigned char hex_sha1[41];
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_file *file;
    struct cio_file *farr[1000];

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    /* cleanup environment */
    utils_recursive_delete(CIO_ENV);

    /* Create main context */
    ctx = cio_create(CIO_ENV, log_cb, CIO_INFO);
    TEST_CHECK(ctx != NULL);

    /* Try to create a file with an invalid stream */
    file = cio_file_open(ctx, NULL, "invalid", 0, 0);
    TEST_CHECK(file == NULL);

    /* Check invalid stream */
    stream = cio_stream_create(ctx, "");
    TEST_CHECK(stream == NULL);

    /* Another invalid name */
    stream = cio_stream_create(ctx, "/");
    TEST_CHECK(stream == NULL);

    /* Create valid stream */
    stream = cio_stream_create(ctx, "test-write");
    TEST_CHECK(stream != NULL);

    /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    ret = read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Data file sha1 */
    cio_sha1_hash(in_data, in_size, hash_sha1, NULL);
    cio_sha1_to_hex(hash_sha1, (char *) hex_sha1);

    for (i = 0; i < 10; i++) {
        snprintf(tmp, sizeof(tmp), "api-test-%04i.txt", i);
        farr[i] = cio_file_open(ctx, stream, tmp,
                                CIO_OPEN | CIO_HASH_CHECK, 1000000);

        cio_file_write(farr[i], in_data, in_size);
        cio_file_sync(farr[i]);
    }

    /* Release file data and destroy context */
    munmap(in_data, in_size);
    cio_destroy(ctx);

    /* Create new context using the data generated above */
    ctx = cio_create(CIO_ENV, log_cb, CIO_INFO);
    TEST_CHECK(ctx != NULL);
    cio_scan_dump(ctx);
    cio_destroy(ctx);
}

/*
 * Create one file chunk and check it updated sha1 after a couple of writes
 * and sync.
 */
static void test_sha_check()
{
    int ret;
    char *in_data;
    char *f_hash;
    size_t in_size;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_file *file;

    /* sha1 hashes */
    char sha_test1[] =  {
        0x14, 0x89, 0xf9, 0x23, 0xc4,
        0xdc, 0xa7, 0x29, 0x17, 0x8b,
        0x3e, 0x32, 0x33, 0x45, 0x85,
        0x50, 0xd8, 0xdd, 0xdf, 0x29
    };

    char sha_test2[] = {
        0x62, 0x4f, 0x06, 0x04, 0x38,
        0xc8, 0x17, 0x3c, 0x91, 0x5c,
        0x26, 0xca, 0xbc, 0x5d, 0x47,
        0x4b, 0x6f, 0x71, 0xea, 0xaf
    };

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    /* cleanup environment */
    utils_recursive_delete(CIO_ENV);

    ctx = cio_create(CIO_ENV, log_cb, CIO_INFO);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test-sha1");
    TEST_CHECK(stream != NULL);

    /* Load sample data file in memory */
    ret = read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /*
     * Test 1:
     *  - create one empty file
     *  - sync
     *  - validate sha_test1
     */
    file = cio_file_open(ctx, stream, "test1.out",
                         CIO_OPEN | CIO_HASH_CHECK, 10);
    cio_file_sync(file);

    /* Check default sha1() for an empty file after msync(2) */
    f_hash = cio_file_hash(file);
    ret = memcmp(f_hash, sha_test1, 20);
    TEST_CHECK(ret == 0);

    /*
     * Test 2:
     *  - append content of 400kb.txt file to file context
     *  - validate file sha1 in mem is the same as sha_test1
     *  - sync
     *  - validate file sha1 in mem is equal to sha_test2
     *
     * note that the second sha1 calculation is done using the initial
     * sha1 context so it skip old data to perform the verification.
     */
    cio_file_write(file, in_data, in_size);
    cio_file_sync(file);

    f_hash = cio_file_hash(file);
    ret = memcmp(f_hash, sha_test2, 20);
    TEST_CHECK(ret == 0);

    /* Release */
    cio_destroy(ctx);
    munmap(in_data, in_size);
}

TEST_LIST = {
    {"fs_write",   test_fs_write},
    {"sha_check",  test_sha_check},
    { 0 }
};
