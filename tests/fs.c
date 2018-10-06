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

static void test_fs_write()
{
    int i;
    int ret;
    char *in_data;
    size_t in_size;
    char *env = "/tmp/cio-fs-test/";
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
    utils_recursive_delete(env);

    /* Create main context */
    ctx = cio_create(env, log_cb, CIO_INFO);
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
    cio_sha1_hash(in_data, in_size, hash_sha1);
    cio_sha1_to_hex(hash_sha1, (char *) hex_sha1);

    for (i = 0; i < 10; i++) {
        snprintf(tmp, sizeof(tmp), "api-test-%04i.txt", i);
        farr[i] = cio_file_open(ctx, stream, tmp, CIO_OPEN, 1000000);

        cio_file_write(farr[i], in_data, in_size);
        cio_file_sync(farr[i]);
    }

    /* Release file data and destroy context */
    munmap(in_data, in_size);
    cio_destroy(ctx);

    /* Create new context using the data generated above */
    ctx = cio_create(env, log_cb, CIO_INFO);
    TEST_CHECK(ctx != NULL);
    cio_scan_dump(ctx);
    cio_destroy(ctx);
}

TEST_LIST = {
    {"fs_write",   test_fs_write},
    { 0 }
};
