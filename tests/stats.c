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

#include <sys/stat.h>
#include <fcntl.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <chunkio/cio_stats.h>

#include "cio_tests_internal.h"

#define CIO_ENV           "/tmp/cio-fs-test/"
#define CIO_FILE_400KB      CIO_TESTS_DATA_PATH "/data/400kb.txt"
#define CIO_FILE_400KB_SIZE 409600

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;

    printf("[cio-test-stats] %-60s => %s:%i\n",  str, file, line);
    return 0;
}

/* Read a file into the buffer at most 'size' bytes. Return bytes read */
static int read_file(const char *file, char *buf, size_t size)
{
    char *p = buf;
    size_t total = 0;
    size_t nb;

    int fd = open(file, O_RDONLY);
    if (fd == -1)
        return -1;

    while (1) {
        nb = read(fd, p, size);
        if (nb == 0)
            break;
        if (nb < 0) {
            close(fd);
            return -1;
        }
        p += nb;
        size -= nb;
        total += nb;
    }
    close(fd);
    return total;
}

static void test_stats_mem()
{
    int i;
    int err;
    int ret;
    int n_files = 100;
    int flags;
    char *in_data;
    size_t in_size;
    char tmp[255];
    size_t written = 0;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk **carr;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    flags = CIO_CHECKSUM;

    /* Create main context */
    ctx = cio_create(NULL, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    TEST_CHECK(ctx->stats.streams_total == 0);

    /* Create valid stream */
    stream = cio_stream_create(ctx, "test-write", CIO_STORE_MEM);
    TEST_CHECK(stream != NULL);
    TEST_CHECK(ctx->stats.streams_total == 1);

    /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    in_size = CIO_FILE_400KB_SIZE;
    in_data = malloc(in_size);
    if (!in_data) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    ret = read_file(CIO_FILE_400KB, in_data, in_size);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Number of test files to create */
    n_files = 100;

    /* Allocate files array */
    carr = calloc(1, sizeof(struct cio_chunk) * n_files);
    if (!carr) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < n_files; i++) {
        snprintf(tmp, sizeof(tmp), "api-test-%04i.txt", i);
        carr[i] = cio_chunk_open(ctx, stream, tmp, CIO_OPEN, 1000000, &err);

        if (carr[i] == NULL) {
            continue;
        }

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;

        /* update metadata */
        cio_meta_write(carr[i], "x", 1);
        written++;

        /* continue appending data to content area */
        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;

        /* update metadata */
        cio_meta_write(carr[i], "xy", 2);

        /*
         * just increment '1', since metadata handling overwrites the area, it
         * do not append at the end.
         */
        written++;
    }

    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /*
     * Delete some chunks: remove some chunks from the list and check
     * for stats adjustment.
     */
    cio_chunk_close(carr[0], CIO_TRUE);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Release file data and destroy context */
    free(carr);
    free(in_data);

    cio_destroy(ctx);
}


static void test_stats_fs()
{
    int i;
    int err;
    int ret;
    int n_files = 100;
    int flags;
    int header = 24; /* file type + crc + padding + meta */
    char *in_data;
    size_t in_size;
    char tmp[255];
    size_t written = 0;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk **carr;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    flags = CIO_CHECKSUM;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    /* Create main context */
    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    TEST_CHECK(ctx->stats.streams_total == 0);

    /* Create valid stream */
    stream = cio_stream_create(ctx, "test-write", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    TEST_CHECK(ctx->stats.streams_total == 1);

    /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    in_size = CIO_FILE_400KB_SIZE;
    in_data = malloc(in_size);
    if (!in_data) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    ret = read_file(CIO_FILE_400KB, in_data, in_size);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Number of test files to create */
    n_files = 12;

    /* Allocate files array */
    carr = calloc(1, sizeof(struct cio_chunk) * n_files);
    if (!carr) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < n_files; i++) {
        snprintf(tmp, sizeof(tmp), "api-test-%04i.txt", i);
        carr[i] = cio_chunk_open(ctx, stream, tmp, CIO_OPEN, 1000000, &err);

        if (carr[i] == NULL) {
            continue;
        }

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

        /* update metadata */
        //cio_meta_write(farr[i], tmp, len);

        /* continue appending data to content area */
        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

        /* each file contains 'header' bytes */
        written += header;
    }

    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Delete one chunk, this should remove 'up' and 'down' */
    cio_chunk_close(carr[0], CIO_FALSE);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Chunk down */
    cio_chunk_down(carr[1]);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Chunk up */
    cio_chunk_up(carr[1]);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* For the new chunk 'up', write 1.2MB and check */
    for (i = 0; i < 3; i++) {
        cio_chunk_write(carr[1], in_data, in_size);
        TEST_CHECK(cio_stats_validate(ctx) == 0);
    }
    cio_chunk_sync(carr[1]);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    cio_chunk_down(carr[10]);
    cio_chunk_down(carr[11]);

    cio_stream_create(ctx, "test-write 2", CIO_STORE_FS);
    cio_stream_create(ctx, "test-write 3", CIO_STORE_MEM);

    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Release file data and destroy context */
    free(carr);
    free(in_data);

    cio_destroy(ctx);
}

TEST_LIST = {
    {"mem",  test_stats_mem},
    {"fs",  test_stats_fs},
    { 0 }
};
