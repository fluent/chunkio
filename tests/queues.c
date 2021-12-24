/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_queue.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <chunkio/cio_stats.h>

#include "cio_tests_internal.h"

#define CIO_ENV           "/tmp/cio-fs-test/"
#define CIO_FILE_400KB      CIO_TESTS_DATA_PATH "/data/400kb.txt"
#define CIO_FILE_400KB_SIZE 409600

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

void test_queues()
{
    int i;
    int err;
    int ret;
    int n_files = 100;
    int flags;
    int header = 24; /* file type + crc + padding + meta */
    char tmp[255];
    char *in_data;
    size_t in_size;
    size_t written = 0;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk **carr;
    struct cio_queue **qarr;
    struct cio_queue_chunk *qch;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    flags = CIO_CHECKSUM;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    /* Create main context */
    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    /* Create valid stream */
    stream = cio_stream_create(ctx, "test-write", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

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

    /* Allocate queues array */
    qarr = calloc(1, sizeof(struct cio_queue) * n_files);
    if (!qarr) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < n_files; i++) {
        snprintf(tmp, sizeof(tmp), "api-test-%04i.txt", i);
        carr[i] = cio_chunk_open(ctx, stream, tmp, CIO_OPEN, 1000000, &err);

        if (carr[i] == NULL) {
            continue;
        }

        /* create queue */
        qarr[i] = cio_queue_create(ctx, tmp);

        /* add chunk to queue */
        qch = cio_queue_chunk_add(ctx, qarr[i], carr[i]);
        TEST_CHECK(qch != NULL);

        /* write some data */
        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

        cio_chunk_write(carr[i], in_data, in_size);
        written += in_size;
        cio_chunk_sync(carr[i]);

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

    free(qarr);


}

static void test_size_check_type(int type)
{
    int err;
    int ret;
    int flags;
    char tmp[255];
    char page[4096] = {0};
    char *in_data;
    size_t in_size;
    struct cio_ctx *ctx;

    /* streams */
    struct cio_stream *stream1;
    struct cio_stream *stream2;

    /* chunks */
    struct cio_chunk *c1;
    struct cio_chunk *c2;
    struct cio_chunk *c3;
    struct cio_chunk *c4;

    /* queues */
    struct cio_queue *q1;
    struct cio_queue *q2;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    flags = CIO_CHECKSUM;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    /* Create main context */
    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    /* Create valid stream */
    stream1 = cio_stream_create(ctx, "test-write-1", type);
    TEST_CHECK(stream1 != NULL);

    stream2 = cio_stream_create(ctx, "test-write-2", type);
    TEST_CHECK(stream2 != NULL);

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

    /* chunks on stream 1 */
    snprintf(tmp, sizeof(tmp), "queue-test-1.txt");
    c1 = cio_chunk_open(ctx, stream1, tmp, CIO_OPEN, 1000000, &err);

    snprintf(tmp, sizeof(tmp), "queue-test-2.txt");
    c2 = cio_chunk_open(ctx, stream1, tmp, CIO_OPEN, 1000000, &err);

    /* chunks on stream 2 */
    snprintf(tmp, sizeof(tmp), "queue-test-3.txt");
    c3 = cio_chunk_open(ctx, stream2, tmp, CIO_OPEN, 1000000, &err);

    snprintf(tmp, sizeof(tmp), "queue-test-4.txt");
    c4 = cio_chunk_open(ctx, stream2, tmp, CIO_OPEN, 1000000, &err);

    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* write metadata */
    cio_meta_write(c1, "meta 1", 6);
    cio_meta_write(c2, "meta 2", 6);
    cio_meta_write(c3, "meta 3", 6);
    cio_meta_write(c4, "meta 4", 6);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* write some data to chunk 1 (1.6MB) and add it to queue 2 */
    cio_chunk_write(c1, in_data, in_size);
    cio_chunk_write(c1, in_data, in_size);
    cio_chunk_write(c1, in_data, in_size);
    cio_chunk_write(c1, in_data, in_size);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* create queues */
    q1 = cio_queue_create(ctx, "queue-1");
    q2 = cio_queue_create(ctx, "queue-2");
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* add and remove chunk 1 from queue 1 (3 times) */
    cio_queue_chunk_add(ctx, q1, c1);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    cio_queue_chunk_del(ctx, q1, c1);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    cio_queue_chunk_add(ctx, q1, c1);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* add chunks 1, 2 and 3 to queue 2 */
    cio_queue_chunk_add(ctx, q2, c1);
    cio_queue_chunk_add(ctx, q2, c2);
    cio_queue_chunk_add(ctx, q2, c3);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* write some data to c2 */
    cio_chunk_write(c2, page, sizeof(page));
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* note: sync alter the chunk size */
    cio_chunk_sync(c2);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* close and delete chunk 2 */
    cio_chunk_close(c2, CIO_TRUE);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* remove chunk 1 from queue 2 */
    cio_queue_chunk_del(ctx, q2, c1);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* chunk 4 to queue 1 */
    cio_queue_chunk_add(ctx, q1, c4);
    TEST_CHECK(cio_stats_validate(ctx) == 0);

        /* add chunk to queue */
        //qch = cio_queue_chunk_add(ctx, qarr[i], carr[i]);
        //TEST_CHECK(qch != NULL);

        /* write some data */
        //cio_chunk_write(carr[i], in_data, in_size);
        //written += in_size;
        //cio_chunk_sync(carr[i]);

    /* Delete one chunk, this should remove 'up' and 'down' */
    //cio_chunk_close(carr[0], CIO_FALSE);
    //TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Chunk down */
    //cio_chunk_down(carr[1]);
    //TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Chunk up */
    //cio_chunk_up(carr[1]);
    //TEST_CHECK(cio_stats_validate(ctx) == 0);

    /* Release file data and destroy context */
    free(in_data);
    cio_destroy(ctx);
}

void test_size_check_fs()
{
    test_size_check_type(CIO_STORE_FS);
}

void test_size_check_mem()
{
    test_size_check_type(CIO_STORE_MEM);
}

TEST_LIST = {
    {"queues"        ,   test_queues},
    {"size_check_fs" ,   test_size_check_fs},
    {"size_check_mem",   test_size_check_mem},
    { 0 }
};
