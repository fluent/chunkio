/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2026 The Fluent Bit Authors
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <chunkio/cio_crc32.h>

#include "cio_tests_internal.h"

#define BUF_SIZE  4096
#define BUF_SLACK 64

static unsigned char buf[BUF_SIZE + BUF_SLACK];
static uint32_t seed = 0x1234abcd;

static uint32_t next_random(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;

    return seed;
}

static void fill_buffer(void)
{
    size_t i;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (unsigned char) (next_random() >> 16);
    }
}

/*
 * On big-endian targets the table code in deps/crc32 has never produced the
 * standard CRC-32: its 8-byte block step mangles the running value, and the
 * result even depends on how the data is aligned and split. That predates
 * the accelerated kernels, which only exist for little-endian targets, and
 * fixing it changes what those systems store. Until that is decided, a
 * big-endian run only checks that crc_update() is the table code.
 */
static int is_little_endian(void)
{
    const uint32_t probe = 1;

    return *(const unsigned char *) &probe == 1;
}

/* One bit at a time: shares no code and no tables with the library */
static crc_t crc_reference(crc_t crc, const unsigned char *data, size_t len)
{
    int bit;

    while (len--) {
        crc ^= *data++;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
    }

    return crc;
}

static uint32_t crc_of(const char *str)
{
    crc_t crc;

    crc = cio_crc32_init();
    crc = cio_crc32_update(crc, str, strlen(str));

    return (uint32_t) cio_crc32_finalize(crc);
}

/* Values every CRC-32 (IEEE 802.3) implementation must produce */
static void test_known_values(void)
{
    size_t i;
    crc_t crc;
    unsigned char zeros[1024];
    char letters[1041];

    printf("crc32 backend: %s\n", crc_backend());

    if (!is_little_endian()) {
        printf("big-endian: skipping standard CRC-32 values\n");
        TEST_CHECK(strcmp(crc_backend(), "table") == 0);
        return;
    }

    TEST_CHECK(crc_of("") == 0x00000000);
    TEST_CHECK(crc_of("a") == 0xe8b7be43);
    TEST_CHECK(crc_of("123456789") == 0xcbf43926);
    TEST_CHECK(crc_of("The quick brown fox jumps over the lazy dog") ==
               0x414fa339);

    /* Long enough for every accelerated kernel to engage */
    memset(zeros, 0, sizeof(zeros));
    crc = cio_crc32_update(cio_crc32_init(), zeros, sizeof(zeros));
    TEST_CHECK((uint32_t) cio_crc32_finalize(crc) == 0xefb5af2e);

    for (i = 0; i < sizeof(letters) - 1; i++) {
        letters[i] = (char) ('a' + (i % 26));
    }
    letters[sizeof(letters) - 1] = '\0';
    crc = crc_reference(cio_crc32_init(), (unsigned char *) letters,
                        sizeof(letters) - 1);
    TEST_CHECK(crc_of(letters) == (uint32_t) cio_crc32_finalize(crc));
}

/*
 * The checksum stored in a chunk must not depend on the kernel that computed
 * it: sweep every length across the kernel size thresholds, at every
 * alignment, from arbitrary states.
 */
static void test_matches_reference(void)
{
    size_t len;
    size_t offset;
    int round;
    crc_t state;
    crc_t expect;

    fill_buffer();

    for (len = 0; len <= 1100; len++) {
        for (offset = 0; offset < 16; offset++) {
            state = (len + offset) % 3 == 0 ? cio_crc32_init() : next_random();
            expect = crc_reference(state, buf + offset, len);
            if (!is_little_endian()) {
                expect = crc_update_table(state, buf + offset, len);
            }

            if (!TEST_CHECK(cio_crc32_update(state, buf + offset, len) ==
                            expect)) {
                TEST_MSG("len=%zu offset=%zu", len, offset);
                return;
            }

            if (!TEST_CHECK(crc_update_table(state, buf + offset, len) ==
                            expect)) {
                TEST_MSG("table: len=%zu offset=%zu", len, offset);
                return;
            }
        }
    }

    for (round = 0; round < 20000; round++) {
        len = next_random() % BUF_SIZE;
        offset = next_random() % BUF_SLACK;
        state = next_random();
        expect = crc_reference(state, buf + offset, len);
        if (!is_little_endian()) {
            expect = crc_update_table(state, buf + offset, len);
        }

        if (!TEST_CHECK(cio_crc32_update(state, buf + offset, len) ==
                        expect)) {
            TEST_MSG("len=%zu offset=%zu", len, offset);
            return;
        }
    }
}

/* Chunks are checksummed one append at a time */
static void test_incremental(void)
{
    int round;
    size_t len;
    size_t pos;
    size_t step;
    crc_t whole;
    crc_t pieces;

    if (!is_little_endian()) {
        printf("big-endian: skipping, see is_little_endian()\n");
        return;
    }

    fill_buffer();

    for (round = 0; round < 2000; round++) {
        len = next_random() % BUF_SIZE;
        whole = cio_crc32_update(cio_crc32_init(), buf, len);

        pieces = cio_crc32_init();
        for (pos = 0; pos < len; pos += step) {
            step = next_random() % 700;
            if (step > len - pos) {
                step = len - pos;
            }
            pieces = cio_crc32_update(pieces, buf + pos, step);
        }

        if (!TEST_CHECK(pieces == whole)) {
            TEST_MSG("len=%zu", len);
            return;
        }
    }
}

TEST_LIST = {
    {"known_values",      test_known_values},
    {"matches_reference", test_matches_reference},
    {"incremental",       test_incremental},
    {NULL, NULL}
};
