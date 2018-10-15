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

#ifndef CIO_FILE_ST_H
#define CIO_FILE_ST_H

#include <stdlib.h>
#include <inttypes.h>

/*
 * ChunkIO data file layout as of 2018/10/05
 *
 * -  2 first bytes as identification: 0xC1 0x00
 * - 20 bytes of sha1 hash of content section
 * - Content section is composed by:
 *   - 2 bytes to specify the length of metadata
 *   - optional metadata
 *   - user data
 *
 *    +--------------+----------------+
 *    |     0xC1     |     0x00       +--> Header 2 bytes
 *    +--------------+----------------+
 *    |           20 BYTES            +--> SHA1(Content)
 *    +-------------------------------+
 *    |            Content            |
 *    |  +-------------------------+  |
 *    |  |         2 BYTES         +-----> Metadata Length
 *    |  +-------------------------+  |
 *    |  +-------------------------+  |
 *    |  |                         |  |
 *    |  |        Metadata         +-----> Optional Metadata (up to 65535 bytes)
 *    |  |                         |  |
 *    |  +-------------------------+  |
 *    |  +-------------------------+  |
 *    |  |                         |  |
 *    |  |       Content Data      +-----> User Data
 *    |  |                         |  |
 *    |  +-------------------------+  |
 *    +-------------------------------+
 */

#define CIO_FILE_ID_00          0xc1    /* header: first byte */
#define CIO_FILE_ID_01          0x00    /* header: second byte */
#define CIO_FILE_HEADER_MIN       24    /* 24 bytes for the header */
#define CIO_FILE_CONTENT_OFFSET   22

/* Return pointer to hash position */
static inline char *cio_file_st_get_hash(char *map)
{
    return map + 2;
}

/* Return pointer to metadata header */
static inline char *cio_file_st_get_meta_header(char *map)
{
    return map + 22;
}

/* Return metadata length */
static inline uint16_t cio_file_st_get_meta_len(char *map)
{
    return (uint16_t) (map[22] << 8) | map[23];
}

/* Return pointer to start point of metadata */
static inline char *cio_file_st_get_meta(char *map)
{
    return map + CIO_FILE_HEADER_MIN;
}

/* Return pointer to start point of content */
static inline char *cio_file_st_get_content(char *map)
{
    uint16_t len;

    len = cio_file_st_get_meta_len(map);
    return map + CIO_FILE_HEADER_MIN + len;
}

static inline ssize_t cio_file_st_get_content_size(char *map, size_t size)
{
    int meta_len;
    size_t s;

    if (size < CIO_FILE_HEADER_MIN) {
        return -1;
    }

    meta_len = cio_file_st_get_meta_len(map);
    s = abs((size - CIO_FILE_HEADER_MIN) - meta_len);
    if (s < size) {
        return s;
    }

    return -1;
}

#endif
