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

#ifndef CIO_FILE_H
#define CIO_FILE_H

#include <chunkio/cio_file_st.h>
#include <chunkio/cio_crc32.h>

struct cio_file {
    int fd;                   /* file descriptor      */
    int flags;                /* open flags */
    int synced;               /* sync after latest write ? */
    int mapped;               /* is the file content mapped ? */
    size_t fs_size;           /* original size in the file system */
    size_t data_size;         /* number of bytes used */
    size_t alloc_size;        /* allocated size       */
    size_t realloc_size;      /* chunk size to increase alloc */
    char *name;               /* name of file         */
    char *path;               /* root path + stream   */
    char *map;                /* map of data          */

    /* cached addr */
    char *st_content;
    crc_t crc_cur;

    struct cio_ctx *ctx;      /* library context      */
    struct cio_stream *st;    /* stream context       */
    struct mk_list _head;     /* head link to stream->files */
};

struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               const char *name,
                               int flags,
                               size_t size);
void cio_file_close(struct cio_file *cf);
int cio_file_write(struct cio_file *cf, const void *buf, size_t count);
int cio_file_sync(struct cio_file *cf);
int cio_file_close_stream(struct cio_stream *st);
char *cio_file_hash(struct cio_file *cf);
void cio_file_hash_print(struct cio_file *cf);

#endif
