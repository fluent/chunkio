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

#ifndef CIO_CHUNK_H
#define CIO_CHUNK_H

struct cio_chunk {
    int lock;                 /* locked for write operations ? */
    char *name;               /* chunk name */
    void *backend;            /* backend context (cio_file, cio_memfs) */
    struct cio_ctx *ctx;      /* library context      */
    struct cio_stream *st;    /* stream context       */
    struct mk_list _head;     /* head link to stream->files */
};

struct cio_chunk *cio_chunk_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 const char *name, int flags, size_t size);
void cio_chunk_close(struct cio_chunk *ch);
int cio_chunk_write(struct cio_chunk *ch, const void *buf, size_t count);
int cio_chunk_sync(struct cio_chunk *ch);
void cio_chunk_close_stream(struct cio_stream *st);
char *cio_chunk_hash(struct cio_chunk *ch);
int cio_chunk_lock(struct cio_chunk *ch);
int cio_chunk_unlock(struct cio_chunk *ch);

#endif
