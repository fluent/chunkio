/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2019 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_STATS_H
#define CIO_STATS_H

#include <chunkio/chunkio.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_stats_internal.h>

#define CIO_STATS_GLOBAL   0
#define CIO_STATS_STREAM   1

void cio_stats_init(struct cio_stats_chunks *sc);
void cio_stats_get(struct cio_ctx *ctx, struct cio_stats *stats);
void cio_stats_print_summary(struct cio_ctx *ctx);

void cio_stats_stream_create(struct cio_ctx *ctx, struct cio_stream *st);
void cio_stats_stream_destroy(struct cio_ctx *ctx);

void cio_stats_chunk_size_set(struct cio_ctx *ctx, struct cio_chunk *ch,
                              size_t new_size);

/* Initialize the stream counters by checking the chunk 'up' or 'down' status */
void cio_stats_chunk_init(struct cio_ctx *ctx, struct cio_chunk *ch);

/* Open and close a chunk */
void cio_stats_chunk_open(struct cio_ctx *ctx, struct cio_chunk *ch);
void cio_stats_chunk_close(struct cio_ctx *ctx, struct cio_chunk *ch);

/* Chunk moves 'up' or 'down' */
void cio_stats_chunk_up(struct cio_ctx *ctx, struct cio_chunk *ch);
void cio_stats_chunk_down(struct cio_ctx *ctx, struct cio_chunk *ch);

int cio_stats_validate(struct cio_ctx *ctx);

#endif
