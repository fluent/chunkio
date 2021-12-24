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

#ifndef CIO_QUEUE_H
#define CIO_QUEUE_H

#include <chunkio/cio_info.h>
#include <chunkio/chunkio.h>

#include <chunkio/cio_stats.h>

/*
 * Queues main definitions and content
 * -----------------------------------
 */

struct cio_queue_chunk {
	struct cio_chunk *chunk;            /* ref to chunk */
	struct mk_list _head;               /* link for struct cio_queue->chunks */
};

struct cio_queue {
	char *name;
	struct cio_stats_chunks stats;      /* queue stats */
	struct mk_list chunks;              /* list of chunks (struct cio_queue_chunk) */
	struct mk_list _head;               /* link for struct cio_ctx->queues         */
};

/*
 * Reference for struct cio_chunk->queues
 * --------------------------------------
 */
struct cio_chunk_queue {
	struct cio_queue *queue;
	struct mk_list _head;
};

struct cio_queue *cio_queue_create(struct cio_ctx *ctx, char *name);
void cio_queue_destroy(struct cio_ctx *ctx, struct cio_queue *q);
void cio_queue_destroy_all(struct cio_ctx *ctx);

struct cio_queue_chunk *cio_queue_chunk_add(struct cio_ctx *ctx,
                                            struct cio_queue *queue,
                                            struct cio_chunk *ch);

int cio_queue_chunk_del(struct cio_ctx *ctx, struct cio_queue *queue,
                        struct cio_chunk *ch);
int cio_queue_chunk_del_all(struct cio_ctx *ctx, struct cio_chunk *ch);

#endif
