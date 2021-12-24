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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_info.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_queue.h>

/*
 * Queue Stats Management: we implement specific stats functions here since the
 * main 'stats' are not aware about 'when' a chunk is associated to a queue.
 */
static void stats_queue_chunk_add(struct cio_ctx *ctx, struct cio_queue *queue,
                                  struct cio_chunk *ch)
{
    int is_up;
    size_t size;
    struct cio_stats_chunks *stats;

    stats = &queue->stats;
    stats->chunks_total++;

    size = cio_chunk_get_real_size(ch);
    stats->chunks_bytes_total += size;

    is_up = cio_chunk_is_up(ch);
    if (is_up) {
        stats->chunks_up_total++;
        stats->chunks_up_bytes_total += size;
    }
    else {
        stats->chunks_down_total++;
        stats->chunks_down_bytes_total += size;
    }
}

static void stats_queue_chunk_del(struct cio_ctx *ctx, struct cio_queue *queue,
                                  struct cio_chunk *ch)
{
    int is_up;
    size_t size;
    struct cio_stats_chunks *stats;

    stats = &queue->stats;
    stats->chunks_total--;

    size = cio_chunk_get_real_size(ch);
    stats->chunks_bytes_total -= size;

    is_up = cio_chunk_is_up(ch);
    if (is_up) {
        stats->chunks_up_total--;
        stats->chunks_up_bytes_total -= size;
    }
    else {
        stats->chunks_down_total--;
        stats->chunks_down_bytes_total -= size;
    }
}

/*
 * For a given chunk (ch), add a reference to 'queue' by adding an entry
 * into the list 'struct cio_chunk->queues'.
 */
static struct cio_chunk_queue *chunk_queue_link(struct cio_chunk *ch,
                                                struct cio_queue *queue)
{
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    /* check if the chunk was already linked to the queue */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        if (ch_queue->queue == queue) {
            return NULL;
        }
    }

    ch_queue = malloc(sizeof(struct cio_chunk_queue));
    if (!ch_queue) {
        cio_errno();
        return NULL;
    }

    ch_queue->queue = queue;
    mk_list_add(&ch_queue->_head, &ch->queues);

    return ch_queue;
}

static int chunk_queue_unlink(struct cio_chunk *ch, struct cio_queue *queue)
{
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue = NULL;

    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        if (ch_queue->queue == queue) {
            break;
        }
        ch_queue = NULL;
    }

    if (!ch_queue) {
        return -1;
    }

    mk_list_del(&ch_queue->_head);
    free(ch_queue);

    return 0;
}

/* Add a chunk to a specific queue */
struct cio_queue_chunk *cio_queue_chunk_add(struct cio_ctx *ctx,
                                            struct cio_queue *queue,
                                            struct cio_chunk *ch)
{
    struct cio_chunk_queue *ch_queue;
    struct cio_queue_chunk *qch;

    ch_queue = chunk_queue_link(ch, queue);
    if (!ch_queue) {
        return NULL;
    }

    qch = malloc(sizeof(struct cio_queue_chunk));
    if (!qch) {
        cio_errno();
        return NULL;
    }
    qch->chunk = ch;
    mk_list_add(&qch->_head, &queue->chunks);

    /* stats */
    stats_queue_chunk_add(ctx, queue, ch);
    return qch;
}

int cio_queue_chunk_del(struct cio_ctx *ctx, struct cio_queue *queue,
                        struct cio_chunk *ch)
{
    struct mk_list *head;
    struct cio_queue_chunk *qch;

    /* Lazy linear search */
    mk_list_foreach(head, &queue->chunks) {
        qch = mk_list_entry(head, struct cio_queue_chunk, _head);
        if (qch->chunk == ch) {
            break;
        }
        qch = NULL;
    }

    if (!qch) {
        return -1;
    }

    /* stats */
    stats_queue_chunk_del(ctx, queue, ch);

    chunk_queue_unlink(ch, queue);
    mk_list_del(&qch->_head);
    free(qch);

    return 0;
}

/* Delete a chunk reference from all queues it's associated */
int cio_queue_chunk_del_all(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    /* iterate chunk queues */
    mk_list_foreach_safe(head, tmp, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);

        /* remove chunk back reference (queue to chunk) */
        cio_queue_chunk_del(ctx, ch_queue->queue, ch);
    }

    return 0;
}

struct cio_queue *cio_queue_create(struct cio_ctx *ctx, char *name)
{
    struct cio_queue *q;

    q = calloc(1, sizeof(struct cio_queue));
    if (!q) {
        cio_errno();
        return NULL;
    }

    q->name = strdup(name);
    if (!q->name) {
        cio_errno();
        free(q);
        return NULL;
    }

    mk_list_init(&q->chunks);
    mk_list_add(&q->_head, &ctx->queues);
    return q;
}

void cio_queue_destroy(struct cio_ctx *ctx, struct cio_queue *queue)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_queue_chunk *qch;

    /* remove queue chunks */
    mk_list_foreach_safe(head, tmp, &queue->chunks) {
        qch = mk_list_entry(head, struct cio_queue_chunk, _head);
        cio_queue_chunk_del(ctx, queue, qch->chunk);
    }

    mk_list_del(&queue->_head);
    free(queue->name);
    free(queue);
}

void cio_queue_destroy_all(struct cio_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_queue *queue;

    mk_list_foreach_safe(head, tmp, &ctx->queues) {
        queue = mk_list_entry(head, struct cio_queue, _head);
        cio_queue_destroy(ctx, queue);
    }
}
