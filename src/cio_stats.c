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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_stats.h>
#include <chunkio/cio_macros.h>
#include <chunkio/cio_queue.h>

void cio_stats_init(struct cio_stats_chunks *sc)
{
    memset(sc, 0, sizeof(struct cio_stats_chunks));
}

static void stats_print(struct cio_stats_chunks *stats)
{
    printf("  - chunks_total           : %lu\n", stats->chunks_total);
    printf("  - chunks_bytes_total     : %lu\n", stats->chunks_bytes_total);
    printf("  - chunks_up_total        : %lu\n", stats->chunks_up_total);
    printf("  - chunks_up_bytes_total  : %lu\n", stats->chunks_up_bytes_total);
    printf("  - chunks_down_total      : %lu\n", stats->chunks_down_total);
    printf("  - chunks_down_bytes_total: %lu\n", stats->chunks_down_bytes_total);
}

void cio_stats_print_summary(struct cio_ctx *ctx)
{
    struct mk_list *head;
    struct cio_stream *st;

    /* global stats */
    printf("======== Chunk I/O Stats ========\n");
    printf("  - streams total          : %lu\n", ctx->stats.streams_total);
    stats_print(&ctx->stats.stats);

    /* stream stats */
    mk_list_foreach(head, &ctx->streams) {
        st = mk_list_entry(head, struct cio_stream, _head);
        printf("=== Stream: %s ===\n", st->name);
        stats_print(&st->stats);
    }
}

/* streams */
void cio_stats_stream_create(struct cio_ctx *ctx, struct cio_stream *st)
{
    /* initialize stream stats */
    cio_stats_init(&st->stats);

    /* increment total counter of streams */
    ctx->stats.streams_total++;
}

void cio_stats_stream_destroy(struct cio_ctx *ctx)
{
    /* decrease the number of streams */
    ctx->stats.streams_total--;
}

static inline void stats_chunk_bytes_add(struct cio_stats_chunks *stats,
                                         size_t bytes, int is_up, int type)
{
    stats->chunks_bytes_total += bytes;

    if (is_up) {
        stats->chunks_up_bytes_total += bytes;
    }
    else {
        stats->chunks_down_bytes_total += bytes;
    }
}

static inline void stats_chunk_bytes_sub(struct cio_stats_chunks *stats,
                                         size_t bytes, int is_up, int type)
{
    stats->chunks_bytes_total -= bytes;

    if (is_up) {
        stats->chunks_up_bytes_total -= bytes;
    }
    else {
        stats->chunks_down_bytes_total -= bytes;
    }
}


static inline void stats_chunk_close(struct cio_stats_chunks *stats,
                                     size_t bytes_total, int is_up, int type)
{
    /* Chunks */
    stats->chunks_total--;

    if (is_up) {
        stats->chunks_up_total--;
    }
    else {
        stats->chunks_down_total--;
    }

    /* update all 'bytes_total' */
    stats_chunk_bytes_sub(stats, bytes_total, is_up, type);
}

static void last_size_set(struct cio_ctx *ctx, struct cio_chunk *ch, size_t size)
{
    ch->last_size = size;
}

static size_t last_size_get(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    return ch->last_size;
}

static void stats_chunk_down_add(struct cio_ctx *ctx, struct cio_chunk *ch,
                                 size_t bytes)
{
    struct cio_stream *st;
    struct cio_stats_chunks *stats;
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    /* global */
    stats = &ctx->stats.stats;
    stats->chunks_down_total++;
    stats->chunks_down_bytes_total += bytes;

    /* stream */
    st = ch->st;
    stats = &st->stats;
    stats->chunks_down_total++;
    stats->chunks_down_bytes_total += bytes;

    /* queues */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        stats = &ch_queue->queue->stats;
        stats->chunks_down_total++;
        stats->chunks_down_bytes_total += bytes;
    }
}

static void stats_chunk_down_dec(struct cio_ctx *ctx, struct cio_chunk *ch,
                                 size_t bytes)
{
    struct cio_stream *st;
    struct cio_stats_chunks *stats;
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    /* global */
    stats = &ctx->stats.stats;
    stats->chunks_down_total--;
    stats->chunks_down_bytes_total -= bytes;

    /* stream */
    st = ch->st;
    stats = &st->stats;
    stats->chunks_down_total--;
    stats->chunks_down_bytes_total -= bytes;

    /* queues */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        stats = &ch_queue->queue->stats;
        stats->chunks_down_total--;
        stats->chunks_down_bytes_total -= bytes;
    }
}

static void stats_chunk_up_add(struct cio_ctx *ctx, struct cio_chunk *ch,
                               size_t bytes)
{
    struct cio_stream *st;
    struct cio_stats_chunks *stats;
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    /* global */
    stats = &ctx->stats.stats;
    stats->chunks_up_total++;
    stats->chunks_up_bytes_total += bytes;

    /* stream */
    st = ch->st;
    stats = &st->stats;
    stats->chunks_up_total++;
    stats->chunks_up_bytes_total += bytes;

    /* queues */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        stats = &ch_queue->queue->stats;
        stats->chunks_up_total++;
        stats->chunks_up_bytes_total += bytes;
    }
}

static void stats_chunk_up_dec(struct cio_ctx *ctx, struct cio_chunk *ch,
                               size_t bytes)
{
    struct cio_stream *st;
    struct cio_stats_chunks *stats;
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    /* global */
    stats = &ctx->stats.stats;
    stats->chunks_up_total--;
    stats->chunks_up_bytes_total -= bytes;

    /* stream */
    st = ch->st;
    stats = &st->stats;
    stats->chunks_up_total--;
    stats->chunks_up_bytes_total -= bytes;

    /* queues */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        stats = &ch_queue->queue->stats;
        stats->chunks_up_total--;
        stats->chunks_up_bytes_total -= bytes;
    }
}

void cio_stats_chunk_init(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    int is_up;
    ssize_t bytes;
    struct cio_stream *st;
    struct cio_stats_chunks *stats;
    struct mk_list *head;
    struct cio_chunk_queue *ch_queue;

    bytes = cio_chunk_get_real_size(ch);
    if (bytes < 0) {
        return;
    }

    /* stream: update the stream stats for the chunk stream owner */
    st = ch->st;
    stats = &st->stats;
    stats->chunks_total++;
    stats->chunks_bytes_total += bytes;

    /* update global and stream 'up'/'down' counters */
    is_up = cio_chunk_is_up(ch);
    if (is_up) {
        stats_chunk_up_add(ctx, ch, bytes);
    }
    else {
        stats_chunk_down_add(ctx, ch, bytes);
    }

    /* queues */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        stats = &ch_queue->queue->stats;
        stats->chunks_total++;
        stats->chunks_bytes_total += bytes;
    }

}

/* chunks: when a chunk is opened or created */
void cio_stats_chunk_open(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    ssize_t size;
    struct cio_stats_chunks *stats = &ctx->stats.stats;

    /* get real size (bytes) of the chunk */
    size = cio_chunk_get_real_size(ch);
    if (size < 0) {
        size = 0;
    }

    /* set last size reported */
    last_size_set(ctx, ch, size);

    /* global */
    stats->chunks_total++;

    /* Initialize (stream type) */
    cio_stats_chunk_init(ctx, ch);
}

void cio_stats_chunk_close(struct cio_ctx *ctx, struct cio_chunk *ch)

{
    int is_up;
    ssize_t size;
    struct cio_stream *st = ch->st;

    /* get real size (bytes) of the chunk */
    size = last_size_get(ctx, ch);

    /* is the chunk 'up' ? */
    is_up = cio_chunk_is_up(ch);

    /* global */
    stats_chunk_close(&ctx->stats.stats, size, is_up, st->type);

    /* stream */
    stats_chunk_close(&st->stats, size, is_up, st->type);

    /*
     * queues: the cleanup of queues associated to the chunk are performed
     * by cio_chunk_close() right after this call.
     */
}

/*
 * Sets the new size of the chunk (last_size) and perform the adjustment
 * in the stream and chunk stats structures.
 */
void cio_stats_chunk_size_set(struct cio_ctx *ctx, struct cio_chunk *ch,
                              size_t new_size)
{
    int is_up;
    struct cio_stream *st = ch->st;
    size_t old_size;
    struct mk_list *head;
    struct cio_queue *queue;
    struct cio_chunk_queue *ch_queue;

    old_size = last_size_get(ctx, ch);
    last_size_set(ctx, ch, new_size);

    is_up = cio_chunk_is_up(ch);

    /* removing old bytes */
    stats_chunk_bytes_sub(&st->stats, old_size, is_up, st->type);
    stats_chunk_bytes_sub(&ctx->stats.stats, old_size, is_up, st->type);

    /* adding new bytes */
    stats_chunk_bytes_add(&st->stats, new_size, is_up, st->type);
    stats_chunk_bytes_add(&ctx->stats.stats, new_size, is_up, st->type);

    /* remove and add bytes to queues */
    mk_list_foreach(head, &ch->queues) {
        ch_queue = mk_list_entry(head, struct cio_chunk_queue, _head);
        queue = ch_queue->queue;
        stats_chunk_bytes_sub(&queue->stats, old_size, is_up, st->type);
        stats_chunk_bytes_add(&queue->stats, new_size, is_up, st->type);
    }
}

/* A chunk is being set to an 'up' state */
void cio_stats_chunk_up(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    ssize_t bytes;

    bytes = last_size_get(ctx, ch);

    /*
     * the chunk is moving from 'down' to 'up', decrement 'down bytes' and
     * add them to 'up bytes'
     */
    stats_chunk_down_dec(ctx, ch, bytes);
    stats_chunk_up_add(ctx, ch, bytes);
}

/* A chunk is being set to a 'down' state */
void cio_stats_chunk_down(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    int is_up;
    ssize_t bytes;

    is_up = cio_chunk_is_up(ch);
    if (!is_up) {
        return;
    }

    bytes = last_size_get(ctx, ch);

    /*
     * the chunk is moving from 'up' to 'down', decrement 'up bytes' and
     * add them to 'down bytes'
     */
    stats_chunk_up_dec(ctx, ch, bytes);
    stats_chunk_down_add(ctx, ch, bytes);
}

static void print_error(const char *file, int line, int scope, const char *fmt, ...)
{
    int ret;
    va_list args;
    char buf[1024];
    char *s;

    va_start(args, fmt);
    ret = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    if (ret >= 0) {
        buf[ret] = '\0';
    }
    va_end(args);

    if (scope == CIO_STATS_GLOBAL) {
        s = "GLOBAL";
    }
    else if (scope == CIO_STATS_STREAM) {
        s = "STREAM";
    }
    else if (scope == CIO_STATS_QUEUE) {
        s = "QUEUE";
    }

    fprintf(stderr, "[%s%s cio stats exception%s] %s:%i: %s\n",
            CIO_ANSI_RED, s, CIO_ANSI_RESET, file, line, buf);
}

#define STATS_ERROR(scope, fmt, ...) \
    print_error(__FILENAME__, __LINE__, scope, fmt, ##__VA_ARGS__)

static int stats_chunk_validate(struct cio_ctx *ctx, struct cio_stats_chunks *sc,
                                struct cio_stream *st, struct cio_queue *queue,
                                int scope)
{
    int ret_code = 0;
    ssize_t s;

    /* same counters as struct cio_stats_chunks */
    size_t chunks_total = 0;            /* number of chunks */
    size_t chunks_bytes_total = 0;      /* number of bytes used by chunks */

    size_t chunks_up_total = 0;         /* number of chunks UP in memory */
    size_t chunks_up_bytes_total = 0;   /* number of bytes used by chunks UP in memory */

    size_t chunks_down_total = 0;       /* number of chunks DOWN in file system */
    size_t chunks_down_bytes_total = 0; /* number of bytes chunks DOWN in file system */
    /* --- */

    struct mk_list *head;
    struct mk_list *s_head;
    struct cio_chunk *ch;
    struct cio_queue_chunk *qch;

    if (scope == CIO_STATS_GLOBAL) {
        /* iterate all streams */
        mk_list_foreach(head, &ctx->streams) {
            st = mk_list_entry(head, struct cio_stream, _head);

            /* count number of chunks per stream */
            chunks_total += mk_list_size(&st->chunks);

            /* count the total number of bytes used by chunks */
            mk_list_foreach(s_head, &st->chunks) {
                ch = mk_list_entry(s_head, struct cio_chunk, _head);

                /* get the real size (bytes) reported */
                s = cio_chunk_get_real_size(ch);
                if (s < 0) {
                    STATS_ERROR(scope,
                                "(chunks_total) chunk %s reports bad size: %i",
                                ch->name, s);
                    continue;
                }
                chunks_bytes_total += s;

                /* counters for chunks 'up/down' */
                if (cio_chunk_is_up(ch)) {
                    /* up */
                    chunks_up_total++;
                    chunks_up_bytes_total += s;
                }
                else {
                    /* down */
                    chunks_down_total++;
                    chunks_down_bytes_total += s;
                }
            }
        }
    }
    else if (scope == CIO_STATS_STREAM) {
        /* count number of chunks per stream */
        chunks_total += mk_list_size(&st->chunks);

        /* count the total number of bytes used by chunks */
        mk_list_foreach(s_head, &st->chunks) {
            ch = mk_list_entry(s_head, struct cio_chunk, _head);

            /* get the real size (bytes) reported */
            s = cio_chunk_get_real_size(ch);
            if (s < 0) {
                STATS_ERROR(scope,
                            "(chunks_total) chunk %s reports bad size: %i",
                            ch->name, s);
                continue;
            }
            chunks_bytes_total += s;

            /* counters for chunks 'up/down' */
            if (cio_chunk_is_up(ch)) {
                /* up */
                chunks_up_total++;
                chunks_up_bytes_total += s;
            }
            else {
                /* down */
                chunks_down_total++;
                chunks_down_bytes_total += s;
            }
        }
    }
    else if (scope == CIO_STATS_QUEUE) {
        /* count number of chunks per stream */
        chunks_total += mk_list_size(&queue->chunks);

        /* count the total number of bytes used by chunks */
        mk_list_foreach(s_head, &queue->chunks) {
            qch = mk_list_entry(s_head, struct cio_queue_chunk, _head);
            ch = qch->chunk;

            /* get the real size (bytes) reported */
            s = cio_chunk_get_real_size(ch);
            if (s < 0) {
                STATS_ERROR(scope,
                            "(chunks_total) chunk %s reports bad size: %i",
                            ch->name, s);
                continue;
            }
            chunks_bytes_total += s;

            /* counters for chunks 'up/down' */
            if (cio_chunk_is_up(ch)) {
                /* up */
                chunks_up_total++;
                chunks_up_bytes_total += s;
            }
            else {
                /* down */
                chunks_down_total++;
                chunks_down_bytes_total += s;
            }
        }
    }

    /* chunks_total */
    if (chunks_total != sc->chunks_total) {
        STATS_ERROR(scope, "(chunks_total) current=%i, expected=%i",
                    sc->chunks_total, chunks_total);
        ret_code = -1;
    }

    /* chunks_bytes_total */
    if (chunks_bytes_total != sc->chunks_bytes_total) {
        STATS_ERROR(scope, "(chunks_bytes_total) current=%i, expected=%i",
                    sc->chunks_bytes_total, chunks_bytes_total);
        ret_code = -1;
    }

    /* chunks_up_total */
    if (chunks_up_total != sc->chunks_up_total) {
        STATS_ERROR(scope, "(chunks_up_total) current=%i, expected=%i",
                    sc->chunks_up_total, chunks_up_total);
        ret_code = -1;
    }

    /* chunks_up_bytes_total */
    if (chunks_up_bytes_total != sc->chunks_up_bytes_total) {
        STATS_ERROR(scope, "(chunks_up_bytes_total) current=%i, expected=%i",
                    sc->chunks_up_bytes_total, chunks_up_bytes_total);
        ret_code = -1;
    }

    /* chunks_down_total */
    if (chunks_down_total != sc->chunks_down_total) {
        STATS_ERROR(scope, "(chunks_down_total) current=%i, expected=%i",
                    sc->chunks_down_total, chunks_down_total);
        ret_code = -1;
    }

    /* chunks_down_bytes_total */
    if (chunks_down_bytes_total != sc->chunks_down_bytes_total) {
        STATS_ERROR(scope, "(chunks_down_bytes_total) current=%i, expected=%i",
                    sc->chunks_down_bytes_total, chunks_down_bytes_total);
        ret_code = -1;
    }

    return ret_code;
}

/*
 * Validate the 'stats' auto-populated by doing a live check of 'current'
 * versus 'expected' values.
 */
int cio_stats_validate(struct cio_ctx *ctx)
{
    int ret;
    int ret_code = 0;
    int total;
    struct mk_list *head;
    struct cio_stream *st;
    struct cio_stats *stats;
    struct cio_stats_chunks *sc;
    struct cio_queue *queue;

    /*
     * Global Stats
     * ------------
     */

    /* cio_stats->streams_total */
    stats = &ctx->stats;
    total = mk_list_size(&ctx->streams);
    if (total != stats->streams_total) {
        STATS_ERROR(CIO_STATS_GLOBAL, "(streams_total) current=%i, expected=%i\n",
                    total, stats->streams_total);
        ret_code = -1;
    }

    /* cio_stats->stats (global chunk stats) */
    sc = &stats->stats;
    ret = stats_chunk_validate(ctx, sc, NULL, NULL, CIO_STATS_GLOBAL);
    if (ret == -1) {
        ret_code = -1;
    }

    /*
     * Stream Stats
     * ------------
     */
    mk_list_foreach(head, &ctx->streams) {
        st = mk_list_entry(head, struct cio_stream, _head);
        sc = &st->stats;
        ret = stats_chunk_validate(ctx, sc, st, NULL, CIO_STATS_STREAM);
        if (ret == -1) {
            ret_code = -1;
        }
    }

    /*
     * Queues Stats
     * ------------
     */
    mk_list_foreach(head, &ctx->queues) {
        queue = mk_list_entry(head, struct cio_queue, _head);
        sc = &queue->stats;
        ret = stats_chunk_validate(ctx, sc, NULL, queue, CIO_STATS_QUEUE);
        if (ret == -1) {
            ret_code = -1;
        }
    }

    return ret_code;
}
