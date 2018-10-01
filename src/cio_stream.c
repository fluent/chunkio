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

#include <stdlib.h>
#include <string.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

struct cio_stream *cio_stream_create(struct cio_ctx *ctx, const char *name)
{
    struct cio_stream *st;

    if (!name) {
        cio_log_error(ctx, "[stream create] stream name not set");
        return NULL;
    }

    st = malloc(sizeof(struct cio_stream));
    if (!st) {
        cio_errno();
        return NULL;
    }

    st->name = strdup(name);
    if (!st->name) {
        cio_errno();
        free(st);
        return NULL;
    }

    st->parent = ctx;
    mk_list_init(&st->files);
    mk_list_add(&st->_head, &ctx->streams);

    return st;
}

void cio_stream_destroy(struct cio_stream *st)
{
    mk_list_del(&st->_head);
    free(st->name);
    free(st);
}
