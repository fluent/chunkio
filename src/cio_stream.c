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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_os.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

static int check_stream_path(struct cio_ctx *ctx, const char *path)
{
    int ret;
    int len;
    char *p;

    /* Compose final path */
    len = strlen(ctx->root_path) + strlen(path) + 2;
    p = malloc(len + 1);
    if (!p) {
        cio_errno();
        return -1;
    }
    ret = snprintf(p, len, "%s/%s", ctx->root_path, path);
    if (ret == -1) {
        cio_errno();
        free(p);
        return -1;
    }

    ret = cio_os_isdir(p);
    if (ret == -1) {
        /* Try to create the path */
        ret = cio_os_mkpath(p, 0755);
        if (ret == -1) {
            cio_log_error(ctx, "cannot create stream path %s", p);
            return -1;
        }
        cio_log_debug(ctx, "created stream path %s", p);
        return 0;
    }

    /* Directory already exists, check write access */
    return access(p, W_OK);
}

struct cio_stream *cio_stream_create(struct cio_ctx *ctx, const char *name)
{
    int ret;
    struct cio_stream *st;

    if (!name) {
        cio_log_error(ctx, "[stream create] stream name not set");
        return NULL;
    }

    ret = check_stream_path(ctx, name);
    if (ret == -1) {
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
