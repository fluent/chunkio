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

#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_log.h>

#include <string.h>

struct cio_chunk *cio_chunk_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 const char *name, int flags, size_t size)
{
    int len;
    void *backend = NULL;
    struct cio_chunk *ch;

    if (!st) {
        cio_log_error(ctx, "[cio chunk] invalid stream");
        return NULL;
    }

    if (!name) {
        cio_log_error(ctx, "[cio chunk] invalid file name");
        return NULL;
    }

    len = strlen(name);
    if (len == 0) {
        cio_log_error(ctx, "[cio chunk] invalid file name");
        return NULL;
    }

    /* allocate chunk context */
    ch = malloc(sizeof(struct cio_chunk));
    if (!ch) {
        cio_errno();
        return NULL;
    }
    ch->name = strdup(name);
    ch->ctx = ctx;
    ch->st = st;
    mk_list_add(&ch->_head, &st->files);

    /* create backend context */
    if (st->type == CIO_STORE_FS) {
        backend = cio_file_open(ctx, st, ch, flags, size);
    }
    else if (st->type == CIO_STORE_MEM) {
        backend = cio_memfs_open(ctx, st, ch, flags, size);
    }

    if (!backend) {
        cio_log_error(ctx, "[cio chunk] error initializing backend file");
        free(ch->name);
        free(ch);
        return NULL;
    }

    ch->backend = backend;

    return ch;
}

void cio_chunk_close(struct cio_chunk *ch)
{
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        cio_file_close(ch);
    }
    else if (type == CIO_STORE_MEM) {
        cio_memfs_close(ch);
    }

    mk_list_del(&ch->_head);
    free(ch->name);
    free(ch);
}

int cio_chunk_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    int ret;
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_write(ch, buf, count);
    }
    else if (type == CIO_STORE_MEM) {
        ret = cio_memfs_write(ch, buf, count);
    }

    return ret;
}

int cio_chunk_sync(struct cio_chunk *ch)
{
    int ret = 0;
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_sync(ch);
    }

    return ret;
}

void cio_chunk_close_stream(struct cio_stream *st)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_chunk *ch;

    mk_list_foreach_safe(head, tmp, &st->files) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        if (st->type == CIO_STORE_FS) {
            cio_file_close(ch);
        }
        else if (st->type == CIO_STORE_MEM) {
            cio_memfs_close(ch);
        }
    }
}

char *cio_chunk_hash(struct cio_chunk *ch)
{
    if (ch->st->type == CIO_STORE_FS) {
        return cio_file_hash(ch->backend);
    }

    return NULL;
}

int cio_chunk_lock(struct cio_chunk *ch)
{
    if (ch->lock == CIO_TRUE) {
        return -1;
    }

    ch->lock = CIO_TRUE;
    return 0;
}

int cio_chunk_unlock(struct cio_chunk *ch)
{
    if (ch->lock == CIO_FALSE) {
        return -1;
    }

    ch->lock = CIO_FALSE;
    return 0;
}
