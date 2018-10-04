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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               const char *name,
                               int flags,
                               size_t size)
{
    int fd;
    int psize;
    int ret;
    int len;
    int oflags;
    char *path;
    struct cio_file *cf;
    struct stat fst;
    (void) ctx;

    if (!st) {
        cio_log_error(ctx, "[cio file] invalid stream");
        return NULL;
    }

    if (!name) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    len = strlen(name);
    if (len == 0) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    if (len == 1 && (name[0] == '.' || name[0] == '/')) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    /* Compose path for the file */
    psize = strlen(ctx->root_path) + strlen(st->name) + strlen(name);
    psize += 8;

    path = malloc(psize);
    if (!path) {
        cio_errno();
        return NULL;
    }

    ret = snprintf(path, psize, "%s/%s/%s",
                   ctx->root_path, st->name, name);
    if (ret == -1) {
        cio_errno();
        free(path);
        return NULL;
    }

    /* Create file context */
    cf = calloc(1, sizeof(struct cio_file));
    if (!cf) {
        cio_errno();
        free(path);
        return NULL;
    }
    cf->ctx = ctx;
    cf->flags = flags;
    cf->st = st;
    cf->realloc_size = getpagesize() * 8;

    cf->name = strdup(name);
    if (!cf->name) {
        cio_errno();
        free(path);
        return NULL;
    }
    cf->path = path;
    mk_list_add(&cf->_head, &st->files);

    /* Open file descriptor */
    if (flags & CIO_OPEN) {
        cf->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, (mode_t) 0600);
    }
    else if (flags & CIO_OPEN_RD) {
        cf->fd = open(path, O_RDONLY);
    }

    if (cf->fd == -1) {
        cio_errno();
        cio_log_error(ctx, "cannot open/create %s", path);
        cio_file_close(cf);
        return NULL;
    }

    if (flags & CIO_OPEN_RD) {
        /* Check if the file exists */
        ret = fstat(cf->fd, &fst);
        if (ret == 0 && fst.st_size >= 0) {
            /* override size, file might already exists */
            size = fst.st_size;
        }
    }

    /* Mmap */
    if (flags & CIO_OPEN) {
        oflags = PROT_READ | PROT_WRITE;
    }
    else if (flags & CIO_OPEN_RD) {
        oflags = PROT_READ;
    }

    cf->map = mmap(0, size, oflags, MAP_SHARED, cf->fd, 0);
    if (cf->map == MAP_FAILED) {
        cio_errno();
        cf->map = NULL;
        cio_file_close(cf);
        return NULL;
    }

    /* Set size */
    if (flags & CIO_OPEN) {
        ret = ftruncate(cf->fd, size);
        if (ret == -1) {
            cio_errno();
            cio_file_close(cf);
            return NULL;
        }
        cf->data_size = 0;
    }
    else if (flags & CIO_OPEN_RD) {
        cf->data_size = size;
        cf->synced = CIO_TRUE;
    }
    cf->alloc_size = size;

    cio_log_debug(ctx, "%s:%s mapped OK", st->name, cf->name);

    return cf;
}

void cio_file_close(struct cio_file *cf)
{
    int ret;

    /* check if the file needs to be synchronized */
    if (cf->synced == CIO_FALSE && cf->map) {
        ret = cio_file_sync(cf);
        if (ret == -1) {
            cio_log_error(cf->ctx,
                          "[cio file] error doing file sync on close at "
                          "%s:%s", cf->st->name, cf->name);
        }
    }

    /* unmap file */
    if (cf->map) {
        munmap(cf->map, cf->alloc_size);
    }

    close(cf->fd);
    mk_list_del(&cf->_head);
    free(cf->name);
    free(cf->path);
    free(cf);
}

int cio_file_write(struct cio_file *cf, const void *buf, size_t count)
{
    int ret;
    void *tmp;
    size_t av_size;
    size_t new_size;

    /* get available size */
    av_size = (cf->alloc_size - cf->data_size);

    /* validate there is enough space, otherwise resize */
    if (count > av_size) {
        if (av_size + cf->realloc_size < count) {
            new_size = count;
            cio_log_debug(cf->ctx,
                          "[cio file] realloc size is not big enough "
                          "for incoming data, consider to increase it");
        }
        else {
            new_size = cf->alloc_size + cf->realloc_size;
        }
        tmp = mremap(cf->map, cf->alloc_size,
                     new_size, MREMAP_MAYMOVE);
        if (tmp == MAP_FAILED) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio file] data exceeds available space "
                          "(alloc=%lu current_size=%lu write_size=%lu)",
                          cf->alloc_size, cf->data_size, count);
            return -1;
        }


        cf->map = tmp;
        cio_log_debug(cf->ctx,
                      "[cio file] alloc_size from %lu to %lu",
                      cf->alloc_size, new_size);
        cf->alloc_size = new_size;
        ret = ftruncate(cf->fd, cf->alloc_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio_file] error setting new file size on write");
            return -1;
        }
    }

    memcpy(cf->map + cf->data_size, buf, count);
    cf->data_size += count;
    cf->synced = CIO_FALSE;

    return 0;
}

int cio_file_sync(struct cio_file *cf)
{
    int ret;

    if (cf->flags & CIO_OPEN_RD) {
        return 0;
    }

    /* If there extra space, truncate the file size */
    if (cf->data_size < cf->alloc_size) {
        ret = ftruncate(cf->fd, cf->data_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio file sync] error adjusting size at: "
                          " %s/%s", cf->st->name, cf->name);
        }
        cf->alloc_size = cf->data_size;
    }

    /* Commit changes to disk */
    ret = msync(cf->map, cf->data_size, MS_SYNC);
    if (ret == -1) {
        cio_errno();
        return -1;
    }

    cf->synced = CIO_TRUE;
    cio_log_debug(cf->ctx, "[cio file] file synced at: %s/%s",
                  cf->st->name, cf->name);
    return 0;
}

/* Set a reallocation chunk size */
void cio_file_realloc_size(struct cio_file *cf, size_t chunk_size)
{
    cf->realloc_size = chunk_size;
}

/* Close all files owned by the given stream */
int cio_file_close_stream(struct cio_stream *st)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_file *cf;

    mk_list_foreach_safe(head, tmp, &st->files) {
        cf = mk_list_entry(head, struct cio_file, _head);
        cio_file_close(cf);
    }

    return 0;
}
