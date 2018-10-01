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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               const char *name,
                               size_t size)
{
    int fd;
    int psize;
    int ret;
    char *path;
    struct cio_file *cf;
    (void) ctx;

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

    cf->name = strdup(name);
    if (!cf->name) {
        cio_errno();
        free(path);
        return NULL;
    }
    cf->path = path;
    mk_list_add(&cf->_head, &st->files);

    /* Open file descriptor */
    cf->fd = open(path, O_RDWR | O_CREAT, (mode_t) 0600);
    if (cf->fd == -1) {
        cio_errno();
        cio_log_error(ctx, "cannot open/create %s", path);
        cio_file_close(cf);
        return NULL;
    }

    /* Mmap */
    cf->map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   cf->fd, 0);
    if (cf->map == MAP_FAILED) {
        cio_errno();
        cf->map = NULL;
        cio_file_close(cf);
        return NULL;
    }

    /* Set size */
    ret = ftruncate(cf->fd, size);
    if (ret == -1) {
        cio_errno();
        cio_file_close(cf);
        return NULL;
    }

    cf->alloc_size = size;
    cf->data_size = 0;

    cio_log_debug(ctx, "%s:%s mapped OK", st->name, cf->name);

    return cf;
}

void cio_file_close(struct cio_file *cf)
{
    close(cf->fd);
    mk_list_del(&cf->_head);

    if (cf->map) {
        msync(cf->map, cf->alloc_size, MS_SYNC);
        munmap(cf->map, cf->alloc_size);
    }

    free(cf->name);
    free(cf->path);
    free(cf);
}

int cio_file_write(struct cio_file *cf, const void *buf, size_t count)
{
    if (cf->data_size + count > cf->alloc_size) {
        cio_log_error(cf->ctx,
                      "[chunkio file] data exceeds available space "
                      "(alloc=%lu current_size=%lu write_size=%lu)",
                      cf->alloc_size, cf->data_size, count);
        return -1;
    }

    memcpy(cf->map + cf->data_size, buf, count);
    cf->data_size += count;

    return 0;
}

int cio_file_sync(struct cio_file *cf)
{
    int ret;

    /* If there available space, truncate the file */
    if (cf->data_size < cf->alloc_size) {
        ret = ftruncate(cf->fd, cf->data_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(cf->ctx, "[chunkio file] error adjusting size");
        }
    }

    /* Commit changes to disk */
    ret = msync(cf->map, cf->data_size, MS_SYNC);
    if (ret == -1) {
        cio_errno();
        return -1;
    }

    return 0;
}
