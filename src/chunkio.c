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
#include <unistd.h>
#include <string.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_os.h>
#include <chunkio/cio_log.h>

/*
 * Validate if root_path exists, if don't, create it, otherwise
 * check if we have write access to it.
 */
static int check_root_path(const char *root_path)
{
    int ret;

    ret = cio_os_isdir(root_path);
    if (ret == -1) {
        /* Try to create the path */
        ret = cio_os_mkpath(root_path, 0755);
        if (ret == -1) {
            return -1;
        }
        return 0;
    }

    /* Directory already exists, check write access */
    return access(root_path, W_OK);
}

struct cio_ctx *cio_create(const char *root_path)
{
    int ret;
    struct cio_ctx *ctx;

    /* Check or initialize file system root path */
    ret = check_root_path(root_path);
    if (ret == -1) {
        fprintf(stderr,
                "[chunkio] cannot initialize root path %s\n",
                root_path);
        return NULL;
    }

    /* Create context */
    ctx = calloc(1, sizeof(struct cio_ctx));
    if (!ctx) {
        perror("calloc");
        return NULL;
    }

    ctx->root_path = strdup(root_path);
    if (!ctx->root_path) {
        perror("strdup");
        free(ctx);
        return NULL;
    }

    return ctx;
}

void cio_destroy(struct cio_ctx *ctx)
{
    free(ctx->root_path);
    free(ctx);
}

int cio_set_log_callback(struct cio_ctx *ctx, void (*log_cb))
{
    ctx->log_cb = log_cb;
}

int cio_set_log_level(struct cio_ctx *ctx, int level)
{
    ctx->log_level = level;
}
