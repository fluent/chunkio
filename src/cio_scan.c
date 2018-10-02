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
#include <sys/types.h>
#include <dirent.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_log.h>

static int cio_scan_stream_files(struct cio_ctx *ctx, struct cio_stream *st)
{
    int len;
    int ret;
    char *path;
    DIR *dir;
    struct dirent *ent;
    struct cio_file *cf;

    len = strlen(ctx->root_path) + strlen(st->name) + 2;
    path = malloc(len);
    if (!path) {
        cio_errno();
        return -1;
    }

    ret = snprintf(path, len, "%s/%s", ctx->root_path, st->name);
    if (ret == -1) {
        cio_errno();
        free(path);
        return -1;
    }

    dir = opendir(path);
    if (!dir) {
        cio_errno();
        return -1;
    }

    cio_log_debug(ctx, "[cio scan] opening stream %s", st->name);

    /* Iterate the root_path */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') || (strcmp(ent->d_name, "..") == 0)) {
            continue;
        }

        /* Look just for directories */
        if (ent->d_type != DT_REG) {
            continue;
        }

        /* register every directory as a stream */
        cf = cio_file_open(ctx, st, ent->d_name, CIO_OPEN_RD, 0);
    }

    return 0;
}

/* Given a cio context, scan it root_path and populate stream/files */
int cio_scan_streams(struct cio_ctx *ctx)
{
    int ret;
    DIR *dir;
    struct dirent *ent;
    struct cio_stream *st;
    struct cio_file *cf;

    dir = opendir(ctx->root_path);
    if (!dir) {
        cio_errno();
        return -1;
    }

    cio_log_debug(ctx, "[cio scan] opening path %s", ctx->root_path);

    /* Iterate the root_path */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') || (strcmp(ent->d_name, "..") == 0)) {
            continue;
        }

        /* Look just for directories */
        if (ent->d_type != DT_DIR) {
            continue;
        }

        /* register every directory as a stream */
        st = cio_stream_create(ctx, ent->d_name);
        if (st) {
            ret = cio_scan_stream_files(ctx, st);
        }
    }

    return 0;
}
