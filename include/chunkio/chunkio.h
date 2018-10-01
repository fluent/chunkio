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

#ifndef CHUNKIO_H
#define CHUNKIO_H

#include <monkey/mk_core/mk_list.h>

#define CIO_FALSE   0
#define CIO_TRUE   !0

/* debug levels */
#define CIO_ERROR  1
#define CIO_WARN   2
#define CIO_INFO   3
#define CIO_DEBUG  4

struct cio_ctx {
    char *root_path;

    /* logging */
    int log_level;
    void (*log_cb)(void *, const char *, int, const char *);

    /* streams */
    struct mk_list streams;
};

struct cio_ctx *cio_create(const char *root_path,
                           void (*log_cb), int log_level);
void cio_destroy(struct cio_ctx *ctx);

int cio_set_log_callback(struct cio_ctx *ctx, void (*log_cb));
int cio_set_log_level(struct cio_ctx *ctx, int level);

#endif
