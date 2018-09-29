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
#include <stdarg.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_debug.h>

void cio_debug_print(void *ctx, int level, const char *file, int line,
                     const char *fmt, ...)
{
    int ret;
    char buf[CIO_DEBUG_BUF_SIZE];
    va_list args;
    struct cio_ctx *cio = ctx;

    if (!cio->log_cb) {
       return;
    }

    if (level <= cio->log_level) {
        return;
    }

    va_start(args, fmt);
    ret = vsnprintf(buf, CIO_DEBUG_BUF_SIZE - 1, fmt, args);

    if (ret >= 0) {
        buf[ret] = '\n';
        buf[ret + 1] = '\0';
    }
    va_end(args);

    cio->log_cb(ctx, file, line, buf);
}
