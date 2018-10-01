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

#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>

struct cio_file *cio_file_create(struct cio_ctx *ctx, size_t size)
{
    struct cio_file *cf;
    (void) ctx;

    cf = malloc(sizeof(struct cio_file));
    if (!cf) {
        perror("malloc");
        return NULL;
    }

    return cf;
}

int cio_file_destroy()
{

}

int cio_file_sync()
{

}
