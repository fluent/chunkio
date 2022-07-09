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

#ifndef CIO_FILE_NATIVE_H
#define CIO_FILE_NATIVE_H

#include <chunkio/cio_file.h>

int cio_file_native_unmap(struct cio_file *cf);
int cio_file_native_map(struct cio_file *cf, size_t map_size);
int cio_file_native_remap(struct cio_file *cf, size_t new_size);
int cio_file_native_lookup_user(char *user, void **result);
int cio_file_native_lookup_group(char *group, void **result);
int cio_file_native_get_size(struct cio_file *cf, size_t *file_size);
int cio_file_native_open(struct cio_ctx *ctx, struct cio_file *cf);
void cio_file_native_close(struct cio_file *cf);
int cio_file_native_delete(struct cio_file *cf);
int cio_file_native_sync(struct cio_file *cf, int sync_mode);
int cio_file_native_resize(struct cio_file *cf, size_t new_size);

#endif
