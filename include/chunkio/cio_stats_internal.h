/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2019-2021 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_STATS_INTERNAL_H
#define CIO_STATS_INTERNAL_H

#include <unistd.h>

/* stats */
struct cio_stats_chunks {
    size_t chunks_total;             /* number of chunks */
    size_t chunks_bytes_total;       /* number of bytes used by chunks */

    size_t chunks_up_total;          /* number of chunks UP in memory */
    size_t chunks_up_bytes_total;    /* number of bytes used by chunks UP in memory */

    size_t chunks_down_total;        /* number of chunks DOWN in file system */
    size_t chunks_down_bytes_total;  /* number of bytes chunks DOWN in file system */
};

/* Global Stats */
struct cio_stats {
    /* Streams */
    size_t streams_total;        /* total number of registered streams */

    /* overall stats for all chunks / global view */
    struct cio_stats_chunks stats;
};

#endif
