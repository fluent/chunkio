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
#include <getopt.h>
#include <string.h>

#include <chunkio/chunkio.h>

static void cio_help(int rc)
{
    printf("Usage: cio [OPTION]\n\n");
    printf("Available Options\n");
    printf("  -r, --root[=PATH]\tset root path\n");
    printf("  -h, --help\t\tprint this help\n");
    exit(rc);
}

int main(int argc, char **argv)
{
    int ret;
    int opt;
    int optid = 1;
    char *root_path = NULL;
    struct cio_ctx *ctx;

    static const struct option long_opts[] = {
        {"root"       , required_argument, NULL, 'r'},
        {"help"       , no_argument      , NULL, 'h'},
    };

    while ((opt = getopt_long(argc, argv, "r:h",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'r':
            root_path = strdup(optarg);
            break;
        case 'h':
            cio_help(EXIT_SUCCESS);
            break;
        default:
            cio_help(EXIT_FAILURE);
        }
    }

    if (!root_path) {
        fprintf(stderr, "[chunkio cli] root path is not defined\n");
        exit(EXIT_FAILURE);
    }

    ctx = cio_create(root_path);
    free(root_path);

    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    cio_destroy(ctx);
    return 0;
}
