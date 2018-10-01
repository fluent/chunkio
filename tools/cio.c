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
#include <sys/types.h>
#include <pwd.h>
#include <limits.h>
#include <signal.h>

#define CIO_ROOT_PATH  ".cio"
#define cio_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n" , sizeof(#X ")\n")-1); \
    break;

#include <chunkio/chunkio.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_file.h>

static void cio_help(int rc)
{
    printf("Usage: cio -r PATH\n\n");
    printf("Available Options\n");
    printf("  -r, --root[=PATH]\tset root path\n");
    printf("  -i, --stdin\t\tdump stdin data to stream/file\n");
    printf("  -s, --stream=STREAM\tset stream name\n");
    printf("  -h, --help\t\tprint this help\n");
    exit(rc);
}

static void cio_signal_handler(int signal)
{
    char s[] = "[cio] caught signal (";

    /* write signal number */
    write(STDERR_FILENO, s, sizeof(s) - 1);
    switch (signal) {
        cio_print_signal(SIGINT);
        cio_print_signal(SIGQUIT);
        cio_print_signal(SIGHUP);
        cio_print_signal(SIGTERM);
        cio_print_signal(SIGSEGV);
    };

    /* Signal handlers */
    switch (signal) {
    case SIGINT:
    case SIGQUIT:
    case SIGHUP:
    case SIGTERM:
        _exit(EXIT_SUCCESS);
    case SIGSEGV:
        abort();
    default:
        break;
    }
}

static void cio_signal_init()
{
    signal(SIGINT,  &cio_signal_handler);
    signal(SIGQUIT, &cio_signal_handler);
    signal(SIGHUP,  &cio_signal_handler);
    signal(SIGTERM, &cio_signal_handler);
    signal(SIGSEGV, &cio_signal_handler);
}

static int log_cb(struct cio_ctx *ctx, const char *file, int line,
                  char *str)
{
    printf("[chunkio] %s:%i: %s", file, line, str);
}

static int cio_default_root_path(char *path, int size)
{
    int len;
    struct passwd *pw;

    pw = getpwuid(getuid());
    if (!pw) {
        perror("getpwuid");
        return -1;
    }

    /* ~/.cio */
    len = snprintf(path, size, "%s/%s",
                   pw->pw_dir, CIO_ROOT_PATH);
    if (len == -1) {
        perror("snprintf");
        return -1;
    }

    return 0;
}

static int cio_stdin(struct cio_ctx *ctx, const char *stream,
                     const char *fname)
{
    int fd;
    int ret;
    size_t total = 0;
    ssize_t bytes;
    char buf[4096];
    struct cio_stream *st;
    struct cio_file *cf;

    /* Prepare stream and file contexts */
    st = cio_stream_create(ctx, stream);
    if (!st) {
        fprintf(stderr, "[chunkio cli] cannot create stream\n");
        return -1;
    }

    cf = cio_file_open(ctx, st, fname, 1024*10*10*10*10);
    if (!cf) {
        fprintf(stderr, "[chunkio cli] cannot create file\n");
        return -1;
    }

    fd = dup(STDIN_FILENO);
    if (fd == -1) {
        perror("dup");
        fprintf(stderr, "[chunkio cli] cannot open standard input\n");
        return -1;
    }

    do {
        bytes = read(fd, buf, sizeof(buf) - 1);
        if (bytes == 0) {
            break;
        }
        else if (bytes == -1) {
            perror("read");
        }
        else {
            ret = cio_file_write(cf, buf, bytes);
            if (ret == -1) {
                fprintf(stderr, "[chunkio cli] error writing to file\n");
                close(fd);
                return -1;
            }
            total += bytes;
        }
    } while (bytes > 0);

    printf("total bytes read => %lu\n", total);
    close(fd);

    cio_file_sync(cf);

    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    int opt;
    int optid = 1;
    int in_stdin = CIO_FALSE;
    int verbose = CIO_INFO;
    char *fname = NULL;
    char *stream = NULL;
    char *root_path = NULL;
    char tmp[PATH_MAX];
    struct cio_ctx *ctx;

    static const struct option long_opts[] = {
        {"root"       , required_argument, NULL, 'r'},
        {"stdin"      , no_argument      , NULL, 'i'},
        {"stream"     , required_argument, NULL, 's'},
        {"verbose"    , no_argument      , NULL, 'v'},
        {"help"       , no_argument      , NULL, 'h'},
    };

    /* Initialize signals */
    cio_signal_init();

    while ((opt = getopt_long(argc, argv, "r:is:f:vh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'r':
            root_path = strdup(optarg);
            break;
        case 'i':
            in_stdin = CIO_TRUE;
            break;
        case 's':
            stream = strdup(optarg);
            break;
        case 'f':
            fname = strdup(optarg);
            break;
        case 'v':
            verbose++;
            break;
        case 'h':
            cio_help(EXIT_SUCCESS);
            break;
        default:
            cio_help(EXIT_FAILURE);
        }
    }

    /* Check root path, if not set, defaults to ~/.cio */
    if (!root_path) {
        ret = cio_default_root_path(tmp, sizeof(tmp) - 1);
        if (ret == -1) {
            fprintf(stderr,
                    "[chunkio cli] cannot set default root path\n");
            cio_help(EXIT_FAILURE);
        }
        root_path = strdup(tmp);
    }

    /* Create CIO instance */
    ctx = cio_create(root_path, log_cb, verbose);
    free(root_path);

    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Dump data to file from stdin ? */
    if (in_stdin == CIO_TRUE) {
        /* we need the stream and file names */
        if (!stream) {
            fprintf(stderr, "[chunkio cli] missing stream name\n");
            cio_help(EXIT_FAILURE);
        }
        if (!fname) {
            fprintf(stderr, "[chunkio cli] missing file name\n");
            free(stream);
            cio_help(EXIT_FAILURE);
        }

        cio_stdin(ctx, stream, fname);
    }

    free(stream);
    free(fname);
    cio_destroy(ctx);
    return 0;
}
