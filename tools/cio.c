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

#define ANSI_RESET "\033[0m"
#define ANSI_BOLD  "\033[1m"

#define ANSI_CYAN          "\033[96m"
#define ANSI_BOLD_CYAN     ANSI_BOLD ANSI_CYAN
#define ANSI_MAGENTA       "\033[95m"
#define ANSI_BOLD_MAGENTA  ANSI_BOLD ANSI_MAGENTA
#define ANSI_RED           "\033[91m"
#define ANSI_BOLD_RED      ANSI_BOLD ANSI_RED
#define ANSI_YELLOW        "\033[93m"

#define ANSI_BOLD_YELLOW   ANSI_BOLD ANSI_YELLOW
#define ANSI_BLUE          "\033[94m"
#define ANSI_BOLD_BLUE     ANSI_BOLD ANSI_BLUE
#define ANSI_GREEN         "\033[92m"
#define ANSI_BOLD_GREEN    ANSI_BOLD ANSI_GREEN
#define ANSI_WHITE         "\033[97m"
#define ANSI_BOLD_WHITE    ANSI_BOLD ANSI_WHITE

#define CIO_ROOT_PATH  ".cio"
#define cio_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n" , sizeof(#X ")\n")-1); \
    break;

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
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

void cio_bytes_to_human_readable_size(size_t bytes,
                                      char *out_buf, size_t size)
{
    unsigned long i;
    unsigned long u = 1024;
    static const char *__units[] = {
        "b", "K", "M", "G",
        "T", "P", "E", "Z", "Y", NULL
    };

    for (i = 0; __units[i] != NULL; i++) {
        if ((bytes / u) == 0) {
            break;
        }
        u *= 1024;
    }
    if (!i) {
        snprintf(out_buf, size, "%lu%s", (long unsigned int) bytes, __units[0]);
    }
    else {
        float fsize = (float) ((double) bytes / (u / 1024));
        snprintf(out_buf, size, "%.1f%s", fsize, __units[i]);
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
    char *dtitle = "chunkio";
    char *dcolor = ANSI_BLUE;

    /* messages from this own client are in yellow */
    if (*file == 't') {
        dtitle = "  cli  ";
        dcolor = ANSI_YELLOW;
    }

    if (ctx->log_level > CIO_INFO) {
        printf("%s[%s]%s %-60s => %s%s:%i%s\n",
               dcolor, dtitle, ANSI_RESET, str,
               dcolor, file, line, ANSI_RESET);
    }
    else {
        printf("%s[%s]%s %s\n", dcolor, dtitle, ANSI_RESET, str);
    }
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

/* command/list: iterate root path and list content */
static int cb_cmd_list(struct cio_ctx *ctx)
{
    /* FIXME: creation context must populate structures first */
}

/* command/stdin: read data from STDIN and dump it into stream/file */
static int cb_cmd_stdin(struct cio_ctx *ctx, const char *stream,
                        const char *fname)
{
    int fd;
    int ret;
    size_t total = 0;
    ssize_t bytes;
    char buf[1024*8];
    struct cio_stream *st;
    struct cio_file *cf;

    /* Prepare stream and file contexts */
    st = cio_stream_create(ctx, stream);
    if (!st) {
        cio_log_error(ctx, "cannot create stream\n");
        return -1;
    }

    /* Open a file with a hint of 32KB */
    cf = cio_file_open(ctx, st, fname, CIO_OPEN, 1024*32);
    if (!cf) {
        cio_log_error(ctx, "cannot create file");
        return -1;
    }

    /* Catch up stdin */
    fd = dup(STDIN_FILENO);
    if (fd == -1) {
        perror("dup");
        cio_log_error(ctx, "cannot open standard input");
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
                cio_log_error(ctx, "error writing to file");
                close(fd);
                return -1;
            }
            total += bytes;
        }
    } while (bytes > 0);

    /* close stdin dup(2) */
    close(fd);

    /* synchronize changes to disk and close */
    cio_file_sync(cf);
    cio_file_close(cf);

    /* print some status */
    cio_bytes_to_human_readable_size(total, buf, sizeof(buf) - 1);
    cio_log_info(ctx, "stdin total bytes => %lu (%s)", total, buf);

    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    int opt;
    int opt_silent = CIO_FALSE;
    int cmd_stdin = CIO_FALSE;
    int cmd_list = CIO_FALSE;
    int verbose = CIO_INFO;
    char *fname = NULL;
    char *stream = NULL;
    char *root_path = NULL;
    char tmp[PATH_MAX];
    struct cio_ctx *ctx;

    static const struct option long_opts[] = {
        {"list"       , no_argument      , NULL, 'l'},
        {"root"       , required_argument, NULL, 'r'},
        {"silent"     , no_argument      , NULL, 'S'},
        {"stdin"      , no_argument      , NULL, 'i'},
        {"stream"     , required_argument, NULL, 's'},
        {"verbose"    , no_argument      , NULL, 'v'},
        {"help"       , no_argument      , NULL, 'h'},
    };

    /* Initialize signals */
    cio_signal_init();

    while ((opt = getopt_long(argc, argv, "lr:Sis:f:vh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'l':
            cmd_list = CIO_TRUE;
            break;
        case 'i':
            cmd_stdin = CIO_TRUE;
            break;
        case 'r':
            root_path = strdup(optarg);
            break;
        case 'S':
            opt_silent = CIO_TRUE;
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

    if (opt_silent == CIO_TRUE) {
        verbose = 0;
    }

    /* Create CIO instance */
    ctx = cio_create(root_path, log_cb, verbose);
    free(root_path);

    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /*
     * Process commands and options
     */
    if (cmd_list == CIO_TRUE) {
        ret = cb_cmd_list(ctx);
    }
    else if (cmd_stdin == CIO_TRUE) {
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

        ret = cb_cmd_stdin(ctx, stream, fname);
    }

    free(stream);
    free(fname);
    cio_destroy(ctx);

    return ret;
}
