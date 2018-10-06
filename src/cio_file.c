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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_sha1.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

char cio_file_sha1_default[] =   {                              \
    0xad, 0x03, 0x9f, 0xc0, 0xeb,                               \
    0x11, 0x9a, 0xf8, 0x3a, 0xe8,                               \
    0x7d, 0x19, 0x85, 0x57, 0x0d,                               \
    0x84, 0xd8, 0x84, 0x4c, 0xc2                                \
};

#define round_up(a, b)  (a + (b - (a % b)))

/* Calculate SHA1 into variable */
static void get_hash(struct cio_file *cf, char *out)
{
    size_t content_len;
    void *in_data;

    in_data = cf->map + CIO_FILE_CONTENT_OFFSET;
    content_len = cf->alloc_size - cf->data_size - 24;

    cio_sha1_hash(in_data, content_len, (unsigned char *) out);
}

/* Update SHA1 hash into memory map */
static void write_hash(struct cio_file *cf)
{
    size_t content_len;
    void *in_data;

    in_data = cf->map + CIO_FILE_CONTENT_OFFSET;
    content_len = cf->alloc_size - cf->data_size - 24;

    cio_sha1_hash(in_data, content_len, (unsigned char *) (cf->map + 2));
}

static void write_header(struct cio_file *cf)
{
    char *p = cf->map;

    p[0] = CIO_FILE_ID_00;
    p[1] = CIO_FILE_ID_01;

    p = cio_file_st_get_meta_header(cf->map);
    *p++ = 0;
    *p++ = 0;

    /* Write default sha1 hash */
    p = cf->map + 2;
    memcpy(p, cio_file_sha1_default, 20);
}

/* Return the available size in the file map to write data */
static size_t get_available_size(struct cio_file *cf)
{
    size_t av;
    int map_len;

    map_len = cio_file_st_get_meta_len(cf->map);

    av = cf->alloc_size - cf->data_size;
    av -= (CIO_FILE_HEADER_MIN + map_len);

    return av;
}

/*
 * For the recently opened or created file, check the structure format
 * and validate relevant fields.
 */
static int cio_file_format_check(struct cio_file *cf, int flags)
{
    char *p;
    char hash[20];

    p = cf->map;

    /* If the file is empty, put the structure on it */
    if (cf->data_size == 0) {
        /* check we have write permissions */
        if (cf->flags & ~CIO_OPEN) {
            cio_log_warn(cf->ctx,
                         "[cio file] cannot initialize chunk (read-only)");
            return -1;
        }

        /* at least we need 24 bytes as allocated space */
        if (cf->alloc_size < CIO_FILE_HEADER_MIN) {
            cio_log_warn(cf->ctx, "[cio file] cannot initialize chunk");
            return -1;
        }

        write_header(cf);
    }
    else {
        /* Check first two bytes */
        if (p[0] != CIO_FILE_ID_00 || p[1] != CIO_FILE_ID_01) {
            cio_log_debug(cf->ctx, "[cio file] invalid header at %s",
                          cf->name);
            return -1;
        }

        /* Get hash stored in the mmap */
        p = cio_file_st_get_hash(cf->map);

        /* Calculate hash from the data */
        get_hash(cf, hash);

        /* Compare */
        if (memcmp(p, hash, 20) != 0) {
            cio_log_debug(cf->ctx, "[cio file] invalid sha1 at %s",
                          cf->name);
            return -1;
        }
    }

    return 0;
}

/*
 * Open or create a data file: the following behavior is expected depending
 * of the passed flags:
 *
 * CIO_OPEN:
 *    - Open for read/write, if the file don't exist, it's created and the
 *      memory map size is assigned to the given value on 'size'.
 */
struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               const char *name,
                               int flags,
                               size_t size)
{
    int fd;
    int psize;
    int ret;
    int len;
    int oflags;
    size_t fs_size = 0;
    ssize_t content_size;
    char *path;
    struct cio_file *cf;
    struct stat fst;
    (void) ctx;

    if (!st) {
        cio_log_error(ctx, "[cio file] invalid stream");
        return NULL;
    }

    if (!name) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    len = strlen(name);
    if (len == 0) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    if (len == 1 && (name[0] == '.' || name[0] == '/')) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    /* Compose path for the file */
    psize = strlen(ctx->root_path) + strlen(st->name) + strlen(name);
    psize += 8;

    path = malloc(psize);
    if (!path) {
        cio_errno();
        return NULL;
    }

    ret = snprintf(path, psize, "%s/%s/%s",
                   ctx->root_path, st->name, name);
    if (ret == -1) {
        cio_errno();
        free(path);
        return NULL;
    }

    /* Create file context */
    cf = calloc(1, sizeof(struct cio_file));
    if (!cf) {
        cio_errno();
        free(path);
        return NULL;
    }
    cf->ctx = ctx;
    cf->flags = flags;
    cf->st = st;
    cf->realloc_size = getpagesize() * 8;
    cf->st_content = NULL;

    cf->name = strdup(name);
    if (!cf->name) {
        cio_errno();
        free(path);
        return NULL;
    }
    cf->path = path;
    mk_list_add(&cf->_head, &st->files);

    /* Open file descriptor */
    if (flags & CIO_OPEN) {
        cf->fd = open(path, O_RDWR | O_CREAT, (mode_t) 0600);
    }
    else if (flags & CIO_OPEN_RD) {
        cf->fd = open(path, O_RDONLY);
    }

    if (cf->fd == -1) {
        cio_errno();
        cio_log_error(ctx, "cannot open/create %s", path);
        cio_file_close(cf);
        return NULL;
    }

    /* Check if some previous content exists */
    ret = fstat(cf->fd, &fst);
    if (ret == -1) {
        cio_errno();
        cio_file_close(cf);
        return NULL;
    }

    /* Get file size from the file system */
    fs_size = fst.st_size;

    /* Mmap */
    if (flags & CIO_OPEN) {
        oflags = PROT_READ | PROT_WRITE;
    }
    else if (flags & CIO_OPEN_RD) {
        oflags = PROT_READ;
    }

    /* If the file is not empty, use file size for the memory map */
    if (fs_size > 0) {
        size = fs_size;
        cf->synced = CIO_TRUE;
    }
    else if (fs_size == 0) {
        cf->synced = CIO_FALSE;

        /* Adjust size to make room for headers */
        if (size < CIO_FILE_HEADER_MIN) {
            size += CIO_FILE_HEADER_MIN;
        }

        /* For empty files, make room in the file system */
        size = round_up(size, cio_page_size);
        ret = ftruncate(cf->fd, size);
        if (ret == -1) {
            cio_errno();
            cio_file_close(cf);
            return NULL;
        }
    }

    /* Map the file */
    size = round_up(size, cio_page_size);
    cf->map = mmap(0, size, oflags, MAP_SHARED, cf->fd, 0);
    if (cf->map == MAP_FAILED) {
        cio_errno();
        cf->map = NULL;
        cio_file_close(cf);
        return NULL;
    }
    cf->alloc_size = size;

    /* check content data size */
    if (fs_size > 0) {
        content_size = cio_file_st_get_content_size(cf->map, size);
        if (content_size == -1) {
            cio_log_error(ctx, "invalid content size %s", path);
            cio_file_close(cf);
            return NULL;
        }
        cf->data_size = content_size;
    }
    else {
        cf->data_size = 0;
    }

    cio_file_format_check(cf, flags);
    cf->st_content = cio_file_st_get_content(cf->map);
    cio_log_debug(ctx, "%s:%s mapped OK", st->name, cf->name);

    return cf;
}

void cio_file_close(struct cio_file *cf)
{
    int ret;

    /* check if the file needs to be synchronized */
    if (cf->synced == CIO_FALSE && cf->map) {
        ret = cio_file_sync(cf);
        if (ret == -1) {
            cio_log_error(cf->ctx,
                          "[cio file] error doing file sync on close at "
                          "%s:%s", cf->st->name, cf->name);
        }
    }

    /* unmap file */
    if (cf->map) {
        munmap(cf->map, cf->alloc_size);
    }

    close(cf->fd);
    mk_list_del(&cf->_head);
    free(cf->name);
    free(cf->path);
    free(cf);
}

int cio_file_write(struct cio_file *cf, const void *buf, size_t count)
{
    int ret;
    size_t meta_len;
    char *p;
    void *tmp;
    size_t av_size;
    size_t new_size;

    if (count == 0) {
        /* do nothing */
        return 0;
    }

    /* get available size */
    av_size = get_available_size(cf);

    /* validate there is enough space, otherwise resize */
    if (count > av_size) {
        if (av_size + cf->realloc_size < count) {
            new_size = cf->alloc_size + count;
            cio_log_debug(cf->ctx,
                          "[cio file] realloc size is not big enough "
                          "for incoming data, consider to increase it");
        }
        else {
            new_size = cf->alloc_size + cf->realloc_size;
        }

        new_size = round_up(new_size, cio_page_size);
        tmp = mremap(cf->map, cf->alloc_size,
                     new_size, MREMAP_MAYMOVE);
        if (tmp == MAP_FAILED) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio file] data exceeds available space "
                          "(alloc=%lu current_size=%lu write_size=%lu)",
                          cf->alloc_size, cf->data_size, count);
            return -1;
        }


        cf->map = tmp;
        cio_log_debug(cf->ctx,
                      "[cio file] alloc_size from %lu to %lu",
                      cf->alloc_size, new_size);
        cf->alloc_size = new_size;

        ret = ftruncate(cf->fd, cf->alloc_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio_file] error setting new file size on write");
            return -1;
        }

        cf->st_content = cio_file_st_get_content(cf->map);
    }

    memcpy(cf->st_content + cf->data_size, buf, count);
    cf->data_size += count;
    cf->synced = CIO_FALSE;

    return 0;
}

int cio_file_sync(struct cio_file *cf)
{
    int ret;
    size_t av_size;
    size_t size;
    struct stat fst;

    if (cf->flags & CIO_OPEN_RD) {
        return 0;
    }

    ret = fstat(cf->fd, &fst);
    if (ret == -1) {
        cio_errno();
        return -1;
    }

    /* If there extra space, truncate the file size */
    av_size = get_available_size(cf);
    if (av_size > 0) {
        size = cf->alloc_size - av_size;
        ret = ftruncate(cf->fd, size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio file sync] error adjusting size at: "
                          " %s/%s", cf->st->name, cf->name);
        }
        cf->alloc_size = size;
    }
    else if (cf->alloc_size > fst.st_size) {
        ret = ftruncate(cf->fd, cf->alloc_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(cf->ctx,
                          "[cio file sync] error adjusting size at: "
                          " %s/%s", cf->st->name, cf->name);
        }
    }

    /* Commit changes to disk */
    ret = msync(cf->map, cf->alloc_size, MS_SYNC);
    if (ret == -1) {
        cio_errno();
        return -1;
    }

    cf->synced = CIO_TRUE;
    cio_log_debug(cf->ctx, "[cio file] synced at: %s/%s",
                  cf->st->name, cf->name);
    return 0;
}

/* Set a reallocation chunk size */
void cio_file_realloc_size(struct cio_file *cf, size_t chunk_size)
{
    cf->realloc_size = chunk_size;
}

/* Close all files owned by the given stream */
int cio_file_close_stream(struct cio_stream *st)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_file *cf;

    mk_list_foreach_safe(head, tmp, &st->files) {
        cf = mk_list_entry(head, struct cio_file, _head);
        cio_file_close(cf);
    }

    return 0;
}
