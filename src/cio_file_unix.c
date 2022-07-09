/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2019 Eduardo Silva <eduardo@monkey.io>
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>

#include <chunkio/chunkio.h>
#include <chunkio/chunkio_compat.h>
#include <chunkio/cio_crc32.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_error.h>
#include <chunkio/cio_utils.h>


int cio_file_native_unmap(struct cio_file *cf)
{
    int ret;

    if (cf == NULL) {
        return -1;
    }

    ret = munmap(cf->map, cf->alloc_size);

    if (ret == 0)
    {
        cf->map = NULL;
    }

    return ret;
}

int cio_file_native_map(struct cio_file *cf, size_t map_size)
{
    int flags;

    if (cf == NULL) {
        return CIO_ERROR;
    }

    if (cf->map != NULL) {
        return CIO_OK;
    }

    if (cf->flags & CIO_OPEN_RW) {
        flags = PROT_READ | PROT_WRITE;
    }
    else if (cf->flags & CIO_OPEN_RD) {
        flags = PROT_READ;
    }
    else {
        flags = 0;
    }

    cf->map = mmap(0, map_size, flags, MAP_SHARED, cf->fd, 0);

    if (cf->map == MAP_FAILED) {
        cio_errno();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_remap(struct cio_file *cf, size_t new_size)
{
    int   result;
    void *tmp;

    result = 0;

/* OSX mman does not implement mremap or MREMAP_MAYMOVE. */
#ifndef MREMAP_MAYMOVE
    result = cio_file_native_unmap(cf);

    if (result == -1) {
        return CIO_ERROR;
    }

    tmp = mmap(0, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, cf->fd, 0);
#else
    (void) result;

    tmp = mremap(cf->map, cf->alloc_size, new_size, MREMAP_MAYMOVE);
#endif

    if (tmp == MAP_FAILED) {
        return CIO_ERROR;
    }

    cf->map = tmp;
    cf->alloc_size = new_size;

    return CIO_OK;
}

int cio_file_native_lookup_user(char *user, void **result)
{
    long           query_buffer_size;
    struct passwd *query_result;
    char          *query_buffer;
    struct passwd  passwd_entry;
    int            api_result;

    if (user == NULL) {
        *result = calloc(1, sizeof(uid_t));

        if (*result == NULL) {
            cio_errno();

            return CIO_ERROR;
        }

        **(uid_t **) result = (uid_t) -1;
    }

    query_buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);

    if (query_buffer_size == -1) {
        query_buffer_size = 4096 * 10;
    }

    query_buffer = calloc(1, query_buffer_size);

    if (query_buffer == NULL) {
        return CIO_ERROR;
    }

    query_result = NULL;

    api_result = getpwnam_r(user, &passwd_entry, query_buffer,
                            query_buffer_size, &query_result);

    if (api_result != 0 || query_result == NULL) {
        cio_errno();

        free(query_buffer);

        return CIO_ERROR;
    }

    *result = calloc(1, sizeof(uid_t));

    if (*result == NULL) {
        cio_errno();

        free(query_buffer);

        return CIO_ERROR;
    }

    **(uid_t **) result = query_result->pw_uid;

    free(query_buffer);

    return CIO_OK;
}

int cio_file_native_lookup_group(char *group, void **result)
{
    long           query_buffer_size;
    struct group  *query_result;
    char          *query_buffer;
    struct group   group_entry;
    int            api_result;

    if (group == NULL) {
        *result = calloc(1, sizeof(gid_t));

        if (*result == NULL) {
            cio_errno();

            return CIO_ERROR;
        }

        **(gid_t **) result = (gid_t) -1;
    }

    query_buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);

    if (query_buffer_size == -1) {
        query_buffer_size = 4096 * 10;
    }

    query_buffer = calloc(1, query_buffer_size);

    if (query_buffer == NULL) {
        return CIO_ERROR;
    }

    query_result = NULL;

    api_result = getgrnam_r(group, &group_entry, query_buffer,
                            query_buffer_size, &query_result);

    if (api_result != 0 || query_result == NULL) {
        cio_errno();

        free(query_buffer);

        return CIO_ERROR;
    }

    *result = calloc(1, sizeof(gid_t));

    if (*result == NULL) {
        cio_errno();

        free(query_buffer);

        return CIO_ERROR;
    }

    **(gid_t **) result = query_result->gr_gid;

    free(query_buffer);

    return CIO_OK;
}

static int apply_file_ownership_and_acl_settings(struct cio_ctx *ctx, char *path)
{
    mode_t filesystem_acl;
    gid_t  numeric_group;
    uid_t  numeric_user;
    char  *connector;
    int    result;
    char  *group;
    char  *user;

    numeric_group = -1;
    numeric_user = -1;

    if (ctx->processed_user != NULL) {
        numeric_user = *(uid_t *) ctx->processed_user;
    }

    if (ctx->processed_group != NULL) {
        numeric_group = *(gid_t *) ctx->processed_group;
    }

    if (numeric_user != -1 || numeric_group != -1) {
        result = chown(path, numeric_user, numeric_group);

        if (result == -1) {
            cio_errno();

            user = ctx->options.user;
            group = ctx->options.group;
            connector = "with group";

            if (user == NULL) {
                user = "";
                connector = "";
            }

            if (group == NULL) {
                group = "";
                connector = "";
            }

            cio_log_error(ctx, "cannot change ownership of %s to %s %s %s",
                          path, user, connector, group);

            return CIO_ERROR;
        }
    }

    if (ctx->options.chmod != NULL) {
        filesystem_acl = strtoul(ctx->options.chmod, NULL, 8);

        result = chmod(path, filesystem_acl);

        if (result == -1) {
            cio_errno();
            cio_log_error(ctx, "cannot change acl of %s to %s",
                          path, ctx->options.user);

            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

int cio_file_native_get_size(struct cio_file *cf, size_t *file_size)
{
    int         ret;
    struct stat st;

    ret = -1;

    if (cf->fd != -1) {
        ret = fstat(cf->fd, &st);
    }

    if (ret == -1) {
        ret = stat(cf->path, &st);
    }

    if (ret == -1) {
        return CIO_ERROR;
    }

    if (file_size != NULL) {
        *file_size = st.st_size;
    }

    return CIO_OK;
}

/* Open file system file, set file descriptor and file size */
int cio_file_native_open(struct cio_ctx *ctx, struct cio_file *cf)
{
    int    ret;

    if (cf->map != NULL || cf->fd != -1) {
        return -1;
    }

    /* Open file descriptor */
    if (cf->flags & CIO_OPEN_RW) {
        cf->fd = open(cf->path, O_RDWR | O_CREAT, (mode_t) 0600);
    }
    else if (cf->flags & CIO_OPEN_RD) {
        cf->fd = open(cf->path, O_RDONLY);
    }

    if (cf->fd == -1) {
        cio_errno();
        cio_log_error(ctx, "cannot open/create %s", cf->path);

        return -1;
    }

    ret = apply_file_ownership_and_acl_settings(ctx, cf->path);

    if (ret == CIO_ERROR) {
        cio_errno();
        cio_file_native_close(cf);

        return -1;
    }

    ret = cio_file_update_size(cf);

    if (ret != CIO_OK) {
        cio_file_native_close(cf);

        return -1;
    }

    return 0;
}

void cio_file_native_close(struct cio_file *cf)
{
    if (cf != NULL && cf->fd != 0) {
        close(cf->fd);

        cf->fd = -1;
    }
}

int cio_file_native_delete(struct cio_file *cf)
{
    return unlink(cf->path);
}

int cio_file_native_sync(struct cio_file *cf, int sync_mode)
{
    int result;

    result = msync(cf->map, cf->alloc_size, sync_mode);

    if (result == -1) {
        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_resize(struct cio_file *cf, size_t new_size)
{
    int ret = -1;

    /*
     * fallocate() is not portable an Linux only. Since macOS does not have
     * fallocate() we use ftruncate().
     */
#if defined(CIO_HAVE_FALLOCATE)
    if (new_size > cf->alloc_size) {
        retry:

        if (cf->allocate_strategy == CIO_FILE_LINUX_FALLOCATE) {
            /*
             * To increase the file size we use fallocate() since this option
             * will send a proper ENOSPC error if the file system ran out of
             * space. ftruncate() will not fail and upon memcpy() over the
             * mmap area it will trigger a 'Bus Error' crashing the program.
             *
             * fallocate() is not portable, Linux only.
             */
            ret = fallocate(cf->fd, 0, 0, new_size);
            if (ret == -1 && errno == EOPNOTSUPP) {
                /*
                 * If fallocate fails with an EOPNOTSUPP try operation using
                 * posix_fallocate. Required since some filesystems do not support
                 * the fallocate operation e.g. ext3 and reiserfs.
                 */
                cf->allocate_strategy = CIO_FILE_LINUX_POSIX_FALLOCATE;
                goto retry;
            }
        }
        else if (cf->allocate_strategy == CIO_FILE_LINUX_POSIX_FALLOCATE) {
            ret = posix_fallocate(cf->fd, 0, new_size);
        }
    }
    else
#endif
    {
        ret = ftruncate(cf->fd, new_size);
    }

    if (!ret) {
        cf->fs_size = new_size;
    }

    return ret;
}
