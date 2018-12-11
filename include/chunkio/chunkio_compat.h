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

#ifndef CHUNKIO_COMPAT_H
#define CHUNKIO_COMPAT_H

/* Windows compatibility utils */
#ifdef _WIN32
#  define PATH_MAX MAX_PATH
#  define ssize_t int
#  include <winsock2.h>
#  pragma comment(lib, "ws2_32.lib")
#  include <windows.h>
#  include <wchar.h>
#  include <io.h>
#  include <direct.h>
#  include <stdint.h>
#  include <stdlib.h>
#  define access _access
#  define W_OK 02 // Write permission.
#  define mode_t uint32_t
#  define mkdir(dir, mode) _mkdir(dir)

static inline char* dirname(const char *dir) {
    char drive[_MAX_DRIVE];
    char splitted_dir[_MAX_DIR];
    char filename[_MAX_FNAME];
    char ext[_MAX_EXT];
    char path_buffer[_MAX_PATH];

    _splitpath(dir, drive, splitted_dir, filename, ext);
    _makepath(path_buffer, drive, splitted_dir, "", "");

    return path_buffer;
}
#  if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#    define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#  endif
#  define strerror_r(errno,buf,len) strerror_s(buf,len,errno)
inline int getpagesize(void)
{
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    return system_info.dwPageSize;
}
#else
#  include <unistd.h>
#endif

#endif
