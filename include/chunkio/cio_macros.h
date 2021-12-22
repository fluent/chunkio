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

#ifndef CIO_MACROS_H
#define CIO_MACROS_H

#ifdef _MSC_VER
#define CIO_ANSI_RESET    ""
#define CIO_ANSI_BOLD     ""
#define CIO_ANSI_CYAN     ""
#define CIO_ANSI_MAGENTA  ""
#define CIO_ANSI_RED      ""
#define CIO_ANSI_YELLOW   ""
#define CIO_ANSI_BLUE     ""
#define CIO_ANSI_GREEN    ""
#define CIO_ANSI_WHITE    ""
#else
#define CIO_ANSI_RESET    "\033[0m"
#define CIO_ANSI_BOLD     "\033[1m"
#define CIO_ANSI_CYAN     "\033[96m"
#define CIO_ANSI_MAGENTA  "\033[95m"
#define CIO_ANSI_RED      "\033[91m"
#define CIO_ANSI_YELLOW   "\033[93m"
#define CIO_ANSI_BLUE     "\033[94m"
#define CIO_ANSI_GREEN    "\033[92m"
#define CIO_ANSI_WHITE    "\033[97m"
#endif

#endif