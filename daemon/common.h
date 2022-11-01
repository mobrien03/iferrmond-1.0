/* SPDX-License-Identifier: GPL-2.0-or-later */
/* This file is part of iferrmond            */
#ifdef hpux
#include <syslog.h>
#else
#include <sys/syslog.h>
#endif /* hpux */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

/*************************************** 
 *  Define Globals
 ***************************************/

#define TRUE  1
#define FALSE 0
#define MAXLINE 1024
#define QUIET 0
#define sz_QUIET "0"
#define INFO  1
#define DEFAULT_TraceLevel		0
#define sz_DEFAULT_TraceLevel		"0"

/***************************************
 * - Set DEBUG to 1, not in Prod!
 * - Mitigate potential for CWE-134 
 *   using constant for fprintf format
 ***************************************/
#define DEBUG 0
#define _DEBUG_FMT_ "%s:%s:%04d:"

extern int TraceLevel;

#define dbg_prt(fmt, ...) \
    do { if (DEBUG) fprintf(stderr, "Debug: " _DEBUG_FMT_ " " \
         fmt, __FILE__, __func__, __LINE__, ##__VA_ARGS__); } while (0)

#define d_MSG(fmt, ...) \
    do { buf[0] = '\0'; \
         sprintf(buf, fmt, ##__VA_ARGS__); \
         fwrite(buf, sizeof(buf[0]), strlen(buf), stderr); } while (0)

/*****************************************
* Function Prototypes
******************************************/
void daemon_SysV(void);
