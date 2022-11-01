/* SPDX-License-Identifier: GPL-2.0-or-later */
/* This file is part of iferrmond            */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/time.h>
#include <fnmatch.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <math.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include "libnetlink.h"
#include "json_writer.h"
#include "version.h"
#include "utils.h"
#include "common.h"

/* DEFINES */
#define MAXS (sizeof(struct rtnl_link_stats)/sizeof(__u32))
#define NO_SUB_TYPE 0xffff
#define MAXPATH 1024
#define RC_SUCCESS 1
#define RC_FAILURE 0
#define UNABLE_TO !
#define IMAXCNT 20
#define INAMEMAX 32
#define eLvl_MAXSTR 5

/* Macro to print iferrmond version info                                     */
#define printVersion \
    do { pD->sBuf[0] = '\0'; \
         sprintf(pD->sBuf, "iferrmond %s\n", pD->myVerRel); \
         printMsg(pD); } while (0)

/* Created printActiveMsg macro to keep line-length down, <=80 in source code*/
#define printActiveMsg \
    do { pD->sBuf[0] = '\0'; \
         sprintf(pD->sBuf, "Monitor Active: \"%s\",", \
                 pD->monIntfs); \
         sprintf(pD->sBuf + strlen(pD->sBuf), " mVer: \"%s\",", \
                 pD->myVerRel); \
         sprintf(pD->sBuf + strlen(pD->sBuf), " iVal: %ds, tHld: %d,", \
                 pD->wIntvl, pD->tHld); \
         sprintf(pD->sBuf + strlen(pD->sBuf), " cHty: %s, eVal: %dh,", \
                 pD->runChatty, pD->errAlertIntvl); \
         sprintf(pD->sBuf + strlen(pD->sBuf), " dVal: %dh, eDly: %dh,", \
                 pD->downAlertIntvl, pD->errDelayTime); \
         sprintf(pD->sBuf + strlen(pD->sBuf), " dDly: %dh, sTim: %s,", \
                 pD->downDelayTime, now(pD, (time_t *) pD->startRawTm)); \
         if ( pD->f_validConfigFile ) { \
             sprintf(pD->sBuf + strlen(pD->sBuf), " cFil: %s\n", \
                     pD->configFile); }\
         else { \
             sprintf(pD->sBuf + strlen(pD->sBuf), " cFil: %s\n", \
                     "\'Invalid, or not specified, using defaults!\'"); } \
         printMsg(pD); } while (0)

#define DMSG(fmt, ...) \
    do { pD->sBuf[0] = '\0'; \
         sprintf(pD->sBuf, "Debug: %s, %s:%04d: " fmt, \
                           __FILE__, __func__, __LINE__, ##__VA_ARGS__); \
         printMsg(pD); } while (0)

#define dMSG(fmt, ...) \
    do { pD->sBuf[0] = '\0'; \
         sprintf(pD->sBuf, fmt, ##__VA_ARGS__); \
         printMsg(pD); } while (0)

/* Intf Array structure type   */
typedef struct interface {
    char   name[32];                /* Interface name                        */
    time_t errRawTm;                /* if !-1, wait until this time to Error:*/
    int    f_errDelayTime;          /* Flag indicates errDelayTime in effect */ 
    time_t downRawTm;               /* if !-1, wait until this time to Error:*/
    int    f_downDelayTime;         /* Flag indicates downDelayTime in effect*/
}INTF;

/* Working data structure type */
typedef struct data {               /* => Internal DATA used by iferrmond <= */
    __u32  tHld;                    /* Minimum errors needed to alert        */
    time_t startRawTm;              /* daemon start date/time, epoch raw/time*/
    int    f_configFile;            /* Configuration File flag               */
    int    f_validConfigFile;       /* Configuration File is valid flag      */
    int    f_debug;                 /* Debug flag                            */
    int    wIntvl;                  /* Wait interval between getting stats   */
    int    errAlertIntvl;           /* Wait interval between kern stat alerts*/
    int    downAlertIntvl;          /* Wait interval between intf down alerts*/
    int    errDelayTime;            /* Upon Start, wait before stats Error   */
    int    downDelayTime;           /* Upon Start, wait before down Error    */
    int    intfCount;               /* Count of interfaces in intfArray      */
    int    iftbl_entry_count;       /* Count of interface entries in kern_db */
    char   myVerRel[25];            /* iferrmond Version and Release info    */
    char   configFile[MAXLINE +1];  /* Configuration File                    */
    char   monIntfs[MAXLINE + 1];   /* Interfaces to monitor from config file*/
    INTF   intf[IMAXCNT];           /* Interface Array                       */
    char   sBuf[MAXLINE + 1];       /* Working area for output to Syslog     */
    char   tBuf[MAXLINE + 1];       /* Temporary buffer                      */
    char   runChatty[2];            /* Run chatty, Y or y from config file   */
}DATA;

/* Global variables */
char *intfArray[IMAXCNT];           /* Pointer to Array of interfaces        */
int dump_zeros;
int reset_history;
int no_output;
int json_output;
int scan_interval;
int time_constant;
double W;
char **patterns;
int npatterns;
int filter_type;
int sub_type;
int source_mismatch;

char info_source[128] = "kernel";
bool is_extended = FALSE;
int ignore_history = 1;
int no_update = 1;
int show_errors = 1;
int TraceLevel = 0;
int debug = FALSE;

typedef struct ifstat_ent {
    struct  ifstat_ent *next;
    char    *name;
    int     ifindex;
    __u64   val[MAXS];
    double  rate[MAXS];
    __u32   ival[MAXS];
}IFSTAT;

struct ifstat_ent *kern_db = NULL;
struct ifstat_ent *hist_db = NULL;

//static const char *stats[MAXS] = {
//	"rx_packets",
//	"tx_packets",
//	"rx_bytes",
//	"tx_bytes",
//	"rx_errors",
//	"tx_errors",
//	"rx_dropped",
//	"tx_dropped",
//	"multicast",
//	"collisions",
//	"rx_length_errors",
//	"rx_over_errors",
//	"rx_crc_errors",
//	"rx_frame_errors",
//	"rx_fifo_errors",
//	"rx_missed_errors",
//	"tx_aborted_errors",
//	"tx_carrier_errors",
//	"tx_fifo_errors",
//	"tx_heartbeat_errors",
//	"tx_window_errors",
//	"rx_compressed",
//	"tx_compressed"
//};

/* Function Prototypes for iferrmond */
static void load_info(DATA *pD);
static int get_nlmsg(struct nlmsghdr *m, void *arg);
int    compareInfo(DATA *pD);
int    printMsg(DATA *pD);
int    processConfig(DATA *pD);
void   removeSpaces(char* s);
void   removeDblQuotes(char* s);
void   loadIntfArray(DATA *pD);
int    hasIntfData(char *iName, IFSTAT **n, IFSTAT **o);
int    chkForErrors(DATA *pD, int i, char *msgStr, IFSTAT *n, IFSTAT *o);
int    processCmdline(int argc, char **argv, DATA *pD);
int    defaultConfig(DATA *pD);
char   *now(DATA *pD, time_t *eTm);
void   getEventLevel(DATA *pD, int i, char eventType, char *eventLevel);
int    initializeDelays(DATA *pD);
int    copyCurrent_to_History(IFSTAT **kern_db, IFSTAT **hist_db, DATA *pD);
void   free_db(IFSTAT *db);
void   usage(void);
void   SIGTERM_handler(int sig);
bool   IsDigitsOnly(const char *str);
