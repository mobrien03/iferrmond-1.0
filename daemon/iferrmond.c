/*******************************************************************************
* Credits and Use Statement (iferrmond) - Must stay with source code!
*******************************************************************************
* iferrmond: Process Daemon to monitor kernel interface statistics and if errors
*            encountered, write status to syslog (via systemd output control).
*
* Copyright ©2021-2022 Michael O'Brien, mobrien03@gmail.com
* 
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; either version 2 of the License, or (at your option) any later 
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this program; if not, write to the: 
*
* Free Software Foundation, Inc.
* 59 Temple Place, Suite 330 
* Boston, MA 02111-1307 USA
*
*******************************************************************************
* Credits and Use Statement (NetLink) - Must stay with source code!
*******************************************************************************
* Reference: https://en.wikipedia.org/wiki/Netlink
*
* Note: iferrmond uses libnetlink provided by Alexey Kuznetsov, his use 
*       statement for libnetlink is below:
*
*	This program is free software; you can redistribute it and/or
*	modify it under the terms of the GNU General Public License
*	as published by the Free Software Foundation; either version
*	2 of the License, or (at your option) any later version.
*
* libnetlink Author:  Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
******************************************************************************/

/******************************************************************************
* To Extract Log: cat iferrmond.c | grep ^\\[ | awk -F\[ '{print $2}'
[******************************************************************************
[Modification Log 
[******************************************************************************
[Date     Who Ver-Rel Description
[-------- --- ------- -------------------------------------------------------
[20221101 MJO 1.0-1.2 - Clean up README and add more description of iferrmond
[                     - Add strl.c (functions strlcpy and strlcat), from Secure
[                       Programming Cookbook for C and C++ by John Viega, 
[                       Matt Messier, Released July 2003, 
[                       published by O'Reilly Media, Inc., ISBN: 9780596003944
[                     - Mitigate potential for CWE-119, CWE-120, CWE-190, and 
[                       CWE-732
[                     - Added bounds checks and further validation for proper
[                       configuration directive values from .conf file
[                     - Updated .conf template with bounds information
[                     - Update iferrmond(1) manual page content
[                     - Cleanup compiler warnings
[                     - Complete re-write of daemon initialization to be inline
[                       with suggestions in daemon(7), SysV model
[                     - Changes to systemd iferrmond.service due to re-write
[                       where type is now "forking", and added PidFile for
[                       proper systemd tracking.
[                     - Moved all "daemon" code into daemon_SysV.c to prep
[                       for later planned changes for new command line args.
[                     - Added LICENSE for for GPLv2.0+
[                     - Updated Makefile to add uninstall capability
[                     - Add INSTALL file
[20210513 MJO 1.0-1.1 - Eliminated minor memory leaks by creating two new
[                       functions: copyCurrent_to_History, and free_db that
[                       properly allocate hist_db, and free an (ifstat_ent *)
[                       linked list (respectively)
[                     - Added usage (-h|-?) and version (-V) functions for
[                       command line options.  
[                     - Added version and release info to the initial start 
[                       "Active:..." message in syslog
[                     - Enabled a signal handler for SIGTERM in order to remove
[                       iferrmond.pid file when stopped. The /var/run/iferrmond 
[                       directory (where pid file is created) will persist from
[                       rpm install until rpm uninstall.  Note that systemd
[                       issues a SIGTERM when stopped via 'systemctl stop', and 
[                       even if via command line (outside of systemd) if a 
[                       'kill PID' is issued, the pid file will be cleaned up
[                       and not negatively affect the next start by systemd.
[                     - Optimize logic in main
[                     - Updated iferrmond.spec file (used for creating rpm) to
[                       save off a copy of iferrmond.conf upon uninstall as
[                       /tmp/iferrmond_rpmsave.conf.  And, upon rpm re-install,
[                       if this file exists, /tmp/iferrmond_rpmsave.conf will
[                       be moved to the installation target as iferrmond.conf, 
[                       thus preserving the previous configuration.
[                     - Updated Credits and Use statement to include this
[                       program (iferrmond) under GNU General Public License
[20210322 MJO 1.0-1.0 - Initial coding
[******************************************************************************
*/
#include "iferrmond.h"

/******************************************************************************
*
* M A I N L I N E - Start daemon and manage monitoring of kernel interface data
*
******************************************************************************/
int main(int argc, char *argv[]) {

DATA pDATA;
int f_firstTime = TRUE;
int RC = 0;

    /***********************************************************
    * Set initial values
    ************************************************************/
    DATA *pD = (DATA *) &pDATA;
    memset(pD, 0, sizeof(pDATA));
    dbg_prt("Started, eUID: %d, sizeof(pDATA): %d\n", 
                 geteuid(), (int) sizeof(pDATA)); 

    strlcpy(pD->myVerRel, "Version 1.0, Release 1.2", sizeof(pD->myVerRel));
    pD->wIntvl = 0;;  
    pD->tHld = -1;;  
    pD->errAlertIntvl = -1;;  
    pD->downAlertIntvl = -1;; 
    pD->errDelayTime = -1;;   
    pD->downDelayTime = -1;;  

    /***********************************************************
    * Process Command Line
    ************************************************************/
    if ( UNABLE_TO processCmdline(argc, argv, pD) ) { 
        dMSG("Error: Unable to processCmdline!\n"); 
        exit(EXIT_FAILURE); 
    }

    /***********************************************************
    * Start daemon
    ************************************************************/
    daemon_SysV();

    /*******************************************************
    * Set signal handler for SIGTERM (kill)
    ********************************************************/
    if ( signal(SIGTERM, SIGTERM_handler) ) {
        dMSG("Error: Unable to install signal handler for SIGTERM!\n"); 
        exit(EXIT_FAILURE); 
    }

    dbg_prt("Before while loop, eUID: %d\n", geteuid()); 

    /***********************************************************
    * Main loop
    ************************************************************/
    while (TRUE) {
        kern_db = malloc(sizeof(*kern_db));

        if ( !kern_db ) { 
            dMSG("Error: malloc failed for kern_db!\n"); 
            exit(EXIT_FAILURE); 
        } else
            memset(kern_db, 0, sizeof(*kern_db));

        dbg_prt("Before load_info\n"); 
        load_info(pD);
    
        if ( f_firstTime ) {
            dbg_prt("Before processConfig\n"); 

            if ( UNABLE_TO processConfig(pD) ) { 
                dMSG("Error: Unable to processConfig!\n"); 
                exit(EXIT_FAILURE); 
            }
            
            pD->startRawTm = time(NULL);

            if ( UNABLE_TO initializeDelays(pD) ) {
                dMSG("Error: Unable to initializeDelays!\n"); 
                exit(EXIT_FAILURE);
            }

            /* Macro to keep line-length <=80 in source code*/
            printActiveMsg;

            f_firstTime = FALSE;
            
        } else {
            dbg_prt("Before compareInfo\n"); 
            compareInfo(pD);
            
            if ( hist_db ) 
                free_db(hist_db);
        }

        if ( UNABLE_TO copyCurrent_to_History(&kern_db, &hist_db, pD) ) {
            dMSG("Error: malloc failed for hist_db!\n"); 
            exit(EXIT_FAILURE); 
        }
    
        if ( kern_db )
            free_db(kern_db);

        dbg_prt("Before sleep\n"); 
        sleep(pD->wIntvl);
    }

    exit(RC);
}


/******************************************************************************
*
* load_info - Request Netlink Data from Kernel, call get_nlmsg to load kern_db
*
******************************************************************************/
static void load_info(DATA *pD) {

int entry_count = 0, f_bottom_of_table = FALSE;
IFSTAT *p;

struct rtnl_handle rth;

    pD->iftbl_entry_count = 0;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	if (rtnl_linkdump_req(&rth, AF_INET) < 0) {
		perror("Cannot send dump request\n");
		exit(1);
	}

    /* 2nd arg is name of function to act as filter */
	if (rtnl_dump_filter(&rth, get_nlmsg, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	rtnl_close(&rth);

    p = kern_db;

    /* Sanitize bottom entry 'next' value in kern_db table, and count entries*/
    while ( f_bottom_of_table == FALSE ) {
        if ( p->ifindex == 1 ) {
            p = p->next;
            p->next = NULL;
            p->name = NULL;
            p->ifindex = 0;
            f_bottom_of_table = TRUE;
        } else
            p = p->next;

        entry_count++;
    }
    
    pD->iftbl_entry_count = entry_count;
}


/******************************************************************************
*
* get_nlmsg - Retrieve Netlink data from kernel, store in kern_db 
*
******************************************************************************/
static int get_nlmsg(struct nlmsghdr *m, void *arg) {

struct ifinfomsg *ifi = NLMSG_DATA(m);
struct rtattr *tb[IFLA_MAX+1];
int len = m->nlmsg_len;
struct ifstat_ent *n;
int i;

	if (m->nlmsg_type != RTM_NEWLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

    /* Ignore interface if it's not up. */
	if (!(ifi->ifi_flags&IFF_UP))
		return 0;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

    /* Ignore interface if name is empty, or no stats. */
	if (tb[IFLA_IFNAME] == NULL || tb[IFLA_STATS] == NULL)
		return 0;

	n = malloc(sizeof(*n));
	if (!n)
		abort();
	n->ifindex = ifi->ifi_index;

    /* Grab the interface name, IE: lo, eth0, eth1, etc */
	n->name = strdup(RTA_DATA(tb[IFLA_IFNAME]));

	memcpy(&n->ival, RTA_DATA(tb[IFLA_STATS]), sizeof(n->ival));
	memset(&n->rate, 0, sizeof(n->rate));

    /* Gather all of the interface stats */
	for (i = 0; i < MAXS; i++)
		n->val[i] = n->ival[i];

	n->next = kern_db;
	kern_db = n;

	return 0;
}


/******************************************************************************
*
* printMsg - Print message to stderr (assumes output control by systemd)
*
******************************************************************************/
int printMsg(DATA *pD) {
    
char tBuf[MAXLINE + 1];

    tBuf[0] = '\0';
    snprintf(tBuf, sizeof(tBuf), "%s", pD->sBuf);
    fwrite(tBuf, sizeof(tBuf[0]), strlen(tBuf), stderr);
   
    return(RC_SUCCESS);
}


/******************************************************************************
*
* compareInfo - Workhorse of daemon to compare new to old stats, and report.
*
******************************************************************************/
int compareInfo(DATA *pD) {

char mStr[MAXLINE];
int i, f_dataFound, f_errorsFound;
IFSTAT *n, *o;
char eventLevel[eLvl_MAXSTR+1];
time_t tm_now;

    time(&tm_now);

    f_dataFound = 0;
    f_errorsFound = FALSE;

    /* Drive logic from watched interfaces */
    for ( i=0; i < pD->intfCount; i++ ) {

        if ( pD->intf[i].f_errDelayTime == TRUE ) {
            if ( tm_now >= pD->intf[i].errRawTm ) {
                pD->intf[i].f_errDelayTime = FALSE;
                pD->intf[i].errRawTm = -1;
            }
        } 

        if ( pD->intf[i].f_downDelayTime == TRUE ) {
            if ( tm_now >= pD->intf[i].downRawTm ) {
                pD->intf[i].f_downDelayTime = FALSE;
                pD->intf[i].downRawTm = -1;
            }
        } 

        n = kern_db;
        o = hist_db;

        eventLevel[0] = '\0';
        mStr[0] = '\0';
        f_dataFound = hasIntfData(pD->intf[i].name, &n, &o);

        switch ( f_dataFound ) {
            case -255:
                f_errorsFound = TRUE;
                getEventLevel(pD, i, 'D', eventLevel);

                if (strcmp(eventLevel, "Alert") == 0) {
                    now(pD, (time_t *) pD->intf[i].downRawTm);
                    dMSG("%s: %s is down! (Alert expires: %s)\n", 
                          eventLevel, pD->intf[i].name, pD->tBuf);
                } else
                    dMSG("%s: %s is down!\n", eventLevel, pD->intf[i].name);
                
                break;
            case   -1:
                f_errorsFound = TRUE;
                getEventLevel(pD, i, 'D', eventLevel);
                dMSG("%s: %s down within last iVal: %ds!\n", 
                      eventLevel, pD->intf[i].name, pD->wIntvl);
                break;
            case    0:
                dMSG("Info: %s up within last iVal: %ds\n", 
                        pD->intf[i].name, pD->wIntvl);
                break;
            case    1:
                f_errorsFound = chkForErrors(pD, i, mStr, n, o);
                if ( f_errorsFound == TRUE ) {
                    dMSG("%s\n", mStr);
                }
                break;
        }

        if ( strncmp(pD->runChatty, "y", 1) == 0 || 
             strncmp(pD->runChatty, "Y", 1) == 0 ) {
            if ( f_dataFound && f_errorsFound == FALSE ) {
                dMSG("No issue found: \"%s\" (Ival: %ds, Thld: %d)\n", 
                     pD->intf[i].name, pD->wIntvl, pD->tHld); 
            }
        }
       
        f_errorsFound = FALSE;
    }

    return(RC_SUCCESS);
}


/******************************************************************************
*
* defaultConfig - daemon's configuration if config file not specified.
*
******************************************************************************/
int defaultConfig(DATA *pD) {

    if ( pD->monIntfs[0]    == '\0' ) { strlcpy(pD->monIntfs, 
                                                "eth0",
                                                sizeof(pD->monIntfs)); }

    if ( pD->wIntvl         ==  0   ) { pD->wIntvl = (int) 300; }

    if ( pD->tHld           == -1   ) { pD->tHld = (__u32) 5; }

    if ( pD->errAlertIntvl  == -1   ) { pD->errAlertIntvl = (int) 168; }

    if ( pD->downAlertIntvl == -1   ) { pD->downAlertIntvl = (int) 24; }

    if ( pD->errDelayTime   == -1   ) { pD->errDelayTime = (int) 12; }

    if ( pD->downDelayTime  == -1   ) { pD->downDelayTime = (int) 8; }

    if ( pD->runChatty[0]   == '\0' ) { strlcpy(pD->runChatty,
                                        "N", sizeof(pD->runChatty)); }

    pD->sBuf[0] = '\0';
    pD->tBuf[0] = '\0';

    loadIntfArray(pD);

    return(RC_SUCCESS);
}


/******************************************************************************
*
* processConfig - Open, Read and process the daemon's configuration file
*
******************************************************************************/
int processConfig(DATA *pD) {

FILE *fp;
char fbuf[MAXLINE];
char *ptr;

    if ( pD->f_configFile == FALSE ) {
        dMSG("'-c configFile' not specified, using defaults.");

        defaultConfig(pD);

        return(RC_SUCCESS);
    } else {
    
        fp = fopen(pD->configFile, "r");
    
        if ( fp == (FILE *) NULL ) {
            dMSG("Error opening configFile: %s, using defaults", 
                 pD->configFile);

            defaultConfig(pD);

            return(RC_SUCCESS);
        }
    
        pD->f_validConfigFile = TRUE;

        while (fgets(fbuf, MAXLINE, fp) != NULL) {
            if ( fbuf[0] == '#' || fbuf[0] == '\n') {
                continue;
            }

            /**********************************************************
            * Interfaces
            ***********************************************************/
            ptr=strstr(fbuf,"Interfaces");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';

                dbg_prt("Interfaces (unvalidated), pD->sBuf: %s\n", 
                            pD->sBuf); 
    
                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    ++ptr;
                    pD->monIntfs[0] = '\0';
                    strlcpy(pD->monIntfs, (char *) ptr, sizeof(pD->monIntfs));

                }

                dbg_prt("Before loadIntfArray (U), pD->monIntfs: %s\n", 
                            pD->monIntfs); 

                loadIntfArray(pD);
            }

            /**********************************************************
            * monInterval
            ***********************************************************/
            ptr=strstr(fbuf,"monInterval");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf,sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';

                dbg_prt("monInterval (U), pD->sBuf: %s\n", 
                            pD->sBuf); 

                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    /**************************************************
                    * Must be digits only, and 6 or less digits with
                    * empty treated as bad input and default will be
                    * set later.
                    *
                    * ~12 days is maximum with 6 digits...
                    ***************************************************/
                    ++ptr;
                    if ( IsDigitsOnly(ptr) && 
                         strlen(ptr) < 7   &&
                         strlen(ptr) > 0 ) {
                        pD->wIntvl = atoi((const char *) ptr);

                        /**********************************************
                        * Don't accept interval less than 5 seconds
                        ***********************************************/
                        if ( pD->wIntvl < 5 ) {
                            dbg_prt("Info: monInterval set from %d to %d\n",
                                    pD->wIntvl, 5); 
                            pD->wIntvl = 5;
                        }

                        dbg_prt("monInterval (V), pD->wIntvl: %d\n", 
                                    pD->wIntvl); 
                    } else {
                        dbg_prt("Info: monInterval invalid-using default\n");
                    }
                }
            }

            /**********************************************************
            * thresHold
            ***********************************************************/
            ptr=strstr(fbuf,"thresHold");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';
    
                dbg_prt("thresHold (U), pD->sBuf: %s\n", 
                            pD->sBuf); 

                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    /**************************************************
                    * Must be digits only, and 9 or less digits, and
                    * must be greater than 0.  Empty treated as bad
                    * input and default will be set later.
                    *
                    * (1 billion - 1) is maximum in 9 digits.
                    * Note: __u32 max decimal value is 4,294,967,295.
                    ***************************************************/
                    ++ptr;
                    if ( IsDigitsOnly(ptr) && 
                         strlen(ptr) < 10  &&
                         strlen(ptr) > 0 ) {
                        pD->tHld = (__u32) atoi((const char *) ptr);

                        /**********************************************
                        * Don't accept threshold of 0, instead set to 1
                        ***********************************************/
                        if ( pD->tHld == 0 ) {
                            dbg_prt("Info: threshold set from %d to %d\n",
                                    pD->tHld, 1); 
                            pD->tHld = 1;
                        }

                        dbg_prt("thresHold (V), pD->tHld: %u\n", 
                                pD->tHld); 
                    } else {
                        dbg_prt("Info: thresHold invalid-using default\n");
                    } 
                }
            }

            /**********************************************************
            * errAlertIntvl
            ***********************************************************/
            ptr=strstr(fbuf,"errorAlertInterval");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';
    
                dbg_prt("errAlertIntvl (U), pD->sBuf: %s\n", 
                            pD->sBuf); 

                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    /**************************************************
                    * Must be digits only, and 4 or less digits with
                    * empty treated as bad input and default will be
                    * set later.  Can be a value of 0.
                    *
                    * ~41 days is maximum with 4 digits...
                    ***************************************************/
                    ++ptr;
                    if ( IsDigitsOnly(ptr) && 
                         strlen(ptr) < 5   &&
                         strlen(ptr) > 0 ) {
                        pD->errAlertIntvl = atoi((const char *) ptr);

                        dbg_prt("errAlertIntvl (V), pD->errAlertIntvl: %d\n", 
                                 pD->errAlertIntvl); 
                    } else {
                        dbg_prt("Info: errAlertIntvl invalid-using default\n");
                    }
                }
            }

            /**********************************************************
            * downAlertIntvl
            ***********************************************************/
            ptr=strstr(fbuf,"downAlertInterval");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';
    
                dbg_prt("downAlertIntvl (U), pD->sBuf: %s\n", 
                            pD->sBuf); 
    
                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    /**************************************************
                    * Must be digits only, and 4 or less digits with
                    * empty treated as bad input and default will be
                    * set later.  Can be a value of 0.
                    *
                    * ~41 days is maximum with 4 digits...
                    ***************************************************/
                    ++ptr;
                    if ( IsDigitsOnly(ptr) && 
                         strlen(ptr) < 5   &&
                         strlen(ptr) > 0 ) {
                        pD->downAlertIntvl = atoi((const char *) ptr);

                        dbg_prt("downAlertIntvl (V), pD->downAlertIntvl: %d\n", 
                                 pD->downAlertIntvl); 
                    } else {
                        dbg_prt("Info: downAlertIntvl invalid-using default\n");
                    }
                }
            }

            /**********************************************************
            * errDelayTime
            ***********************************************************/
            ptr=strstr(fbuf,"errorDelayTime");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';
    
                dbg_prt("errDelayTime (U), pD->sBuf: %s\n", 
                         pD->sBuf); 
    
                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    /**************************************************
                    * Must be digits only, and 4 or less digits with
                    * empty treated as bad input and default will be
                    * set later.  Can be a value of 0.
                    *
                    * ~41 days is maximum with 4 digits...
                    ***************************************************/
                    ++ptr;
                    if ( IsDigitsOnly(ptr) && 
                         strlen(ptr) < 5   &&
                         strlen(ptr) > 0 ) {
                        pD->errDelayTime = atoi((const char *) ptr);

                        dbg_prt("errDelayTime (V), pD->errDelayTime: %d\n", 
                                 pD->errDelayTime); 
                    } else {
                        dbg_prt("Info: errDelayTime invalid-using default\n");
                    }
                }
            }

            /**********************************************************
            * downDelayTime
            ***********************************************************/
            ptr=strstr(fbuf,"downDelayTime");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';
    
                dbg_prt("downDelayTime (U), pD->sBuf: %s\n", 
                         pD->sBuf); 
    
                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    /**************************************************
                    * Must be digits only, and 4 or less digits with
                    * empty treated as bad input and default will be
                    * set later.  Can be a value of 0.
                    *
                    * ~41 days is maximum with 4 digits...
                    ***************************************************/
                    ++ptr;
                    if ( IsDigitsOnly(ptr) && 
                         strlen(ptr) < 5   &&
                         strlen(ptr) > 0 ) {
                        pD->downDelayTime = atoi((const char *) ptr);

                        dbg_prt("downDelayTime (V), pD->downDelayTime: %d\n", 
                                 pD->downDelayTime); 
                    } else {
                        dbg_prt("Info: downDelayTime invalid-using default\n");
                    }
                }
            }

            /**********************************************************
            * chatty
            ***********************************************************/
            ptr=strstr(fbuf,"chatty");
    
            if ( (ptr != NULL) && (ptr == fbuf) ) {
                pD->sBuf[0] = '\0';
                strlcpy(pD->sBuf, fbuf, sizeof(pD->sBuf));
    
                /* remove newline */
                pD->sBuf[strlen(pD->sBuf)-1] = '\0';

                dbg_prt("chatty (U), pD->sBuf: %s\n", 
                            pD->sBuf); 
    
                ptr=strstr(pD->sBuf, "=");
    
                if ( ptr != NULL ) {
                    pD->runChatty[0] = '\0';
                    
                    ++ptr;
                    if ( (strncmp(ptr, "y", 1) == 0  ||
                          strncmp(ptr, "Y", 1) == 0  ||
                          strncmp(ptr, "n", 1) == 0  ||
                          strncmp(ptr, "N", 1) == 0) &&
                         strlen(ptr) == 1 ) {
                        strlcpy(pD->runChatty, (char *) ptr, 
                                sizeof(pD->runChatty));

                        dbg_prt("chatty (V), pD->runChatty: %s\n", 
                                    pD->runChatty); 
                    } else {
                        dbg_prt("Info: runChatty invalid-using default\n");
                    }
                }
            }
        }

        /* Now catch anything else not specified in config file      */
        defaultConfig(pD);
    }

    return(RC_SUCCESS);
}


/******************************************************************************
*
* removeSpaces - Remove spaces from a sting
*
******************************************************************************/
void removeSpaces(char* s) {

const char* d;

    d = s;
    do {
        while (*d == ' ') {
            ++d;
        }
    } while ((*s++ = *d++));
}


/******************************************************************************
*
* removeDblQuotes - Remove double quotes from a sting
*
******************************************************************************/
void removeDblQuotes(char* s) {

const char* d;

    d = s;
    do {
        while (*d == '"') {
            ++d;
        }
    } while ((*s++ = *d++));
}


/******************************************************************************
*
* loadIntfArray - Load IntfArray from supplied Configuration Data
*
******************************************************************************/
void loadIntfArray(DATA *pD) {

int i;
char input[MAXLINE + 1];
char *token;

    for (i=0;i<IMAXCNT;i++) { pD->intf[i].name[0] = '\0'; }

    i = 0;
    pD->intfCount = 0;

    input[i] = '\0';
    strlcpy(input, pD->monIntfs, sizeof(input));
    removeSpaces(input);
    removeDblQuotes(input);

    /* Load pD->intf->name, by parsing substrings in input,  */
    /* separated by commas                                   */
    token = strtok (input,",");

    while ( token != NULL && i < IMAXCNT-1 ) {
        pD->intf[i].name[0] = '\0';
        strlcpy(pD->intf[i].name, token, sizeof(pD->intf[i].name));
        i++;
        pD->intfCount++;
        token = strtok (NULL, ",");
    }

    /* Put back cleaned list of input -- no spaces           */
    pD->monIntfs[0] = '\0';
    i = 0;

    while (i < pD->intfCount ) { 
        strlcat(pD->monIntfs, pD->intf[i].name, sizeof(pD->monIntfs));

        if ( i+1 < pD->intfCount ) {
            strlcat(pD->monIntfs, ",", sizeof(pD->monIntfs));
        }

        i++;
    }
}


/******************************************************************************
*
* hasIntfData - Function to determine if stats exist for a watched interface
*
*    Input: Watched Interface Name
*  Returns: TRUE  = Data found for Intf Name in both kern_db and hist_db
*              0  = Data found for Intf Name only in kern_db
*             -1  = Data found for Intf Name only in hist_db
*           -255  = No Data found for Intf Name in either kern_db or hist_db
*
*           if TRUE, and IFSTAT pointers to new(kern_db), and old(hist_db)
*
******************************************************************************/
int hasIntfData(char *iName, IFSTAT **n, IFSTAT **o) {

int f_kern_db, f_hist_db;
IFSTAT *tn, *to;

    tn = *n;
    to = *o;

    f_kern_db = FALSE;
    f_hist_db = FALSE;

    /* ifindex 1 is always lo, so check all others */
    while (tn->ifindex > 1 && tn->name != NULL ) {
        if ( strcmp(iName, tn->name) == 0 ) { 
            f_kern_db = TRUE; 
        } 

        /* If match, break out, leaving n current  */
        if ( f_kern_db ) { 
            break; 
        }

        /* Otherwise, increment n to next entry    */
        tn = tn->next;
        *n = tn;
    }

    /* ifindex 1 is always lo, so check all others */
    while (to->ifindex > 1 && to->name != NULL ) {
        if ( strcmp(iName, to->name) == 0 ) { 
            f_hist_db = TRUE; 
        }

        /* If match, break out, leaving o current  */
        if ( f_hist_db ) { 
            break; 
        }

        /* Otherwise, increment n to next entry    */
        to = to->next;
        *o = to;
    }

    if ( f_kern_db == FALSE && f_hist_db == FALSE ) { return(-255); }
    if ( f_kern_db == FALSE && f_hist_db == TRUE  ) { return(-1)  ; }
    if ( f_kern_db == TRUE  && f_hist_db == FALSE ) { return(0)   ; }

    return(TRUE);
}


/******************************************************************************
*
* chkForErrors - Function to determine if current errors exist for an interface
*
******************************************************************************/
int chkForErrors(DATA *pD, int i, char *mStr, IFSTAT *n, IFSTAT *o) {

struct rtnl_link_stats64 *sn;
struct rtnl_link_stats64 *so;
char buf[MAXLINE];
char eventLevel[6];
int f_ErrorsFound;

    sn = (struct rtnl_link_stats64 *) &n->val;
    so = (struct rtnl_link_stats64 *) &o->val;
    
    buf[0] = '\0';
    eventLevel[0] = '\0';
    getEventLevel(pD, i, 'E', eventLevel);
    snprintf(buf, sizeof(buf), "%s: %s:", eventLevel, pD->intf[i].name);
    f_ErrorsFound = FALSE;

    if ( sn->rx_length_errors    >= (pD->tHld + so->rx_length_errors   ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " rx_length_errors=%llu[%llu]",
                 sn->rx_length_errors,
                 sn->rx_length_errors - so->rx_length_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->rx_over_errors      >= (pD->tHld + so->rx_over_errors     ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " rx_over_errors=%llu[%llu]", 
                 sn->rx_over_errors,
                 sn->rx_over_errors - so->rx_over_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->rx_crc_errors       >= (pD->tHld + so->rx_crc_errors      ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " rx_crc_errors=%llu[%llu]", 
                 sn->rx_crc_errors,
                 sn->rx_crc_errors - so->rx_crc_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->rx_frame_errors     >= (pD->tHld + so->rx_frame_errors    ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " rx_frame_errors=%llu[%llu]", 
                 sn->rx_frame_errors,
                 sn->rx_frame_errors - so->rx_frame_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->rx_fifo_errors      >= (pD->tHld + so->rx_fifo_errors     ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " rx_fifo_errors=%llu[%llu]", 
                 sn->rx_fifo_errors,
                 sn->rx_fifo_errors - so->rx_fifo_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->rx_missed_errors    >= (pD->tHld + so->rx_missed_errors   ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " rx_missed_errors=%llu[%llu]", 
                 sn->rx_missed_errors,
                 sn->rx_missed_errors - so->rx_missed_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->tx_aborted_errors   >= (pD->tHld + so->tx_aborted_errors  ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " tx_aborted_errors=%llu[%llu]", 
                 sn->tx_aborted_errors,
                 sn->tx_aborted_errors - so->tx_aborted_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->tx_carrier_errors   >= (pD->tHld + so->tx_carrier_errors  ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " tx_carrier_errors=%llu[%llu]", 
                 sn->tx_carrier_errors,
                 sn->tx_carrier_errors - so->tx_carrier_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->tx_fifo_errors      >= (pD->tHld + so->tx_fifo_errors     ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " tx_fifo_errors=%llu[%llu]", 
                 sn->tx_fifo_errors,
                 sn->tx_fifo_errors - so->tx_fifo_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->tx_heartbeat_errors >= (pD->tHld + so->tx_heartbeat_errors) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " tx_heartbeat_errors=%llu[%llu]", 
                 sn->tx_heartbeat_errors,
                 sn->tx_heartbeat_errors - so->tx_heartbeat_errors);
        f_ErrorsFound = TRUE;
    }

    if ( sn->tx_window_errors    >= (pD->tHld + so->tx_window_errors   ) ){
        snprintf(buf + strlen(buf), 
                 sizeof(buf) - strlen(buf),
                 " tx_window_errors=%llu[%llu]", 
                 sn->tx_window_errors,
                 sn->tx_window_errors - so->tx_window_errors);
        f_ErrorsFound = TRUE;
    }

    if ( f_ErrorsFound == TRUE ) {
        snprintf(mStr, MAXLINE, "%s", buf);
        return(TRUE);
    }

    return(FALSE);
}


/******************************************************************************
*
* Function to process the command line
*
******************************************************************************/
int processCmdline(int argc, char ** argv, DATA * pD) {

extern char *optarg;                        
int a;                                     

    pD->f_configFile = FALSE;
    pD->f_validConfigFile = FALSE;
    pD->configFile[0] = '\0';
    pD->f_debug = FALSE;

    /*********************************************************************
    * Get Commmand line options/arguments
    *********************************************************************/
    while ((a = getopt(argc, argv, "h?c:DV")) != EOF) {
        switch(a) {
            case 'c':            /* Configuration file                  */
                 pD->f_configFile = TRUE;
                 if ( strlen(optarg) < (MAXLINE - 1) ) {
                     strlcpy(pD->configFile, optarg, sizeof(pD->configFile));
                 }
                 break;
            case 'D':            /* Debug Flag                          */
                 pD->f_debug = TRUE;
                 break;
            case 'V':            /* Version Flag                        */
                 printVersion;
                 exit(0);
            case 'h':            /* Help                                */
            case '?':  
                 usage();
                 exit(0);
            default:             /* Anything else                       */
                 fprintf(stderr,"Error: Must supply valid arguments!\n");
                 usage();
                 exit(-1);
            }
    }

    return(RC_SUCCESS);
}


/******************************************************************************
*
* now - Return the date/time in format: YYYYMMDDHHMMSS
*
******************************************************************************/
char *now(DATA *pD, time_t *eTm) {

time_t eTime;
struct tm *tm;

    pD->tBuf[0] = '\0';
 
    /* If passed-in eTm is NULL, get current time, otherwise convert eTm */
    if ( !eTm ) {
        time(&eTime);
    } else {
        eTime = (time_t) eTm;
    }

    tm = localtime(&eTime);

    /* int snprintf(char *str, size_t size, const char *format, ...);    */
    snprintf((char *) pD->tBuf, (size_t) 20, 
             (const char *) "%04d-%02d-%02dT%02d:%02d:%02d",
             tm->tm_year+1900,
             tm->tm_mon+1,
             tm->tm_mday,
             tm->tm_hour,
             tm->tm_min,
             tm->tm_sec);

    return(pD->tBuf);
}


/******************************************************************************
*
* getEventLevel - Determine if Event Level should be "Error: " or "Alert: "
*
******************************************************************************/
void getEventLevel(DATA *pD, int i, char eventType, char *eventLevel) {

time_t now;
time_t errRawTmValue;
time_t downRawTmValue;
time_t waitValue;
time_t expireRawTm;

    time(&now);

    switch ( eventType ) {
        case 'E':
            errRawTmValue = pD->intf[i].errRawTm;
            waitValue     = pD->errAlertIntvl*60*60;
            expireRawTm   = now + waitValue;

            if ( errRawTmValue == -1 || (now >= errRawTmValue) ) {
                pD->intf[i].errRawTm = expireRawTm;
                strlcpy(eventLevel, "Error", eLvl_MAXSTR+1);
            } else
                strlcpy(eventLevel, "Alert", eLvl_MAXSTR+1);

            break;
        case 'D':
            downRawTmValue = pD->intf[i].downRawTm;
            waitValue     = pD->downAlertIntvl*60*60;
            expireRawTm   = now + waitValue;

            if ( downRawTmValue == -1 || (now >= downRawTmValue) ) {
                pD->intf[i].downRawTm = expireRawTm;
                strlcpy(eventLevel, "Error", eLvl_MAXSTR+1);
            } else
                strlcpy(eventLevel, "Alert", eLvl_MAXSTR+1);

            break;
    }
    return;
}



/******************************************************************************
*
* initializeDelays - Upon Startup, set default delay times
*
******************************************************************************/
int initializeDelays(DATA *pD) {

time_t errRawTmValue;
time_t errWaitValue;
time_t downRawTmValue;
time_t downWaitValue;
time_t now;
int i;

    errWaitValue   = pD->errDelayTime*60*60;
    errRawTmValue  = pD->startRawTm + errWaitValue;

    downWaitValue  = pD->downDelayTime*60*60;
    downRawTmValue = pD->startRawTm + downWaitValue;
   
    time(&now);

    for (i=0; i < pD->intfCount; i++) {
        pD->intf[i].f_errDelayTime  = TRUE;
        pD->intf[i].f_downDelayTime = TRUE;

        pD->intf[i].errRawTm = errRawTmValue;
        if ( now >= pD->intf[i].errRawTm ) { 
            pD->intf[i].f_errDelayTime = FALSE;
            pD->intf[i].errRawTm = -1;
        }

        pD->intf[i].downRawTm = downRawTmValue;
        if ( now >= pD->intf[i].downRawTm ) {
            pD->intf[i].f_downDelayTime = FALSE;
            pD->intf[i].downRawTm = -1;
        }
    }

    return(RC_SUCCESS);
}


/******************************************************************************
*
* copyCurrent_to_History - Copies the current kernel interface statistics 
*                          (kern_db) to history statistics (hist_db).  
*
* Notes: kern_db is a linked list of interfaces, with each entry added 
*        previously (by the kernel). The first entry added (ifindex=0) is an 
*        empty one; added next is the loopback interface lo (ifindex=1); 
*        followed by all others, with ifindex incrementing each time, etc.
*
*        As each entry is added, it becomes the top of the list, and the 
*        (ifstat_ent *kern_db) is adjusted to point to the new top of the list
*        entry.  The 'next' pointer of each entry (except ifindex=0) will 
*        contain the address of the previous entry.  User space programs, such
*        as iferrmond, will have received the pointer to this list of 
*        interfaces (from the kernel) pointing at the top of this list -- and
*        that's what kern_db represents.
*                          
*        As received from the kernel, each entry in the list has two "malloc's"
*        (exception: ifindex=0, only #1 below), with their resulting pointers, 
*        related to the entry.  (Note, that each pointer will need to be freed 
*        later on, for both kern_db and hist_db - otherwise memory leakage will
*        occur):
*           1) The malloc of the entry itself, with the pointer to this entry
*              *only* existing in 1 of 2 places:
*                a) As kern_db, which points to the top of the list (last one),
*                b) As the 'next' pointer within the entry added *after* a 
*                   given interface entry.
*           2) Each entry contains a pointer to it's interface 'name', IE: lo, 
*              eth0, eth1, etc, which is created from an strdup(3), a Posix
*              call, that front-ends a malloc to create the pointer.
*
*        The reason for all of this description around this linked list of
*        interfaces, is because in order to properly copy the linked list
*        originally created by the kernel, the copy *must* be created, with
*        each entry added in the exact same order, so that linkage between the 
*        entries match what the kernel provides -- otherwise, it would not be 
*        an exact copy.
*
*        An important point is that as interfaces are removed and added back
*        this can leave gaps in the consecutive ifindex numbers, so in the
*        logic below, allow for this possibility.
******************************************************************************/
int copyCurrent_to_History(IFSTAT **kern_db, IFSTAT **hist_db, DATA *pD) {

int i, j, k, index_max, f_index_found;
IFSTAT *h, *c;

    h = *hist_db;
    c = *kern_db;

    /* Grab the ifindex entry number of top of the list entry,  */
    /* (of kern_db)                                             */
    index_max = c->ifindex;
    index_max++;

    /* 'i' represents the ifindex number of each entry to be    */
    /* added to the copy (hist_db), starting with ifindex=0     */
    for ( i=0; i < index_max; i++ ) {
        f_index_found = FALSE;
       
        /* Search kern_db for an ifindex matching 'i', and upon */
        /* breaking out of the for loop, the 'c' pointer will   */
        /* point to a matching kern_db entry, or it's possible  */  
        /* a match was not found due to gaps in the ifindex     */
        /* range.                                               */
        for ( k=0; k < (pD->iftbl_entry_count +1); k++ ) {
            if ( c->ifindex == i ) {
                f_index_found = TRUE;
                break;
            } else
               c = c->next; 
        } 

        /* There can be holes in the index numbers, so if the   */
        /* value of 'i' is not in the list, break out and try   */
        /* the next increment of 'i'                            */
        if ( f_index_found == FALSE ) { 
            /* Reset c back to the top of kern_db               */
            c = *kern_db;
            continue; 
        }

        /* malloc #1 - Create the new entry                     */
        h = malloc(sizeof(*h));
        if ( !h )  
            return(RC_FAILURE); 
        else {
            memset(h, 0, sizeof(*h));
            h->ifindex = c->ifindex;
        }
        
        /* Only copy interface data for ifindex greater than 0  */ 
        if ( h->ifindex > 0 ) {

            /* malloc #2 - Create the pointer to the intf name  */
            h->name = strdup(c->name);
            
            memcpy(&h->ival, &c->ival, sizeof(c->ival));
            memset(&h->rate, 0, sizeof(c->rate));
            
            /* Gather all of the interface stats */
            for (j = 0; j < MAXS; j++)
                h->val[j] = c->ival[j];
        }

        /* Create the linkage, and set the new top-of-the-list  */
        h->next = *hist_db;
        *hist_db = h;

        /* Reset c back to the top of kern_db                   */
        c = *kern_db;
    }

    return(RC_SUCCESS);
}

/******************************************************************************
*
* free_db - De-construct (or free) both pointers related to each entry in a 
*           linked list of type (ifstat_ent *)
*
* Notes: 1st pass: free the memory for the pointer for each interface name
*        2nd pass: free each entry in the table, finally removing ifindex=0. 
*
* See the flowerbox comments for copyCurrent_to_History, for background on the
* structure of a linked list of interfaces.
*
******************************************************************************/
void free_db(IFSTAT *db) {

IFSTAT *p, *d, *n;

    p = d = n = db;

    /* Clean up from strdup's for the interface names   */
    while ( p->name != NULL ) {
        free(p->name);
        p->name = NULL;
        p = p->next;
    }

    /* Clean up from malloc's for each interface entry  */
    while ( d->ifindex > 0 ) {
        n = d->next;
        free(d);
        d = n;
    }

    free(d);
    return;
}

/******************************************************************************
*
* usage - provide help for iferrmond
*
******************************************************************************/
void usage(void) {

    fprintf(stderr,"\n");
    fprintf(stderr,"iferrmond [ -V ] | [ -h | -? ]\n");
    fprintf(stderr,"iferrmond [ -d ] [ -c {configuration file} ]\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"Arguments:\n");
    fprintf(stderr," -V           Optional - Report version, and exit.\n");
    fprintf(stderr," -h | -?      Optional - Display this help, and exit.\n");
    fprintf(stderr," -d           Optional - Debug output to syslog.\n");
    fprintf(stderr," -c conf_file Optional - configuration file.\n");
    fprintf(stderr,"\n");

    return;
}


/******************************************************************************
*
* SIGTERM_handler - When our PID is issued any below (all are the same):
*                   kill PID
*                   kill -SIGTERM PID
*                   kill -15 PID 
*
* Note: systemd will issue "kill PID" when stopping iferrmond.service via
*       "systemctl stop iferrmond.service"
*
******************************************************************************/
void  SIGTERM_handler(int sig) {

    signal(sig, SIG_IGN);

    fprintf(stderr, "Info: SIGTERM (%d) received, shutting down.\n", sig); 

    if ( remove("/var/run/iferrmond/iferrmond.pid") != 0 ) {
        fprintf(stderr, 
                "Error: %d (%s) removing /var/run/iferrmond/iferrmond.pid!\n",
                errno, strerror(errno));
    } else {
        fprintf(stderr, 
                "Info: /var/run/iferrmond/iferrmond.pid removed.\n");
    }

     exit(0);
}


/******************************************************************************
* IsDigitsOnly - Check that string contains only digits
*
******************************************************************************/
#include <stdbool.h>
#include <ctype.h>

bool IsDigitsOnly(const char *str) {
char c;

    while ((c = *str++) != '\0')
        if (!isdigit(c))
            return false;

    return true;
}
