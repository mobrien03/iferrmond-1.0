/*******************************************************************************
* Credits and Use Statement (daemon_SysV) - Must stay with source code!
********************************************************************************
* daemon_SysV:  Will perform optional [-V] SysV daemon initialization
*
* This file is part of iferrmond.
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
*******************************************************************************/

/*******************************************************************************
* MODIFICATION lOG
* Date     Programmer      Description
* -----------------------------------------------------------------------------
* 20221031 M. O'Brien      Initial coding
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "common.h"

/******************************************************************************
* daemon_SysV initialization, as recommended in manual page: daemon(7)
******************************************************************************/
void daemon_SysV(void) {
pid_t pidOne, pidTwo; 
int i, fd, pipefd[2];
FILE *fp;
sigset_t allSigs;
char buf[128];
char doneBuf[5];
struct rlimit *rlim;

    /**************************************************************************
    * Initialization
    **************************************************************************/
    buf[0] = '\0';
    doneBuf[0] = '\0';
    rlim = NULL;

    /**************************************************************************
    * Step 1: Close all open file descriptors 
    * Note: Instructions indicate to close all but fd 0,1 and 2.  However, 
    *       those will be closed a bit later anyway, to re-assign them in 
    *       Step 9, so do them all now, and save some code later....
    **************************************************************************/
    for (fd=0; fd < getrlimit(RLIMIT_NOFILE, rlim); fd++) { close(fd); }

    /**************************************************************************
    * Step 1a: Set up un-named pipe for child status later on...
    **************************************************************************/
    pipe(pipefd);                       /* pipe for child (daemon) -> parent */

    /**************************************************************************
    * Step 2: Reset all signal handlers to default
    **************************************************************************/
    for (i=1; i < _NSIG; i++) { signal(i, SIG_DFL); }

    /**************************************************************************
    * Step 3: Reset the signal mask to SIG_UNBLOCK for all signals
    **************************************************************************/
    sigemptyset(&allSigs);
    sigfillset(&allSigs);
    sigprocmask(SIG_UNBLOCK, &allSigs, NULL);

    /**************************************************************************
    * Step 4: Sanitize the environment
    **************************************************************************/
    clearenv();                                     /* Clears all variables  */

    /**************************************************************************
    * Step 5: Call fork(), to create a background process (1st child)
    **************************************************************************/
    pidOne=fork();                                  /* Create new child proc */

    if ( pidOne < 0 ) { exit(150); }                /* oops, max processess! */

    if ( pidOne > 0 ) {                             /* this is the parent    */
        /**********************************************************************
        * Step 15: Original parent exits after daemon startup reported "Done"
        **********************************************************************/
        close(pipefd[1]);                           /* don't need it...      */
        i=0;
        buf[0] = '\0';

        while( i < 5 ) { read(pipefd[0], &buf[i], 1); i++; }
        
        if ( strcmp(buf, "Done") == 0 ) exit(0); else exit(151);
    } 
    
    if ( pidOne == 0 ) {                            /* this is the 1st child */
        /**********************************************************************
        * Step 6: In 1st child, call setsid() to detach from terminal
        **********************************************************************/
        setsid();

        /**********************************************************************
        * Step 7: In 1st child, call fork() again (2nd child and ultimately
        * the final daemon created)
        **********************************************************************/
        pidTwo=fork();                              /* Create new child proc */

        if ( pidTwo < 0 ) { exit(150); }            /* oops, max processes!  */

        if ( pidTwo > 0 ) {                         /* this is the 1st child */
            /******************************************************************
            * Step 8: 1st child exiting...
            ******************************************************************/
            exit(0); 
        } else if ( pidTwo == 0 ) {                 /* this is final daemon  */
            /******************************************************************
            * Step 9: connect /dev/null to standard input, output, and error
            ******************************************************************/
            open("/dev/null", O_RDONLY);
            open("/dev/null", O_RDWR);
            open("/dev/null", O_RDWR);

            /******************************************************************
            * Step 10: reset umask
            ******************************************************************/
            umask(0);

            /******************************************************************
            * Step 11: cd to root (/)
            ******************************************************************/
            chdir("/");

            /******************************************************************
            * Step 12: create pid file
            ******************************************************************/
            buf[0] = '\0';
            snprintf(buf, sizeof(buf), "%d\n", getpid());

            mkdir("/var/run/iferrmond", 0755);

            /* TODO: These hard-codes have gotta go...                       */
            chown("/var/run/iferrmond", 9152, 9479);

            fp = fopen("/var/run/iferrmond/iferrmond.pid", "w+");
            fwrite(buf, sizeof(buf[0]), strlen(buf), fp);
            fclose(fp);

            /* TODO: These hard-codes have gotta go...                       */
            chown("/var/run/iferrmond/iferrmond.pid", 9152, 9479);

            chmod("/var/run/iferrmond/iferrmond.pid", 0644);

            /******************************************************************
            * Step 13: drop privleges
            ******************************************************************/
            /* TODO: These hard-codes have gotta go...                       */
            seteuid(9152);
            
            /******************************************************************
            * Step 14: Signal original parent daemon processing is Done.
            ******************************************************************/
            close(pipefd[0]);                       /* Don't need it...      */ 
            doneBuf[0] = '\0';

            strcpy(doneBuf, "Done");                /* Now parent can exit...*/
            write(pipefd[1], doneBuf, sizeof(doneBuf));

            close(pipefd[1]);                       /* Daemonizing all Done! */ 
        }
    }
}
