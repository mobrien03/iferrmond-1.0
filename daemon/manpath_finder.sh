#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later 
# This file is part of iferrmond 
#
# manpath_finder_app
#
# This is a bash script written to determine the operating system being used. 
# Furthermore, this allows a value to be passed back to a variable within the Makefile.
#
# The paths that follow are for manual pages.
# Local Path for SuSE distro is:                /usr/local/man/man1
# Local Path for Oracle (RH variant) distro is: /usr/local/share/man/man1
# If /usr/local/man exists, but not sub-dir man1, then use /usr/local/man/man1

if [ -d "/usr/local/man/man1" ]
then
    returnval=$"/local/man/man1"
elif [ -d "/usr/local/share/man/man1" ]
then
    returnval="/local/share/man/man1"
elif [ -d "/usr/local/man" ]
then
    returnval="/local/man/man1"
else
    returnval="ERROR"
fi

echo $returnval
