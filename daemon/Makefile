# SPDX-License-Identifier: GPL-2.0
TARGETS=iferrmond 
COMPONENTS=iferrmond iferrmond.conf iferrmond_default.conf iferrmond.service iferrmond.1 
DEPS = common.h  svc_common.h


ifeq ($(PREFIX),)
	PREFIX := /usr
endif

include ../config.mk

.PHONY: all install $(COMPONENTS)

all: $(TARGETS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

iferrmond: iferrmond.o daemon_SysV.o strl.o
	$(QUIET_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o iferrmond iferrmond.o daemon_SysV.o strl.o $(LDLIBS) -lm
	objdump -S iferrmond > iferrmond_objdump-S.txt 2>&1

$(man_path):
	man_path=$(shell ./manpath_finder.sh)	

install: all
	install -d ${DESTDIR}$(PREFIX)$(shell ./manpath_finder.sh)
	install -m 644 -o root -g root iferrmond.1 ${DESTDIR}$(PREFIX)$(shell ./manpath_finder.sh)
	install -d ${DESTDIR}$(PREFIX)/local/bin
	install -m 755 -o 9152 -g 9479 iferrmond ${DESTDIR}$(PREFIX)/local/bin
	install -d ${DESTDIR}$(PREFIX)/local/share/iferrmond
	install -m 644 -o root -g root iferrmond_default.conf ${DESTDIR}$(PREFIX)/local/share/iferrmond
	install -d ${DESTDIR}$(PREFIX)/local/etc
	install -m 644 -o root -g root iferrmond_default.conf ${DESTDIR}$(PREFIX)/local/etc/iferrmond.conf
	install -d ${DESTDIR}$(PREFIX)/lib/systemd/system
	install -m 644 -o root -g root iferrmond.service ${DESTDIR}$(PREFIX)/lib/systemd/system

start:
	systemctl enable iferrmond.service
	systemctl daemon-reload
	systemctl start iferrmond.service 
	systemctl status -l iferrmond.service 

uninstall:
	pkill iferrmond || true
	rm -f ${DESTDIR}$(PREFIX)$(shell ./manpath_finder.sh)/iferrmond.1
	rm -f ${DESTDIR}$(PREFIX)/local/bin/iferrmond
	rm -f ${DESTDIR}$(PREFIX)/local/share/iferrmond/iferrmond_default.conf
	rm -f ${DESTDIR}$(PREFIX)/local/etc/iferrmond.conf
	rm -f ${DESTDIR}$(PREFIX)/lib/systemd/system/iferrmond.service
	systemctl disable iferrmond.service
	systemctl daemon-reload

clean:
	rm -f *.o $(TARGETS) 
