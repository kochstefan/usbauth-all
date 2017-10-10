# Copyright (C) 2017 Stefan Koch <stefan.koch10@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.

BUILT_SOURCES = syn.usbauth_yy.h
AM_YFLAGS = -d
lib_LTLIBRARIES = libusbauth-configparser.la
libusbauth_configparser_la_CFLAGS = $(UDEV_CFLAGS)
libusbauth_configparser_la_SOURCES = lex.usbauth_yy.l syn.usbauth_yy.y usbauth-configparser.c
libusbauth_configparser_la_LIBADD = $(UDEV_LIBS)
libusbauth_configparser_la_LDFLAGS = -version-info 1:0:0
usbauthincludedir = $(includedir)/usbauth
usbauthinclude_HEADERS = generic.h usbauth-configparser.h

clean-local:
	rm -f lex.usbauth_yy.c syn.usbauth_yy.h syn.usbauth_yy.c

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/*.{la,a}
