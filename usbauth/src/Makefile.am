# Copyright (C) 2017 Stefan Koch <stefan.koch10@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

sbin_PROGRAMS = usbauth
usbauth_CFLAGS = $(USBAUTH_CFLAGS) $(UDEV_CFLAGS) $(DBUS_CFLAGS)
usbauth_SOURCES = usbauth.c
usbauth_LDADD = $(USBAUTH_LIBS) $(UDEV_LIBS) $(DBUS_LIBS)
