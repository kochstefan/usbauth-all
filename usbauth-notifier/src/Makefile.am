# Copyright (C) 2017-2018 Stefan Koch <stefan.koch10@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

notifier_installdir = $(exec_prefix)/lib/$(PACKAGE)
notifier_install_PROGRAMS = usbauth-notifier
bin_PROGRAMS = usbauth-npriv
usbauth_notifier_CFLAGS = -include config.h $(USBAUTH_CFLAGS) $(NOTIFY_CFLAGS) $(UDEV_CFLAGS) $(DBUS_CFLAGS)
usbauth_notifier_SOURCES = usbauth-notifier.c
usbauth_notifier_LDADD = $(USBAUTH_LIBS) $(NOTIFY_LIBS) $(UDEV_LIBS) $(DBUS_LIBS)
usbauth_npriv_CFLAGS = -include config.h
usbauth_npriv_SOURCES = usbauth-npriv.c
