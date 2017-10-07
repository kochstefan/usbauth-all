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

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([usbauth], [1.0], [stefan.koch10@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_PROG_AR
LT_INIT

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h stdlib.h string.h sys/file.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([strtol])

PKG_CHECK_MODULES([USBAUTH], [libusbauth-configparser])
PKG_CHECK_MODULES([UDEV], [libudev])
PKG_CHECK_MODULES([DBUS], [dbus-1])

AC_CONFIG_FILES([Makefile
                 data/Makefile
                 src/Makefile
                 usbauth.spec])
AC_OUTPUT
