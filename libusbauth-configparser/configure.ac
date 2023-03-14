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

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libusbauth-configparser], [1.0.5], [stefan.koch10@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_SYS_LARGEFILE
AM_PROG_AR
LT_INIT

# Checks for programs.
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([inttypes.h libintl.h malloc.h stddef.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strtol])

PKG_CHECK_MODULES([UDEV], [libudev])

AC_CONFIG_FILES([Makefile
                 data/Makefile
                 data/libusbauth-configparser.pc
                 src/Makefile
                 libusbauth-configparser.spec])
AC_OUTPUT
