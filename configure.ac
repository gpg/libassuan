# configure.ac - for libassuan
#       Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc,
# 
# This file is part of GnuPG.
# 
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.52)
# Version number: Remember to change it immediately *after* a release.
#                 Add a "-cvs" prefix for non-released code.
AC_INIT(libassuan, 0.0.1-cvs, gpa-dev@gnupg.org)

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR(src/assuan.h)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_MAINTAINER_MODE

AH_TOP([
/* We need this, because some autoconf tests rely on this (e.g. stpcpy)
   and it should be used for new programs anyway. */
#define _GNU_SOURCE  1
])

AH_BOTTOM([
/* Some global constants. */
#ifdef HAVE_DRIVE_LETTERS
#define GNUPG_DEFAULT_HOMEDIR "c:/gnupg"
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.gnupg"
#endif 
#define GNUPG_PRIVATE_KEYS_DIR "private-keys-v1.d"
])



AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",
                                        [Bug report address])

# Checks for programs.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
#AC_ARG_PROGRAM

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi

case "${target}" in
    *-*-mingw32*)
        PRINTABLE_OS_NAME="MingW32"
        AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
                  [defined if we run on some of the PCDOS like systems 
                   (DOS, Windoze. OS/2) with special properties like
                    no file modes])
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        PRINTABLE_OS_NAME="OS/2"
        ;;
    i?86-*-msdosdjgpp*)
        PRINTABLE_OS_NAME="MSDOS/DJGPP"
        try_dynload=no
        ;;
    *-linux*)
        PRINTABLE_OS_NAME="GNU/Linux"
        ;;
dnl let that after linux to avoid gnu-linux problems
    *-gnu*)
        PRINTABLE_OS_NAME="GNU/Hurd"
        ;;
    *)
        PRINTABLE_OS_NAME=`uname -s || echo "Unknown"`
        ;;
esac
AC_DEFINE_UNQUOTED(PRINTABLE_OS_NAME, "$PRINTABLE_OS_NAME",
                   [A human readable text with the name of the OS])

# For src/libassuan-config.in
LIBASSUAN_CONFIG_LIBS="-lassuan"
LIBASSUAN_CONFIG_CFLAGS=""
AC_SUBST(LIBASSUAN_CONFIG_LIBS)
AC_SUBST(LIBASSUAN_CONFIG_CFLAGS)

AC_CONFIG_COMMANDS([assuan-defs],[chmod +x src/libassuan-config])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h locale.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

# Checks for library functions.

AC_CHECK_FUNCS(flockfile funlockfile)

# Check for funopen
AC_CHECK_FUNCS(funopen)
if test $ac_cv_func_funopen != yes; then
  # No funopen but we can implement that in terms of fopencookie.
  AC_CHECK_FUNCS(fopencookie, AC_LIBOBJ(funopen), AC_MSG_ERROR([[
No implementation of fopencookie or funopen available.
]]))
fi

AC_REPLACE_FUNCS(isascii)
AC_REPLACE_FUNCS(putc_unlocked)
AC_REPLACE_FUNCS(memrchr)

AC_CONFIG_FILES([
Makefile
src/Makefile
src/libassuan-config
doc/Makefile
tests/Makefile
])
AC_OUTPUT
