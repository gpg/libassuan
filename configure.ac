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
AC_PREREQ(2.59)
min_automake_version="1.9.3"

# Version number: Remember to change it immediately *after* a release.
#                 Add a "-cvs" prefix for non-released code.
AC_INIT(libassuan, 0.6.10, gnupg-devel@gnupg.org)
# Note, that this is not yet available as a shared library.

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR(src/assuan.h)
AM_CONFIG_HEADER(config.h)

AC_GNU_SOURCE


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


# 
# Options depending on the host OS.
# 
have_dosish_system=no
have_w32_system=no
case "${host}" in
    *-mingw32*)
        have_dosish_system=yes
        have_w32_system=yes
        ;;
esac

if test "$have_dosish_system" = yes; then
   AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
             [Defined if we run on some of the PCDOS like systems 
              (DOS, Windoze. OS/2) with special properties like
              no file modes])
fi
dnl AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = yes)

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
dnl AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)



# For src/libassuan-config.in
LIBASSUAN_CONFIG_LIBS="-lassuan"
LIBASSUAN_CONFIG_CFLAGS=""
if test "$have_w32_system" = yes; then
  LIBASSUAN_CONFIG_LIBS="$LIBASSUAN_CONFIG_LIBS -lwsock32"
fi
AC_SUBST(LIBASSUAN_CONFIG_LIBS)
AC_SUBST(LIBASSUAN_CONFIG_CFLAGS)


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h locale.h sys/uio.h])

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
    AC_CHECK_FUNCS(fopencookie)
    if test $ac_cv_func_fopencookie = yes; then
        AC_LIBOBJ([funopen])
    else
        AC_MSG_WARN([
***
*** No implementation of fopencookie or funopen available.
*** The assuan_get_data_fp feature won't work.
***])
    fi
fi


AC_REPLACE_FUNCS(isascii)
AC_REPLACE_FUNCS(putc_unlocked)
AC_REPLACE_FUNCS(memrchr)

# Create the config files.
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_CONFIG_FILES([src/libassuan-config], [chmod +x src/libassuan-config])

AC_OUTPUT
