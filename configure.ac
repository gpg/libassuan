# configure.ac - for libassuan
# Copyright (C) 2001, 2002, 2003, 2006, 2007 Free Software Foundation, Inc.
# 
# This file is part of Assuan.
#
# Assuan is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Assuan is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
min_automake_version="1.10"

# Remember to change the version number immediately *after* a release.
# Set my_issvn to "yes" for non-released code.  Remember to run an
# "svn up" and "autogen.sh" right before creating a distribution.
m4_define([my_version], [1.0.4])
m4_define([my_issvn], [no])

m4_define([svn_revision], m4_esyscmd([echo -n $( (svn info 2>/dev/null \
            || echo 'Revision: 0')|sed -n '/^Revision:/ {s/[^0-9]//gp;q;}')]))
AC_INIT([libassuan], my_version[]m4_if(my_issvn,[yes],[-svn[]svn_revision]),
        [bug-libassuan@gnupg.org])
# Note, that this is not yet available as a shared library.

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR(src/assuan.h)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_HOST
AB_INIT

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
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
#AC_ARG_PROGRAM

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),_gcc_wopt=yes,_gcc_wopt=no)
    AC_MSG_RESULT($_gcc_wopt)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_wopt" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi
fi


AH_BOTTOM([
#define _ASSUAN_IN_LIBASSUAN 1

/* We explicitly need to disable PTH's soft mapping as Debian
   currently enables it by default for no reason. */
#define PTH_SYSCALL_SOFT 0

])


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
    *-solaris*)
	AC_DEFINE(_XOPEN_SOURCE, 500, Activate extensions on Solaris)
	AC_DEFINE(_XOPEN_SOURCE_EXTENDED, 1, Activate extensions on Solaris)
	AC_DEFINE(__EXTENSIONS__, 1, Activate extensions on Solaris)
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

#
# See whether we can build a Pth enabled version
#
GNUPG_PATH_PTH
AM_CONDITIONAL(HAVE_PTH, test "$have_pth" = "yes")


# Check for network libraries.  They are needed for tests.
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))
AC_SUBST(NETLIBS)

# For src/libassuan-config.in
LIBASSUAN_CONFIG_LIB="-lassuan"
LIBASSUAN_CONFIG_CFLAGS=""
LIBASSUAN_CONFIG_API_VERSION="1"
LIBASSUAN_CONFIG_THREAD_MODULES=
if test "$have_pth" = yes; then
LIBASSUAN_CONFIG_THREAD_MODULES="pth"
fi
LIBASSUAN_CONFIG_EXTRA_LIBS=
if test "$have_w32_system" = yes; then
  LIBASSUAN_CONFIG_EXTRA_LIBS="$LIBASSUAN_CONFIG_EXTRA_LIBS -lws2_32"
fi
if test x"$NETLIBS" != x; then
  LIBASSUAN_CONFIG_EXTRA_LIBS="$LIBASSUAN_CONFIG_EXTRA_LIBS $NETLIBS"
fi
AC_SUBST(LIBASSUAN_CONFIG_LIB)
AC_SUBST(LIBASSUAN_CONFIG_CFLAGS)
AC_SUBST(LIBASSUAN_CONFIG_API_VERSION)
AC_SUBST(LIBASSUAN_CONFIG_THREAD_MODULES)
AC_SUBST(LIBASSUAN_CONFIG_EXTRA_LIBS)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h locale.h sys/uio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

gl_HEADER_SYS_SOCKET
gl_TYPE_SOCKLEN_T

AC_CHECK_MEMBER(struct cmsghdr.cmsg_len,
                [use_descriptor_passing=yes],
                [use_descriptor_passing=no
                 AC_MSG_WARN([
***
*** Data structure for sending ancillary data missing.
*** Descriptor passing won't work.
***])],[
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <unistd.h>
       ])
if test "$use_descriptor_passing" = "yes"; then
 AC_DEFINE(USE_DESCRIPTOR_PASSING, 1,
            [Defined if descriptor passing is supported])
fi
AM_CONDITIONAL(USE_DESCRIPTOR_PASSING, test "$use_descriptor_passing" = "yes")


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
AC_REPLACE_FUNCS(stpcpy)
# Check for unistd.h for setenv replacement function.
AC_CHECK_HEADERS(unistd.h)
AC_REPLACE_FUNCS(setenv)


#
# Check for the getsockopt SO_PEERCRED
#
AC_MSG_CHECKING(for SO_PEERCRED)
AC_CACHE_VAL(assuan_cv_sys_so_peercred,
      [AC_TRY_COMPILE([#include <sys/socket.h>], 
         [struct ucred cr; 
          int cl = sizeof cr;
          getsockopt (1, SOL_SOCKET, SO_PEERCRED, &cr, &cl);],
          assuan_cv_sys_so_peercred=yes,
          assuan_cv_sys_so_peercred=no)
       ])
AC_MSG_RESULT($assuan_cv_sys_so_peercred) 
if test $assuan_cv_sys_so_peercred = yes; then
  AC_DEFINE(HAVE_SO_PEERCRED, 1,
            [Defined if SO_PEERCRED is supported (Linux specific)])
fi




# Create the config files.
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([m4/Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_CONFIG_FILES([tests/Makefile])
AC_CONFIG_FILES([src/libassuan-config], [chmod +x src/libassuan-config])

AC_OUTPUT
