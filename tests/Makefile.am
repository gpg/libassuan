# Makefile for Assuan regression tests
# Copyright (C) 2006 Free Software Foundation, Inc.
#
# This file is part of Assuan.
#
# Assuan is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.
#
# Assuan is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

TESTS_ENVIRONMENT = EXEEXT=$(EXEEXT); export EXEEXT;

EXTRA_DIST = motd

BUILT_SOURCES =
CLEANFILES =

test_programs = version
test_programs += pipeconnect

if HAVE_W32_SYSTEM
test_programs += fdpassing
check_SCRIPTS = fdpassing-socket.sh
testtools =
else
testtools = socks5
endif

if USE_DESCRIPTOR_PASSING
test_programs += fdpassing
check_SCRIPTS = fdpassing-socket.sh
endif

TESTS = $(test_programs) $(check_SCRIPTS)

AM_CFLAGS = $(GPG_ERROR_CFLAGS)
AM_LDFLAGS = -no-install

noinst_HEADERS = common.h
noinst_PROGRAMS = $(test_programs) $(w32cetools) $(testtools)
LDADD = ../src/libassuan.la $(GPG_ERROR_LIBS) @LDADD_FOR_TESTS_KLUDGE@
