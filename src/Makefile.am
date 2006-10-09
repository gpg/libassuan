# Assuan Makefile
# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA 

## Process this file with automake to produce Makefile.in

EXTRA_DIST = libassuan-config.in mkerrors libassuan.m4
INCLUDES = -I.. -I$(top_srcdir)/include
BUILT_SOURCES = assuan-errors.c
MOSTLYCLEANFILES = assuan-errors.c

if HAVE_PTH
libassuan_pth = libassuan-pth.a
else
libassuan_pth = 
endif

bin_SCRIPTS = libassuan-config
m4datadir = $(datadir)/aclocal
m4data_DATA = libassuan.m4
lib_LIBRARIES = libassuan.a $(libassuan_pth)
include_HEADERS = assuan.h


common_sources = \
	assuan-defs.h \
	assuan-util.c \
	assuan-errors.c \
	assuan-buffer.c \
	assuan-handler.c \
	assuan-inquire.c \
	assuan-listen.c \
	assuan-connect.c \
	assuan-client.c \
	assuan-pipe-server.c \
	assuan-socket-server.c \
	assuan-pipe-connect.c \
	assuan-socket-connect.c \
	assuan-uds.c \
	assuan-logging.c \
	assuan-socket.c

libassuan_a_SOURCES = $(common_sources) assuan-io.c
libassuan_a_LIBADD = @LIBOBJS@

if HAVE_PTH
libassuan_pth_a_SOURCES = $(common_sources) assuan-io-pth.c
libassuan_pth_a_LIBADD = @LIBOBJS@
endif

assuan-errors.c : assuan.h mkerrors
	$(srcdir)/mkerrors < $(srcdir)/assuan.h > assuan-errors.c
