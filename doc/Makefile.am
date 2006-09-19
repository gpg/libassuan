# Assuan Makefile
# Copyright (C) 2003 Free Software Foundation, Inc.
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

info_TEXINFOS = assuan.texi

assuan_TEXINFOS = lgpl.texi gpl.texi


online: assuan.html assuan.pdf
	set -e; \
	echo "Uploading current manuals to www.gnupg.org ..."; \
        user=werner ; \
	(cd assuan.html && rsync -vr --exclude='.svn' .  \
	  $${user}@cvs.gnupg.org:webspace/manuals/assuan/ ); \
        rsync -v assuan.pdf $${user}@cvs.gnupg.org:webspace/manuals/

