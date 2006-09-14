
ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = config.rpath  config.rpath autogen.sh README.SVN

SUBDIRS = m4 src doc tests


dist-hook:
	echo "$(VERSION)" > $(distdir)/VERSION

