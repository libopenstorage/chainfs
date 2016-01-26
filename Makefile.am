AM_CFLAGS = -Wall -Werror -Ilibchainfs

TIMEOUT_KILL = timeout --foreground -s 6 1h
TIMEOUT_SHORT = timeout --foreground -s 6 1m

noinst_LIBRARIES = lib/libchainfs.a 

lib_libchainfs_a_SOURCES=libchainfs/chainfs.c libchainfs/hash.c

bin_PROGRAMS=bin/chainfs

bin_chainfs_SOURCES = \
	libchainfs/chainfs.c \
	libchainfs/hash.c

bin_chainfs_LDADD=lib/libchainfs.a -lfuse -lpthread -lulockmgr

chainfs: bin/chainfs
	sudo $(TIMEOUT_KILL) bin/chainfs

if HAVE_DOXYGEN

doxyfile.stamp:
	(cd docs && $(DOXYGEN) Doxyfile)
	echo Timestamp > doxyfile.stamp

all-local: doxyfile.stamp

CLEANFILES = doxyfile.stamp

endif
