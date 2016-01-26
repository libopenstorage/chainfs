AM_CFLAGS = -Wall -Werror -Ilibchainfs

TIMEOUT_KILL = timeout --foreground -s 6 1h
TIMEOUT_SHORT = timeout --foreground -s 6 1m

lib_LIBRARIES=\
	lib/libchainfs.a

bin_PROGRAMS=\
	bin/test

# ChainFS
lib_libchainfs_a_SOURCES= \
	libchainfs/chainfs.c\
	libchainfs/dummyfs.c\
	libchainfs/inode.c\
	libchainfs/hash.c\
	libchainfs/snappy.c

bin_test_SOURCES = \
	libchainfs/test.c

bin_test_LDADD=lib/libchainfs.a -lfuse -lpthread -lulockmgr

test: bin/test
	sudo $(TIMEOUT_KILL) bin/test

if HAVE_DOXYGEN

doxyfile.stamp:
	(cd docs && $(DOXYGEN) Doxyfile)
	echo Timestamp > doxyfile.stamp

all-local: doxyfile.stamp

CLEANFILES = doxyfile.stamp lib/libchainfs.a bin/test

endif
