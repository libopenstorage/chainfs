# chainfs
Implements a chained filesystem in userspace.  Uses FUSE to export the chained namespace.

# Building chainfs

```
# autoreconf -i
# ./configure
# make 
```

### Installing chainfs

`libchainfs.a` will be installed under `/usr/local/lib`.

```
# make install
```

### Building a debug build
```
# make clean; ./configure CFLAGS='-g3 -O0'; make
```
