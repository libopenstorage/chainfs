# chainfs
Implements a chained filesystem in userspace.  Uses FUSE to export the chained namespace.

### EXPERIMENTAL!  
Note that this is still in development and experimental.  Currently the following are known issues

1. Data modified on shared layers are not snap'd and therefore visible in other containers.
2. There are two heavy weight locks around accessing the `layer` data structures which can be avoided.

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
