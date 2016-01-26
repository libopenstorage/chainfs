# chainfs
Implements a chained filesystem in userspace.  Uses FUSE to export the chained namespace.

# Building chainfs

```
# autoreconf -i
# ./configure
# make 
```

### Building a debug build
```
# make clean; ./configure CFLAGS='-g3 -O0’; make
```
