// gcc chainfs.c hash.c -DiFILE_OFFSET_BITS=64 -lfuse -lulockmgr -lpthread -o chainfs

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#define _GNU_SOURCE

#include <fuse.h>
#include <pthread.h>
#include <ulockmgr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "hash.h"

#define MAX_DESC 4096
#define MAX_LAYERS 64
#define MAX_INSTANCES 128

char *dummy_src;

struct dummy_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static char *real_path(const char *path, bool create_mode)
{
	char *r = NULL;

	if (!strcmp(path, "/")) {
		// This is a request for the root virtual path.  There are only
		// dummy FS volumes at this location and no specific dummy FS context.
		r = strdup(dummy_src);
	} else {
		asprintf(&r, "%s%s", dummy_src, path);
	}

	return r;
}

static void free_path(char *path)
{
	free(path);
}

static int dummy_opendir(const char *path, struct fuse_file_info *fi)
{
	int res = 0;
	char *rp = NULL;
	struct dummy_dirp *d = malloc(sizeof(struct dummy_dirp));

	if (d == NULL) {
		res = -ENOMEM;
		goto done;
	}

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	d->dp = opendir(rp);
	if (d->dp == NULL) {
		res = -errno;
		free(d);
		goto done;
	}
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (unsigned long) d;

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static inline struct dummy_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct dummy_dirp *) (uintptr_t) fi->fh;
}

static int dummy_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi)
{
	int res = 0;
	off_t nextoff = 0;
	struct stat st;
	char *rp = NULL;
	DIR *dp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	dp = opendir(rp);
	if (!dp) {
		fprintf(stderr, "Warning, cannot open %s as a directory.\n", rp);
		goto done;
	}

	while (true) {
		struct dirent *entry = NULL;
		entry = readdir(dp);
		if (!entry) {
			break;
		}

		if (strcmp(".", entry->d_name) == 0 ||
			strcmp("..", entry->d_name) == 0 || 
			strcmp("_parent", entry->d_name) == 0) {
				/* XXX TODO recurse into _parent */
				continue;
		}

		memset(&st, 0, sizeof(st));
		st.st_ino = entry->d_ino;
		st.st_mode = entry->d_type << 12;

		nextoff = 0;
		if (filler(buf, entry->d_name, &st, nextoff)) {
			fprintf(stderr, "Warning, Filler too full on %s.\n", rp);
			break;
		}
	}

done:
	if (dp) {
		closedir(dp);
	}

	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct dummy_dirp *d = get_dirp(fi);
	(void) path;

	closedir(d->dp);
	free(d);

	return 0;
}

static int dummy_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = lstat(rp, stbuf);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_access(const char *path, int mask)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = access(rp, mask);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_readlink(const char *path, char *buf, size_t size)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = readlink(rp, buf, size - 1);
	if (res == -1) {
		res = -errno;
		goto done;
	}
	buf[res] = '\0';
	res = 0;

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_unlink(const char *path)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = unlink(rp);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_rmdir(const char *path)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = rmdir(rp);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_symlink(const char *path, const char *to)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(to, true);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = symlink(path, rp);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_rename(const char *path, const char *to)
{
	int res = 0;
	char *path_rp = NULL;
	char *to_rp = NULL;

	path_rp = real_path(path, false);
	if (!path_rp) {
		res = -errno;
		goto done;
	}

	to_rp = real_path(to, true);
	if (!to_rp) {
		res = -errno;
		goto done;
	}

	res = rename(path_rp, to_rp);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (path_rp) {
		free_path(path_rp);
	}

	if (to_rp) {
		free_path(to_rp);
	}

	return res;
}

static int dummy_link(const char *path, const char *to)
{
	int res = 0;
	char *path_rp = NULL;
	char *to_rp = NULL;

	path_rp = real_path(path, false);
	if (!path_rp) {
		res = -errno;
		goto done;
	}

	to_rp = real_path(to, true);
	if (!to_rp) {
		res = -errno;
		goto done;
	}

	res = link(path_rp, to_rp);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (path_rp) {
		free_path(path_rp);
	}

	if (to_rp) {
		free_path(to_rp);
	}

	return res;
}

static int dummy_chmod(const char *path, mode_t mode)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = chmod(rp, mode);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_chown(const char *path, uid_t uid, gid_t gid)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = lchown(rp, uid, gid);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_truncate(const char *path, off_t size)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, true);
	if (!rp) {
		res = -errno;
		goto done;
	}

	int fd = open(rp, O_RDWR, 0777);
	if (fd == -1) {
		errno = ENOENT;
		res = -ENOENT;
		goto done;
	}

	res = ftruncate(fd, size);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_utimens(const char *path, const struct timespec ts[2])
{
	struct timeval tv[2];
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(rp, tv);
	res = 0;
	errno = 0;
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_open(const char *path, struct fuse_file_info *fi)
{
	int res = 0;
	char *rp = NULL;
	int fd;

	rp = real_path(path, true);
	if (!rp) {
		res = -errno;
		goto done;
	}

	fd = open(rp, fi->flags, 0777);
	if (fd == -1) {
		res = -errno;
		goto done;
	}

	fi->fh = fd;

done:
	if (rp) {
		free_path(rp);
	}


	return res;
}

static int dummy_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res = 0;
	char *rp = NULL;
	int fd;

	rp = real_path(path, true);
	if (!rp) {
		res = -errno;
		goto done;
	}

	fd = open(rp, fi->flags, mode);
	if (fd == -1) {
		res = -errno;
		goto done;
	}

	fi->fh = fd;

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_mkdir(const char *path, mode_t mode)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, true);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = mkdir(rp, mode);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, true);
	if (!rp) {
		res = -errno;
		goto done;
	}

	if (S_ISFIFO(mode)) {
		res = mkfifo(rp, mode);
	} else {
		res = mknod(rp, mode, rdev);
	}

	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_fgetattr(const char *path, struct stat *stbuf,
		struct fuse_file_info *fi)
{
	int res = 0;
	(void) path;

	res = fstat(fi->fh, stbuf);
	if (res == -1) {
		return -errno;
	}

	return 0;
}

static int dummy_ftruncate(const char *path, off_t size,
		struct fuse_file_info *fi)
{
	int res;
	(void) path;

	res = ftruncate(fi->fh, size);
	if (res == -1) {
		return -errno;
	}

	return 0;
}

static int dummy_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int res;
	(void) path;

	res = pread(fi->fh, buf, size, offset);
	if (res == -1) {
		res = -errno;
	}

	return res;
}

static int dummy_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	int res;
	(void) path;

	res = pwrite(fi->fh, buf, size, offset);
	if (res == -1) {
		res = -errno;
	}

	return res;
}

static int dummy_statfs(const char *path, struct statvfs *stbuf)
{
	int res = 0;

	res = statvfs(dummy_src, stbuf);
	if (res == -1) {
		res = -errno;
	}

	return res;
}

static int dummy_flush(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	return 0;
}

static int dummy_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	close(fi->fh);

	return 0;
}

static int dummy_fsync(const char *path, int isdatasync,
		struct fuse_file_info *fi)
{
	int res;
	(void) path;

#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
		res = fsync(fi->fh);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int dummy_setxattr(const char *path, const char *name, const char *value,
		size_t size, int flags)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = lsetxattr(rp, name, value, size, flags);
	if (res == -1) {
		res = -errno;
		goto done;
	}
	res = 0;

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_getxattr(const char *path, const char *name, char *value,
		size_t size)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = lgetxattr(rp, name, value, size);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_listxattr(const char *path, char *list, size_t size)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	res = llistxattr(rp, list, size);
	if (res == -1) {
		res = -errno;
		goto done;
	}

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

static int dummy_removexattr(const char *path, const char *name)
{
	int res = 0;
	char *rp = NULL;

	rp = real_path(path, false);
	if (!rp) {
		res = -errno;
		goto done;
	}

	int res = lremovexattr(rp, name);
	if (res == -1) {
		ret = -errno;
		goto done;
	}
	res = 0;

done:
	if (rp) {
		free_path(rp);
	}

	return res;
}

#endif /* HAVE_SETXATTR */

static int dummy_lock(const char *path, struct fuse_file_info *fi, int cmd,
		struct flock *lock)
{
	(void) path;

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			sizeof(fi->lock_owner));
}

struct fuse_operations dummy_oper = {
	.getattr	= dummy_getattr,
	.fgetattr	= dummy_fgetattr,
	.access		= dummy_access,
	.readlink	= dummy_readlink,
	.opendir	= dummy_opendir,
	.readdir	= dummy_readdir,
	.releasedir	= dummy_releasedir,
	.mknod		= dummy_mknod,
	.mkdir		= dummy_mkdir,
	.symlink	= dummy_symlink,
	.unlink		= dummy_unlink,
	.rmdir		= dummy_rmdir,
	.rename		= dummy_rename,
	.link		= dummy_link,
	.chmod		= dummy_chmod,
	.chown		= dummy_chown,
	.truncate	= dummy_truncate,
	.ftruncate	= dummy_ftruncate,
	.utimens	= dummy_utimens,
	.create		= dummy_create,
	.open		= dummy_open,
	.read		= dummy_read,
	.write		= dummy_write,
	.statfs		= dummy_statfs,
	.flush		= dummy_flush,
	.release	= dummy_release,
	.fsync		= dummy_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= dummy_setxattr,
	.getxattr	= dummy_getxattr,
	.listxattr	= dummy_listxattr,
	.removexattr= dummy_removexattr,
#endif
	.lock		= dummy_lock,

	.flag_nullpath_ok = 1,
};
