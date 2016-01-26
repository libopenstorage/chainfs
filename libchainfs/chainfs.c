// gcc chainfs.c layer.c hash.c -DEXPERIMENTAL_ -DSTANDALONE_ -DFILE_OFFSET_BITS=64 -lfuse -lulockmgr -lpthread -o chainfs

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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
#include <sys/types.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "layer.h"

static void trace(const char *fn, const char *path)
{
	fprintf(stderr, "%s  %s\n", fn, path);
}

static char *upper_path(struct layer *upper, const char *path)
{
	char *p, *new_path = NULL;

	p = strchr(path+1, '/');
	if (!p) {
		asprintf(&new_path, "/%s", upper->id);
	} else {
		asprintf(&new_path, "/%s%s", upper->id, p);
	}

	return new_path;
}

static int union_opendir(const char *path, struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (!(inode->mode & S_IFDIR)) {
		errno = ENOTDIR;
		res = -errno;
		goto done;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

// This does the bulk of unifying entries from the various layers.
// It has to make sure dup entries are avoided.
static int union_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;
	struct layer *layer;

	trace(__func__, path);

	// Check to see if it is a root listing.
	if (!strcmp(path, "/")) {
		// List all layers.
		if (root_fill(filler, buf)) {
			res = -errno;
		}

		goto done;
	}

	// Find the directory inode in the first layer that contains this path.
	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (!(inode->mode & S_IFDIR)) {
		errno = ENOTDIR;
		res = -errno;
		goto done;
	}

	layer = inode->layer;

	// TODO filter dup entries from other layers.
	do {
		char *new_path;

		if (inode) {
			struct inode *child = inode->child;
			struct stat stbuf;

			pthread_mutex_lock(&inode->lock);
			{
				while (child) {
					memset(&stbuf, 0, sizeof(struct stat));

					stbuf.st_mode = child->mode;
					stbuf.st_nlink = child->nlink;
					stbuf.st_uid = child->uid;
					stbuf.st_gid = child->gid;
					stbuf.st_size = child->size;
					stbuf.st_atime = child->atime;
					stbuf.st_mtime = child->mtime;
					stbuf.st_ctime = child->ctime;

					if (filler(buf, child->name, &stbuf, 0)) {
						pthread_mutex_unlock(&inode->lock);

						fprintf(stderr, "Warning, Filler too full on %s.\n", path);
						errno = ENOMEM;
						res = -errno;

						goto done;
					}

					child = child->next;
				}
			}
			pthread_mutex_unlock(&inode->lock);

			deref_inode(inode);
		}

		layer = layer->parent;
		if (!layer) {
			break;
		}

		new_path = upper_path(layer, path);
		if (!new_path) {
			res = -errno;
			goto done;
		}

		// Recursively find other directory inodes that have the same path
		// in the upper layers.
		inode = ref_inode(new_path, false, REF_OPEN, 0);
	} while (true);

done:

	return res;
}

static int union_releasedir(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int union_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	memset(stbuf, 0, sizeof(struct stat));
	stat_inode(inode, stbuf);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_access(const char *path, int mask)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	// TODO check mask bits against the inode.

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_unlink(const char *path)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (delete_inode(inode)) {
		deref_inode(inode);
		res = -errno;
		goto done;
	}

done:

	return res;
}

static int union_rmdir(const char *path)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (!(get_inode_mode(inode) & S_IFDIR)) {
		errno = ENOTDIR;
		res = -errno;
		goto done;
	}

	if (delete_inode(inode)) {
		deref_inode(inode);
		res = -errno;
		goto done;
	}

done:

	return res;
}

static int union_rename(const char *from, const char *to)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, from);

	inode = ref_inode(from, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	inode = rename_inode(inode, to);
	if (!inode) {
		res = -errno;
		goto done;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_chmod(const char *path, mode_t mode)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	chmod_inode(inode, mode);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_chown(const char *path, uid_t uid, gid_t gid)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	res = chown_inode(inode, uid, gid);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_truncate(const char *path, off_t size)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (inode->mode & S_IFDIR) {
		errno = EISDIR;
		res = -EISDIR;
		goto done;
	}

	res = truncate_inode(inode, size);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_utimens(const char *path, const struct timespec ts[2])
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	res = utimens_inode(inode, (time_t)ts[0].tv_sec, (time_t)ts[1].tv_sec);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_open(const char *path, struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, (fi->flags & O_CREAT ? REF_CREATE : false),
			0777 | S_IFREG);
	if (!inode) {
		res = -errno;
		goto done;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, (fi->flags & O_CREAT ? REF_CREATE : false),
			mode | S_IFREG);
	if (!inode) {
		res = -errno;
		goto done;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_mkdir(const char *path, mode_t mode)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_CREATE, mode | S_IFDIR);
	if (!inode) {
		res = -errno;
		goto done;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_mknod(const char *path, mode_t mode, dev_t rdev)
{
	trace(__func__, path);

	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int union_fgetattr(const char *path, struct stat *stbuf,
		struct fuse_file_info *fi)
{
	return union_getattr(path, stbuf);
}

static int union_ftruncate(const char *path, off_t size,
	struct fuse_file_info *fi)
{
	return union_truncate(path, size);
}

static int union_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (get_inode_mode(inode) & S_IFDIR) {
		errno = EISDIR;
		res = -EISDIR;
		goto done;
	}

	res = read_inode(inode, buf, size, offset);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (get_inode_mode(inode) & S_IFDIR) {
		errno = EISDIR;
		res = -EISDIR;
		goto done;
	}

	res = write_inode(inode, buf, size, offset);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_statfs(const char *path, struct statvfs *stbuf)
{
	int res = 0;

	trace(__func__, path);

	res = statvfs("/", stbuf);
	if (res == -1) {
		res = -errno;
	}

	return res;
}

static int union_flush(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	return 0;
}

static int union_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	return 0;
}

static int union_fsync(const char *path, int isdatasync,
		struct fuse_file_info *fi)
{
	int res = 0;
	struct inode *inode = NULL;

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (get_inode_mode(inode) & S_IFDIR) {
		errno = EISDIR;
		res = -EISDIR;
		goto done;
	}

	res = sync_inode(inode);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_readlink(const char *path, char *buf, size_t size)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, path);

	inode = ref_inode(path, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	if (inode->symlink) {
		strncpy(buf, inode->symlink, size);
	} else {
		errno = EINVAL;
		res = -errno;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_symlink(const char *from, const char *to)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, from);

	inode = ref_inode(to, true, REF_CREATE_EXCL, S_IFLNK);
	if (!inode) {
		res = -errno;
		goto done;
	}

	inode->symlink = strdup(from);
	if (!inode->symlink) {
		res = -errno;
	}

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

static int union_link(const char *from, const char *to)
{
	int res = 0;
	struct inode *inode = NULL;

	trace(__func__, from);

	inode = ref_inode(from, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	link_inode(inode, to);

done:
	if (inode) {
		deref_inode(inode);
	}

	return res;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int union_setxattr(const char *path, const char *name, const char *value,
		size_t size, int flags)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int union_getxattr(const char *path, const char *name, char *value,
		size_t size)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int union_listxattr(const char *path, char *list, size_t size)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int union_removexattr(const char *path, const char *name)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
	int res = 0;
}

#endif /* HAVE_SETXATTR */

static int union_lock(const char *path, struct fuse_file_info *fi, int cmd,
		struct flock *lock)
{
	(void) path;

	trace(__func__, path);

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			sizeof(fi->lock_owner));
}

static struct fuse_operations union_oper = {
	.getattr	= union_getattr,
	.fgetattr	= union_fgetattr,
	.access		= union_access,
	.readlink	= union_readlink,
	.opendir	= union_opendir,
	.readdir	= union_readdir,
	.releasedir	= union_releasedir,
	.mknod		= union_mknod,
	.mkdir		= union_mkdir,
	.symlink	= union_symlink,
	.unlink		= union_unlink,
	.rmdir		= union_rmdir,
	.rename		= union_rename,
	.link		= union_link,
	.chmod		= union_chmod,
	.chown		= union_chown,
	.truncate	= union_truncate,
	.ftruncate	= union_ftruncate,
	.utimens	= union_utimens,
	.create		= union_create,
	.open		= union_open,
	.read		= union_read,
	.write		= union_write,
	.statfs		= union_statfs,
	.flush		= union_flush,
	.release	= union_release,
	.fsync		= union_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= union_setxattr,
	.getxattr	= union_getxattr,
	.listxattr	= union_listxattr,
	.removexattr= union_removexattr,
#endif
	.lock		= union_lock,

	.flag_nullpath_ok = 1,
};

int start_unionfs(char *mount_path)
{
	char *argv[6];

	init_layers();

	umask(0);

	argv[0] = "graph-unionfs";
	argv[1] = mount_path;
	argv[2] = "-f";
	argv[3] = "-o";
	argv[4] = "allow_other";

	return fuse_main(5, argv, &union_oper, NULL);
}

int alloc_unionfs(char *id)
{
	return set_upper(id);
}

int release_unionfs(char *id)
{
	return unset_upper(id);
}

void *launch(void *arg)
{
	start_unionfs("/var/lib/openstorage/unionfs");

	return NULL;
}

int main()
{
	pthread_t tid;
	int c;

	system("umount /var/lib/openstorage/unionfs");

	pthread_create(&tid, NULL, launch, NULL);

	sleep(2);

	fprintf(stderr, "Creating layers...\n");

	create_layer("layer1", NULL);
	create_layer("layer2", "layer1");

	fprintf(stderr, "Ready... Press 'q' to exit.\n");
	do {
		c = getchar();
	} while (c != 'q');


	system("umount /var/lib/openstorage/unionfs");

	return 0;
}
