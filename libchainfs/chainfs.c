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

#include "inode.h"
#include "chainfs.h"

static chainfs_mode_t g_chainfs_mode;

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

static int chain_opendir(const char *path, struct fuse_file_info *fi)
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
static int chain_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
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

static int chain_releasedir(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int chain_getattr(const char *path, struct stat *stbuf)
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

static int chain_access(const char *path, int mask)
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

static int chain_unlink(const char *path)
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

static int chain_rmdir(const char *path)
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

static int chain_rename(const char *from, const char *to)
{
	int res = 0;
	struct inode *inode = NULL;
	struct inode *new_inode = NULL;

	trace(__func__, from);

	inode = ref_inode(from, true, REF_OPEN, 0);
	if (!inode) {
		res = -errno;
		goto done;
	}

	new_inode = rename_inode(inode, to);
	if (!new_inode) {
		res = -errno;
		goto done;
	}

	if (delete_inode(inode)) {
		res = -errno;
		goto done;
	}
	inode = NULL;

done:
	if (inode) {
		deref_inode(inode);
	}

	if (new_inode) {
		deref_inode(new_inode);
	}

	return res;
}

static int chain_chmod(const char *path, mode_t mode)
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

static int chain_chown(const char *path, uid_t uid, gid_t gid)
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

static int chain_truncate(const char *path, off_t size)
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

static int chain_utimens(const char *path, const struct timespec ts[2])
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

static int chain_open(const char *path, struct fuse_file_info *fi)
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

static int chain_create(const char *path, mode_t mode, struct fuse_file_info *fi)
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

static int chain_mkdir(const char *path, mode_t mode)
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

static int chain_mknod(const char *path, mode_t mode, dev_t rdev)
{
	trace(__func__, path);

	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int chain_fgetattr(const char *path, struct stat *stbuf,
		struct fuse_file_info *fi)
{
	return chain_getattr(path, stbuf);
}

static int chain_ftruncate(const char *path, off_t size,
	struct fuse_file_info *fi)
{
	return chain_truncate(path, size);
}

static int chain_read(const char *path, char *buf, size_t size, off_t offset,
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

static int chain_write(const char *path, const char *buf, size_t size,
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

static int chain_statfs(const char *path, struct statvfs *stbuf)
{
	int res = 0;

	trace(__func__, path);

	res = statvfs("/", stbuf);
	if (res == -1) {
		res = -errno;
	}

	return res;
}

static int chain_flush(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	return 0;
}

static int chain_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	return 0;
}

static int chain_fsync(const char *path, int isdatasync,
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

static int chain_readlink(const char *path, char *buf, size_t size)
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

static int chain_symlink(const char *from, const char *to)
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

static int chain_link(const char *from, const char *to)
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
static int chain_setxattr(const char *path, const char *name, const char *value,
		size_t size, int flags)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int chain_getxattr(const char *path, const char *name, char *value,
		size_t size)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int chain_listxattr(const char *path, char *list, size_t size)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
}

static int chain_removexattr(const char *path, const char *name)
{
	// XXX TODO
	errno = EINVAL;
	return -EINVAL;
	int res = 0;
}

#endif /* HAVE_SETXATTR */

static int chain_lock(const char *path, struct fuse_file_info *fi, int cmd,
		struct flock *lock)
{
	(void) path;

	trace(__func__, path);

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			sizeof(fi->lock_owner));
}

static struct fuse_operations chain_oper = {
	.getattr	= chain_getattr,
	.fgetattr	= chain_fgetattr,
	.access		= chain_access,
	.readlink	= chain_readlink,
	.opendir	= chain_opendir,
	.readdir	= chain_readdir,
	.releasedir	= chain_releasedir,
	.mknod		= chain_mknod,
	.mkdir		= chain_mkdir,
	.symlink	= chain_symlink,
	.unlink		= chain_unlink,
	.rmdir		= chain_rmdir,
	.rename		= chain_rename,
	.link		= chain_link,
	.chmod		= chain_chmod,
	.chown		= chain_chown,
	.truncate	= chain_truncate,
	.ftruncate	= chain_ftruncate,
	.utimens	= chain_utimens,
	.create		= chain_create,
	.open		= chain_open,
	.read		= chain_read,
	.write		= chain_write,
	.statfs		= chain_statfs,
	.flush		= chain_flush,
	.release	= chain_release,
	.fsync		= chain_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= chain_setxattr,
	.getxattr	= chain_getxattr,
	.listxattr	= chain_listxattr,
	.removexattr= chain_removexattr,
#endif
	.lock		= chain_lock,

	.flag_nullpath_ok = 1,
};

int start_chainfs(chainfs_mode_t mode, char *mount_path)
{
	extern struct fuse_operations dummy_oper;
	extern char *dummy_src;
	char *argv[6];
	int ret = 0;

	system("umount -l /var/lib/openstorage/chainfs");
	system("mkdir -p /var/lib/openstorage/chainfs");

	init_layers();

	umask(0);

	argv[0] = "graph-chainfs";
	argv[1] = mount_path;
	argv[2] = "-f";
	argv[3] = "-o";
	argv[4] = "allow_other";

	g_chainfs_mode = mode;

	switch (mode)
	{
	case mode_chainfs:
		ret = fuse_main(5, argv, &chain_oper, NULL);
		break;

	case mode_dummyfs:
		dummy_src = strdup("/tmp/test");
		if (!dummy_src) {
			return -errno;
		}

		rmdir(dummy_src);
		mkdir(dummy_src, 0644);
		ret = fuse_main(5, argv, &dummy_oper, NULL);
		break;

	default:
		errno = EINVAL;
		return -1;
	}

	return ret;
}

void stop_chainfs()
{
	system("umount /var/lib/openstorage/chainfs");
}

int alloc_chainfs(char *id)
{
	return set_upper(id);
}

int release_chainfs(char *id)
{
	return unset_upper(id);
}

// Create a layer and link it to a parent.  Parent can be "" or NULL.
int create_layer(char *id, char *parent_id)
{
	int ret = 0;

	if (g_chainfs_mode == mode_dummyfs) {
		char dir[4096];

		sprintf(dir, "/tmp/test/%s", id);
		mkdir(dir, 0644);
		fprintf(stderr, "Created layer %s\n", dir);
	} else if (g_chainfs_mode == mode_chainfs) {
		ret = create_inode_layer(id, parent_id);
	} else {
		fprintf(stderr, "Unknown chainFS mode.\n");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}

int remove_layer(char *id)
{
	int ret = 0;

	if (g_chainfs_mode == mode_dummyfs) {
		char dir[4096];

		sprintf(dir, "/tmp/test/%s", id);
		rmdir(dir);
		fprintf(stderr, "Created layer %s\n", dir);
	} else if (g_chainfs_mode == mode_chainfs) {
		ret = remove_inode_layer(id);
	} else {
		fprintf(stderr, "Unknown chainFS mode.\n");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}

// Returns true if layer exists.
int check_layer(char *id)
{
	bool ret = false;

	if (g_chainfs_mode == mode_dummyfs) {
		extern char *dummy_src;
		struct stat st;
		char dir[4096];

		sprintf(dir, "%s/%s", dummy_src, id);

		ret = stat(dir, &st);
	} else if (g_chainfs_mode == mode_chainfs) {
		ret = check_inode_layer(id);
	} else {
		fprintf(stderr, "Unknown chainFS mode.\n");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}
