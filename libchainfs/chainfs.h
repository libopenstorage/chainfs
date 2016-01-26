#ifdef EXPERIMENTAL_
#ifndef _CHAINFS_H_
#define _CHAINFS_H_
extern int alloc_chainfs(char *id);
extern int release_chainfs(char *id);
extern int start_chainfs(char *mount_path);
#endif // _CHAINFS_H_
#endif // EXPERIMENTAL_
