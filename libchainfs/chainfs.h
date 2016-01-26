#ifndef _CHAINFS_H_
#define _CHAINFS_H_

typedef enum
{
	mode_chainfs = 0,
	mode_dummyfs	// For testing baseline performance.
} chainfs_mode_t;

// Create a layer and link it to a parent.  Parent can be "" or NULL.
extern int create_layer(char *id, char *parent_id);

// Remove a layer and all the inodes in this layer.
extern int remove_layer(char *id);

// Returns true if layer exists.
extern int check_layer(char *id);

// Allocate a chained FS starting from the given layer ID.
extern int alloc_chainfs(char *id);

// Release a chained FS.
extern int release_chainfs(char *id);

// Start ChainFS.  mode_dummyfs is used only for performance testing
// and will not work as a functional chained FS.
extern int start_chainfs(chainfs_mode_t mode, char *mount_path);

// Exits ChainFS and releases all filesystem resources associated with ChainFS.
extern void stop_chainfs(void);

#endif // _CHAINFS_H_
