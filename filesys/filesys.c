#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/fat.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();		// list_init (&open_inodes);

#ifdef EFILESYS
	fat_init ();		// load boot sector

	if (format)
		do_format ();

	fat_open ();		// Load FAT directly from the disk
	struct thread *main_thread = thread_current();
	ASSERT(main_thread == LOADER_KERN_BASE);
	main_thread->cwd = dir_open_root();
	fat_fs_print();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, char type) {
	cluster_t inode_clst = 0;
	struct dir *base_dir = *name == '/' ? dir_open_root() : dir_reopen(thread_current()->cwd);
	struct dir *dir = NULL;

	char long_name[READDIR_MAX_LEN+1];
	strlcpy(long_name, name, READDIR_MAX_LEN+1);	// copy NAME

	char *dirname = long_name;
	char filename[READDIR_MAX_LEN+1];
	char *f = strrchr(long_name, '/');
	if (f != NULL) {	// name : "/foo" || "/foo/bar" || "foo/bar"
		f++; 
		strlcpy (filename, f, READDIR_MAX_LEN+1);
		*f = '\0';							// dirname  : "/"   || "/foo/" || "foo/"
											// filename : "foo" || "bar"   || "bar"
		
		if (strcmp(dirname, "/") == 0) {
			dir = dir_open_root(); 
		}
		else {
			struct inode *inode;
			if(dir_lookup(base_dir, dirname, &inode))
				dir = dir_open(inode);
		}
	}
	else {				// name : "foo"
		strlcpy (filename, long_name, READDIR_MAX_LEN+1);
		dir = dir_reopen(thread_current()->cwd);
	}

	bool success = (dir != NULL
			&& (inode_clst = fat_create_chain (0))
			&& inode_create (inode_clst, initial_size, type)
			&& dir_add (dir, filename, inode_clst));
	if (!success)
		fat_remove_chain(inode_clst, 0);
	else if (type == 1) {
		struct dir *new_dir = dir_open(inode_open(inode_clst));
		dir_add(new_dir, ".", inode_clst);
		dir_add(new_dir, "..", inode_get_inumber(*(uintptr_t *)dir));
		dir_close(new_dir);
	}
	dir_close (base_dir);
	dir_close (dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
uintptr_t
filesys_open (const char *name) {
	struct dir *base_dir = *name == '/' ? dir_open_root() : dir_reopen(thread_current()->cwd);
	char long_name[READDIR_MAX_LEN+1];
	strlcpy(long_name, name, READDIR_MAX_LEN+1);
	int len = strlen(name);
	long_name[len] = '/';
	long_name[len+1] = '\0';

	struct inode *inode = NULL;

	if (base_dir != NULL)
		dir_lookup (base_dir, long_name, &inode);
	dir_close (base_dir);

	if (inode == NULL)
		return NULL;

	if (inode_get_type(inode) == 0)
		return file_open (inode);
	else if (inode_get_type(inode) == 1)
		return dir_open (inode);
	else
		PANIC("todo : open symbolic link");
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	struct dir *base_dir = *name == '/' ? dir_open_root() : dir_reopen(thread_current()->cwd);
	struct dir *dir = NULL;

	char long_name[READDIR_MAX_LEN+1];
	strlcpy(long_name, name, READDIR_MAX_LEN+1);	// copy NAME

	char *dirname = long_name;
	char filename[READDIR_MAX_LEN+1];
	char *f = strrchr(long_name, '/');
	if (f != NULL) {	// name : "/foo" || "/foo/bar" || "foo/bar"
		f++; 
		strlcpy (filename, f, READDIR_MAX_LEN+1);
		*f = '\0';							// dirname  : "/"   || "/foo/" || "foo/"
											// filename : "foo" || "bar"   || "bar"
		if (strcmp(dirname, "/") == 0) {
			dir = dir_open_root(); 
		}
		else {
			struct inode *inode;
			if(dir_lookup(base_dir, dirname, &inode))
				dir = dir_open(inode);
		}
	}
	else {				// name : "foo"
		strlcpy (filename, long_name, READDIR_MAX_LEN+1);
		dir = dir_reopen(thread_current()->cwd);
	}

	bool success = false;
	if (dir == NULL)
		return false;
	else {
		struct inode *inode;
		if (dir_lookup(dir, filename, &inode)) {
			if (inode_get_type(inode) == 0) {		// file
				inode_close(inode);
				success = true;
			}
			else if (inode_get_type(inode) == 1) {	// directory
				struct dir *subdir = dir_open(inode);
				char name[NAME_MAX + 1];
				success = !dir_readdir(subdir, name)
						&& inode_get_open_cnt(inode) <= 1;		// should not be opened by other process.
				dir_close(subdir);
			}
			else
				PANIC("todo : remove symbolic link");
		}
	}
	if (success)
		success = dir_remove(dir, filename);

	dir_close (base_dir);
	dir_close (dir);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	bool init_root = dir_create (ROOT_DIR_CLUSTER, 16)
					&& dir_add(dir_open_root(), ".", ROOT_DIR_CLUSTER)
					&& dir_add(dir_open_root(), "..", ROOT_DIR_CLUSTER);
	if (!init_root)
		PANIC ("root directory creation failed");
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
