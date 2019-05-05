//#include <linux/fuse.h>
#include <errno.h>
#include <fuse.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>

#define FUSE_USE_VERSION 30

static struct fuse_operations operations = {
  .getattr = do_getattr,
  .readdir = do_readdir,
  .read = do_read,

  .readlink = do_readlink,
  // no .getdir -- that's deprecated
  .getdir = NULL,
  .mknod = do_mknod,
  .mkdir = do_mkdir,
  .unlink = do_unlink,
  .rmdir = do_rmdir,
  .symlink = do_symlink,
  .rename = do_rename,
  .link = do_link,
  .chmod = do_chmod,
  .chown = do_chown,
  .truncate = do_truncate,
  .utime = do_utime,
  .open = do_open,
  .read = do_read,
  .write = do_write,
  .statfs = do_statfs,
  .flush = do_flush,
  .release = do_release,
  .fsync = do_fsync,

#ifdef HAVE_SYS_XATTR_H
  .setxattr = do_setxattr,
  .getxattr = do_getxattr,
  .listxattr = do_listxattr,
  .removexattr = do_removexattr,
#endif

  .opendir = do_opendir,
  .readdir = do_readdir,
  .releasedir = do_releasedir,
  .fsyncdir = do_fsyncdir,
  .init = do_init,
  .destroy = do_destroy,
  .access = do_access,
  .ftruncate = do_ftruncate,
  .fgetattr = do_fgetattr
}

typedef int (*fuse_fill_dir_t) (void *buf, const char *name, const struct stat *stbuf, off_t off);

static int do_getattr( const char *path, struct stat *st )
{
  printf( "[getattr] Called\n" );
	printf( "\tAttributes of %s requested\n", path );
  st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now

	if ( strcmp( path, "/" ) == 0 )
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}

	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi )
{
  printf( "--> Getting The List of Files of %s\n", path );

  	filler( buffer, ".", NULL, 0 ); // Current Directory
  	filler( buffer, "..", NULL, 0 ); // Parent Directory

  	if ( strcmp( path, "/" ) == 0 ) // If the user is trying to show the files/directories of the root directory show the following
  	{
  		filler( buffer, "file54", NULL, 0 );
  		filler( buffer, "file349", NULL, 0 );
  	}

  	return 0;
}

int main (int argc, char *argv[]){

  return fuse_main(argc, argv, &operations, NULL);
}
