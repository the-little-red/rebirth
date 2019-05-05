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

}


// Model of the fuse_structed used
// struct fuse_context {
//         struct fuse *fuse;
//         uid_t uid;
//         gid_t gid;
//         pid_t pid;
//         void *private_data;
//         mode_t umask;
// };

int main (int argc, char *argv[]){
  
  return fuse_main(argc, argv, &operations, NULL);
}
