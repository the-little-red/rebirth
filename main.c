//#include <linux/fuse.h>
#include <errno.h>
#include <fuse.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
  struct fuse_context * context;

}
