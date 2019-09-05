#!/usr/bin/env python
#|**********************************************************************;
#* Project           : Rebirth is a Fuse filesystem written in python that can detect ransomware attacks.
#*                     Rebirth uses as base code the Passthrough Fuse filesystem (https://www.stavros.io/posts/python-fuse-filesystem/)
#*                     And a watchdog (https://www.thepythoncorner.com/2019/01/how-to-create-a-watchdog-in-python-to-look-for-filesystem-changes/)
#*                     So it can mount a simple filesystem in user space and detect any changes in files.
#*                     The ransomware detection is my original code and will follow GPU's license.
#*                     Special Credits to Davide Mastromatteo (Python Watchdog) and Stavros Korokithakis (Fuse Filesystem) since at least 50% of this code is heavyly based on their code guides (links).
#*
#* Program name      : rebirth.py
#*
#* Author            : Arianne de Paula Bortolan (the-little-red)
#*
#* Purpose           : Identify ransomware attacks on a filesystem and alert the user about it.
#*
#* Last Edit         : 04/09/2019
#*
#|**********************************************************************;
TODO: finish watchdog, add metrics to detect the ransomware, testing
# Some Reference links:
# =======

# https://github.com/pleiszenburg/loggedfs-python
# https://www.thepythoncorner.com/2019/01/how-to-create-a-watchdog-in-python-to-look-for-filesystem-changes/
# https://info.cs.st-andrews.ac.uk/student-handbook/files/project-library/sh/Dooler.pdf
# https://pythonhosted.org/watchdog/
# https://pdfs.semanticscholar.org/bf0b/2b96f4329ec6f28fabc80d64ca9c03307d9a.pdf
# https://pypi.org/project/watchdog/

# Library's
# =======

import os
import sys
import errno
import logging
import time
import threading
import time
import math
import string
import fileinput
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from fuse import FUSE, FuseOSError, Operations

# Shannon entropy base codes:
# Stolen from Ero Carrera
# http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html

# def range_bytes (): return range(256)
# def range_printable(): return (ord(c) for c in string.printable)
# def H(data, iterator=range_bytes):
#     if not data:
#         return 0
#     entropy = 0
#     for x in iterator():
#         p_x = float(data.count(chr(x)))/len(data)
#         if p_x > 0:
#             entropy += - p_x*math.log(p_x, 2)
#     return entropy
# def main ():
#     for row in fileinput.input():
#         string = row.rstrip('\n')
#         print ("%s: %f" % (string, H(string, range_printable)))
#https://rosettacode.org/wiki/Entropy#Python:_More_succinct_version
# >>> import math
# >>> from collections import Counter
# >>>
# >>> def entropy(s):
# ...     p, lns = Counter(s), float(len(s))
# ...     return -sum( count/lns * math.log(count/lns, 2) for count in p.values()

# for str in ['gargleblaster', 'tripleee', 'magnus', 'lkjasdlk',
#                'aaaaaaaa', 'sadfasdfasdf', '7&wS/p(']:
#     print ("%s: %f" % (str, H(str, range_printable)))

class Epitaph():
    def __init__ (patterns, ignore_patterns, ignore_directories, case_sensitive):
        self.event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    # Watchdog methods
    def on_created(event):
        print(f"{event.src_path} has been created!")

    def on_deleted(event):
        print(f"{event.src_path} deleted")

    def on_modified(event):
        print(f"{event.src_path} has been modified")

    def on_moved(event):
        print(f"{event.src_path}  moved to {event.dest_path}")

# Classes
# =======

class FuseR(Operations):
    def __init__(self, root):
        self.root = root

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid','st_blocks'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        return os.symlink(target, self._full_path(name))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

# Main
# =======

def main(mountpoint, root, event):
    #path = "."
    go_recursively = True
    the_observer = Observer()
    the_observer.schedule(event, mountpoint, recursive=go_recursively)
    the_observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()
    FUSE(FuseR(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    #File patterns the event handler will deal with, since is *, it will handle all patterns
    patterns = "*"
    #File patterns that will be ignored by the watchdog
    ignore_patterns = ""
    #True if want to be notified just by regular files (not directories)
    ignore_directories = False
    #Make the patterns case sensitive
    case_sensitive = True
    event_handler = Epitaph(patterns, ignore_patterns, ignore_directories, case_sensitive)
    main(sys.argv[2], sys.argv[1], event_handler)
