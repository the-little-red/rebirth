#!/usr/bin/env python3
#|**********************************************************************;
#* Project           : Rebirth is a Fuse filesystem written in python that can detect ransomware attacks.
#*                     Rebirth uses as base code the Passthrough Fuse filesystem (https://www.stavros.io/posts/python-fuse-filesystem/)
#*                     So it can mount a simple filesystem in user space and detect any changes in files.
#*                     The ransomware detection is my original code and will follow GPU's license.
#*                     Special Credits Stavros Korokithakis (Fuse Filesystem) since at least 50% of this code is heavyly based on his code guide (link).
#*
#* PS                : Shannon and Hash functions are high cost functions, if trying to optimize this code, start by this guys
#*
#* Program name      : rebirth.py
#*
#* Author            : Arianne de Paula Bortolan (the-little-red)
#*
#* Purpose           : Identify ransomware attacks on a filesystem and alert the user about it.
#*
#* Last Edit         : 19/11/2019
#*
#|**********************************************************************;

#BASH IN PYTHON: https://stackoverflow.com/questions/13745648/running-bash-script-from-within-python
#HASH in python: https://nitratine.net/blog/post/how-to-hash-files-in-python/
# ssdeep hash https://medium.com/@nikhilh20/fuzzy-hashing-ssdeep-3cade6931b72
# Some Reference links to read:
# =======
# https://www.thepythoncorner.com/2019/01/how-to-create-a-watchdog-in-python-to-look-for-filesystem-changes/
# https://info.cs.st-andrews.ac.uk/student-handbook/files/project-library/sh/Dooler.pdf
# https://pdfs.semanticscholar.org/bf0b/2b96f4329ec6f28fabc80d64ca9c03307d9a.pdf
# https://www.slideshare.net/matteobertozzi/python-fuse
# https://www.slideshare.net/gnurag/fuse-python?next_slideshow=1
# https://www.thepythoncorner.com/2017/08/logging-in-python/
# https://stackoverflow.com/questions/11114492/check-if-a-file-is-not-open-not-used-by-other-process-in-python
# https://stackoverflow.com/questions/38916777/python-library-for-handling-linuxs-audit-log
# https://rosettacode.org/wiki/Entropy
#

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
import hashlib
import magic
import ssdeep
import subprocess #can use system commands
from fuse import FUSE, FuseOSError, Operations, fuse_get_context
from os import path
from collections import Counter

LAST_PID = "0"
EXE_LOCATION = ""
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
        uid, gid, pid = fuse_get_context()
        exe = str("/proc/") + str(pid) + str(("/exe"))
        LAST_PID = pid
        EXE_LOCATION =  os.readlink(exe)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
       # print("file %s created" % path)
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

    def release(self, filepath, fh):
        print("file %s writed " % filepath)
        os.close(fh)
        if (os.path.isfile(filepath)):
            dir, filename = os.path.split(filepath)
            filename, ext = os.path.splitext(filename)
            print("file: %s" % filename)
            print("extension: %s" % file_extension)
            if(file_extension != "swp") and (file_extension != "swx"):
                print("Checking metrics mode ON!")
                metricsfile = str("/files_info/")+str(filename)+str(".mm")
                #check if metrics file exist, else, create metrics file
                if(os.path.isfile(metricsfile)):
                    secure_change = metrics(self,filepath,metricsfile)
                    if secure_change:
                        print("No problems found, keep going.")
                        return True
                    else:
                        print("GOTCHA! Suspicious processing found! Blocking exe!!")
                        return block_process(self.LAST_PID,EXE_LOCATION)
                else:
                    write_metrics(filepath,metricsfile)
            #pid of last alt str(os.getpid())
        return

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

# ===== METRICS FUNCTIONS ======

    #verify shannon entropy, high entropy --> high change of problems, if file type is pdf|zip|tar then ignores high entropy
    def shannon(self, file, filetowrite):
        f = open(file, "rb")
        byteArr = f.read()
        f.close()
        p, lns = Counter(byteArr), float(os.path.getsize(file))
        shannon = -sum( count/lns * math.log(count/lns, 2) for count in p.values())
        fw = open(file,"rb")
        with open(filetowrite, 'r') as file:
            data = file.readlines()
        print("Shannon comparisson \n")
        shannon_old = data[0].replace('\n','')
        status_ok= True
        if(data[0]):
            if(shannon > float(shannon_old)):
                status_ok = False
                data[0]= shannon
                # and write everything back
                with open(filetowrite, 'w') as file:
                    for item in data:
                        file.write("%s\n" % item)
        return status_ok

    #verify hash similarity
    def hash_sim(self, file, filetowrite):
        with open(filetowrite, 'r') as file:
            data = file.readlines()
        print ("Hash comparisson")
        print (data)
        old_hash= str(data[1].replace('\n',''))
        print(old_hash)
        status_ok = True
        hash_actual= str(ssdeep.hash_from_file(filename))
        print(hash_actual)
        deep = ssdeep.compare(hash_actual, old_hash)
        print(deep)
        #sshdash metric define as 21 - 100 a safe comparisson metric, this means that the result 21 means that
        #at least these files have some similarity
        if(deep >= 21):
            status_ok = True
        else:
            #less than 21% of similarity, houston we have a problem
            status_ok = False
        data[1]= hash_actual+"\n"
        # and write everything back
        print(data)
        with open(filetowrite, '+w') as file:
            for item in data:
                file.write("%s" % item)
        return status_ok

    #verify changes in filetype
    def magical(self,file, filetowrite):
        print("Magic number compare")
        with open(filetowrite, 'r') as file:
            data = file.readlines()
        status_ok = True
        with magic.Magic(flags=magic.MAGIC_MIME_ENCODING) as m:
            magic_num = m.id_filename(filename)
        old_magic = str(data[2].replace('\n',''))
        magic_num = str(magic_num)
        if(magic_num != old_magic):
            status_ok = False
        data[2]= magic_num
        with open(filetowrite, 'w') as file:
            for item in data:
                file.write("%s\n" % item)
        # and write everything back
        return status_ok

    #verify metrics, check them all, but if at least two dont pass, block by precaution
    def metrics(self, filename, filetowrite):
        shannon_ok = shannon(filename, filetowrite)
        hash_ok = hash_sim(filename, filetowrite)
        magical_ok = magical(filename, filetowrite)
        if shannon_ok and hash_ok and magical_ok:
            print("all 3 ok")
            return True
        if shannon_ok and magical_ok:
            print("shannon and magical ok")
            return True
        if shannon_ok and hash_ok:
            print("shannon and hash ok")
            return True
        return False

    def write_metrics(self, file, filetowrite):
        data = [0,0,""]
        f = open(filename, "rb")
        byteArr = f.read()
        p, lns = Counter(byteArr), float(os.path.getsize(filename))
        data[0] = -sum( count/lns * math.log(count/lns, 2) for count in p.values())
        print("Shannon %f" % data[0])
        data[1] = ssdeep.hash_from_file(filename)
        print("Hash ", data[1])
        with magic.Magic(flags=magic.MAGIC_MIME_ENCODING) as m:
            data[2] = m.id_filename(filename)
        print(data)
        with open(filetowrite, '+w') as file:
            for item in data:
                file.write("%s\n" % item)
        return


    #yes i shouldn't be running a shell via python, but im just too lazy to try anything else, also i restore btrfs file for precaution in this same script
    def block_process(self, PID, LOCATION):
        try:
           #subprocess.call("./stop_malware.sh", shell=True)
           subprocess.Popen(["bash", "./stop_malware.sh",PID,LOCATION], shell=True)
        except:
           print ("Not possible to stop Suspicious process!!!")
           return exit(1)
        print ("Suspicious process stopped and archives returned to original state!")
        return

# Main
# =======

def main(mountpoint, root):
   # try:
   #    os.mkdir('/files_info/')
   # except FileExistsError as exc:
   #    print(exc)
   FUSE(FuseR(root), mountpoint, nothreads=True, foreground=True,nonempty=True)

if __name__ == '__main__':
    if (len(sys.argv) < 2) or (len(sys.argv) > 3):
       print('usage: %s <mountpoint>' % sys.argv[0])
       exit(1)

    main(sys.argv[2], sys.argv[1])
