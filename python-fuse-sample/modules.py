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
import ssdeep
import magic
import subprocess #can use system commands
from fuse import FUSE, FuseOSError, Operations
from os import path
from collections import Counter


#verify shannon entropy, high entropy --> high change of problems, if file type is pdf|zip|tar then ignores high entropy
def shannon(file, filetowrite):
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
def hash_sim(filename, filetowrite):
    with open(filetowrite, 'r') as file:
        data = file.readlines()
    print ("Hash comparisson")
    print (data)
    old_hash= str(data[1].replace('\n',''))
    print(old_hash)
    status_ok = True
    hash_actual= str(ssdeep.hash(filename))
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
def magical(filename, filetowrite):
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

#def write_stats():
    #verify metrics, check them all, but if at least two dont pass, block by precaution
def metrics(filename, filetowrite):
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

def block_process(self, PID):
    try:
       #subprocess.call("./stop_malware.sh", shell=True)
       subprocess.Popen(["bash", "./stop_malware.sh",PID], shell=True)
    except:
       print("Not possible to stop Suspicious process!!!")
       return exit(1)
    print ("Suspicious process stopped and archives returned to original state!")
    return

def write_metrics(filename, filetowrite):
    data = [0,0,""]
    f = open(filename, "rb")
    byteArr = f.read()
    p, lns = Counter(byteArr), float(os.path.getsize(filename))
    data[0] = -sum( count/lns * math.log(count/lns, 2) for count in p.values())
    print("Shannon %f" % data[0])
    data[1] = ssdeep.hash(filename)
    print("Hash ", data[1])
    with magic.Magic(flags=magic.MAGIC_MIME_ENCODING) as m:
        data[2] = m.id_filename(filename)
    print(data)
    with open(filetowrite, '+w') as file:
        for item in data:
            file.write("%s\n" % item)
    return

def main(path):
    dir, filename = os.path.split(path)
    filename, ext = os.path.splitext(filename)
    metricsfile = str("/files_info/")+str(filename)+str(".mm")
    write_metrics(path, metricsfile)
    metrics(path, metricsfile)
    # if (os.path.isfile(path)):
    #     path = os.path.basename(path)
    #     filename, file_extension = os.path.splitext(path)
    #     print("file: %s" % filename)
    #     print("extension: %s" % file_extension)
    #     if(file_extension != "swp") and (file_extension != "swx"):
    #        print("Checking metrics mode ON!")
    #        metricsfile = str(metrics_path)+str(filename)+str(metrics_ext)
    #        print(metricsfile)
    #        if(os.path.isfile(metricsfile)):
    #            secure_change = metrics(path,metricsfile)
    #            print("file exists!")
    #            if(secure_change):
    #                print("No problems found, keep going.")
    #            else:
    #                print("GOTCHA! Suspicious processing found! Blocking exe!!")
    #        else:
    #            print("file dont exist! going to write it")
    #            write_metrics(filepath,metricsfile)


if __name__ == '__main__':
    path = "./tobe-mounted/arquivo-pdf.pdf"
    main(path)
    print("ending program :3")

            #pid of last alt str(os.getpid())
