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
import puremagic
import subprocess #can use system commands
from fuse import FUSE, FuseOSError, Operations
from os import path
from collections import Counter


#verify shannon entropy, high entropy --> high change of problems, if file type is pdf|zip|tar then ignores high entropy
def shannon(file, filetowrite):
    f = open(file, "rb")
    byteArr = map(ord, f.read())
    f.close()
    fileSize = len(byteArr)
    print ('File size in bytes:')
    print (fileSize)
    print ()
    p, lns = Counter(byteArr), float(len(byteArr))
    shannon = sum( count/lns * math.log(count/lns, 2) for count in p.values())
    print ("entropy:")
    print (sum( count/lns * math.log(count/lns, 2) for count in p.values()))
    fw = open(file,"rb")
    with open(filetowrite, 'r') as file:
        data = file.readlines()
    print("Shannon comparisson \n")
    print (data[0])
    status_ok= True
    if(data[0]):
        if(shannon > data[0]):
            status_ok = False
            data[0]= shannon
            # and write everything back
            with open(filetowrite, 'w') as file:
                file.writelines(data)
    print("Finished compare \n")
    return status_ok

    #verify hash similarity
def hash_sim(file, filetowrite):
    with open(filetowrite, 'r') as file:
        data = file.readlines()
    print ("Hash comparisson \n")
    print (data)
    status_ok = True
    if(data):
        f = open(file, "rb")
        hash_actual= sshdeep.hash(f)
        #sshdash metric define as 21 - 100 a safe comparisson metric, this means that the result 21 means that
        #at least these files have some similarity
        print(sshdeep.compare(hash_actual, data[1]))
        if(sshdeep.compare(hash_actual, data[1]) >= 21):
            status_ok = True
        else:
            #less than 21% of similarity, houston we have a problem
            status_ok = False
	data[1]= hash_actual
	# and write everything back
	with open(filetowrite, 'w') as file:
		file.writelines(data)
    print("Finished compare \n")
    return status_ok

    #verify changes in filetype
def magical(file, filetowrite):
    print("Magic number compare \n")
    with open(filetowrite, 'r') as file:
	    data = file.readlines()
    print(data)
    status_ok = True
    if(data):
	    if(compare hash and data[2]):
		   status_ok = False
	data[1]= hash_dif
	# and write everything back
	with open(filetowrite, 'w') as file:
		file.writelines(data)
    return status_ok

#def write_stats():
    #verify metrics, check them all, but if at least two dont pass, block by precaution
def metrics(filename, filetowrite):
    shannon_ok = shannon(filename, filetowrite)
    hash_ok = hash_sim(filename, filetowrite)
    magical_ok = magical(filename, filetowrite)
    if shannon_ok and hash_ok and magical_ok:
        return True
    if shannon_ok and magical_ok:
        return True
    if shannon_ok and hash_ok:
        return True
    return False

def block_process(self, PID):
    try:
       #subprocess.call("./stop_malware.sh", shell=True)
       subprocess.Popen(["bash", "./stop_malware.sh",PID], shell=True)
    except:
       print "Not possible to stop Suspicious process!!!"
       return exit(1)
    print "Suspicious process stopped and archives returned to original state!"
    return

def main(path):
    metrics_ext=".me"
    if (!os.path.isdir(path)) and (os.path.exists(path)):
	    filename, file_extension = os.path.splitext(path)
	    print("file: %s" % filename)
	    print("extension: %s" % file_extension)
	    if(file_extension != "swp") and (file_extension != "swx"):
	       print("Checking metrics mode ON!")
           metricsfile = str(metrics_path)+str(filename)+str(metrics_ext)
           if(os.path.isfile(metrics)):
	       #    secure_change = metrics(path,metricsfile)
               print("file exists!")
	           #if(secure_change):
	            #   print("No problems found, keep going.")
	           #else:
                #   print("GOTCHA! Suspicious processing found! Blocking exe!!")
           else:
               print("file dont exist!")
                   #write_metrics(filepath,metricsfile)


if __name__ == '__main__':
    path = "./files_data/testing"
	main(path)
    print("ending program :3")

            #pid of last alt str(os.getpid())
