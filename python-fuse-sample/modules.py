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
import subprocess #can use system commands
from fuse import FUSE, FuseOSError, Operations
from collections import Counter


path = "./files_data/"

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
		print (data)
		status_ok= True
		if(data):
			if(shannon > data):
				status_ok = False				
		data[0]= shannon
		# and write everything back
		with open(filetowrite, 'w') as file:
    		file.writelines(data)
        return status_ok

    #verify hash similarity
    def hash_sim(file, filetowrite):
    	with open(filetowrite, 'r') as file:
    		data = file.readlines()
		print (data)
		status_ok= True
		if(data):
			if(compare hash and data[1] ):
				status_ok = False				
		data[1]= hash_dif
		# and write everything back
		with open(filetowrite, 'w') as file:
    		file.writelines(data)
        return status_ok

    #verify changes in filetype
    def magical(file, filetowrite):
        	with open(filetowrite, 'r') as file:
    		data = file.readlines()
		print (data)
		status_ok= True
		if(data):
			if(compare hash and data[2]):
				status_ok = False				
		data[1]= hash_dif
		# and write everything back
		with open(filetowrite, 'w') as file:
    		file.writelines(data)
        return status_ok

    #verify metrics, check them all, but if at least two dont pass, block by precaution
    def metrics(self, filename, extension):
        shannon_ok = shannon(self, filename, extension)
        hash_ok = hash_sim(self, filename, extension)
        magical_ok = magical(self, filename, extension)
        if shannon_ok and hash_ok and magical_ok:
            return True
        if shannon_ok and magical_ok:
            return True
        if shannon_ok and hash_ok:
            return True
        return False

    def main():
	    if (!path.isdir(path)) and (path.exists(path)):
		    filename, file_extension = os.path.splitext(path)
		        print("file: %s" % filename)
		        print("extension: %s" % file_extension)
		        if(file_extension != "swp") and (file_extension != "swx"):
		            print("Checking metrics mode ON!")
		            secure_change = metrics(self,path,file_extension)
		            if secure_change:
		                print("No problems found, keep going.")
		            else: 
	                print("GOTCHA! Suspicious processing found! Blocking exe!!")
	
if __name__ == '__main__':
	main()
	               
            #pid of last alt str(os.getpid())
