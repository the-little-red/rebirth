# Rebirth A.K.A CebolaFS
A fuse filesystem made in python that tries to detect ransomwares

Rebirth is my final assignment in my degree of Computer Science, is a prototype of a FileSystem that tries to detect Ransomware attacks
The detection is made by monitoring file's state by using 3 metrics: Shannon entropy, Fuzzy Hash of the file content and the magic numbers of this file.

