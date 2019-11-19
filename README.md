# Rebirth A.K.A CebolaFS
A fuse filesystem made in python that tries to detect ransomwares

Rebirth is my final assignment in my degree of Computer Science, is a prototype of a FileSystem that tries to detect Ransomware attacks
The detection is made by monitoring file's state by using 3 metrics: Shannon entropy, Fuzzy Hash of the file content and the magic numbers of this file.

Rebirth uses as base code the Passthrough Fuse filesystem (https://www.stavros.io/posts/python-fuse-filesystem/)
So it can mount a simple filesystem in user space and detect any changes in files.
The ransomware detection is my original code and will follow GPU's license.
Special Credits Stavros Korokithakis (Fuse Filesystem) since at least 50% of this code is heavy based on his code guide (link).

This software follows GNU GPL3 Licens
