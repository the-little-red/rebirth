#!/usr/bin/python3.7

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

# Watchdog methods    
    def on_created(event):
        print(f"hey, {event.src_path} has been created!")

    def on_deleted(event):
        print(f"what the f**k! Someone deleted {event.src_path}!")

    def on_modified(event):
        print(f"hey buddy, {event.src_path} has been modified")

    def on_moved(event):
        print(f"ok ok ok, someone moved {event.src_path} to {event.dest_path}")
