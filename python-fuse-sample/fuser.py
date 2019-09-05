#!/usr/bin/env python
import os
ref={}
for p in os.listdir("/proc/"):
  if not p.isdigit(): continue
  d = "/proc/%s/fd/" % p
  try:
   for fd in os.listdir(d):
     f = os.readlink(d+fd)
     if f not in ref: ref[f] = []
     ref[f].append(p)
  except OSError:
    pass
for (k,v) in ref.iteritems():
  print k, " ".join(v)
