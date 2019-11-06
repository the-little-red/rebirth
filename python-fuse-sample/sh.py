import math
from collections import Counter
import sys


 def entropy(s):
     p, lns = Counter(s), float(len(s))
     return -sum( count/lns * math.log(count/lns, 2) for count in p.values())
 
