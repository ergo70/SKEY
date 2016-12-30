# -*- coding: utf-8 -*-
"""
Created on Fri Dec 23 22:15:31 2016

@author: ergo
"""

import sys
from mhash import MHASH, MHASH_RIPEMD128
from os import urandom, path, chmod
from socket import getfqdn

CONFIG = path.expanduser("~") + '/.skey'

if(len(sys.argv) == 2):
    size = int(sys.argv[1])
else:
    size = 10;

if(size > 50):
    size = 50;

c = 1
base = 48

hashes = []

iv = urandom(16).encode('hex')
p = urandom(16).encode('hex')

next_hash = MHASH(MHASH_RIPEMD128, p + iv).hexdigest()

for n in xrange(1, 999999):
    next_hash = MHASH(MHASH_RIPEMD128, p + next_hash).hexdigest()

for i in xrange(0, size):
    hashes.append('-'.join(next_hash[i:i+4] for i in xrange(0, len(next_hash), 4)))
    for n in xrange(1, 1000000):
        next_hash = MHASH(MHASH_RIPEMD128, p + next_hash).hexdigest()

try:   
    chmod(CONFIG, 0200)
except:
    pass 
   
with open(CONFIG, 'w') as last_seen:
    last_seen.write(chr(base + size))
    last_seen.write(p)
    last_seen.write(next_hash)
    
chmod(CONFIG, 0400)    

hashes.reverse()

print(getfqdn()+'\n')    
    
for i in hashes:
    print str(c) +'\t' + i
    c+=1
