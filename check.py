# -*- coding: utf-8 -*-
"""
Created on Fri Dec 23 23:17:19 2016

@author: ergo
"""

import sys
from mhash import MHASH, MHASH_RIPEMD128
from os import path, chmod

CONFIG = path.expanduser("~") + '/.skey'
base = 48

if(len(sys.argv) != 2):
    exit()

password = sys.argv[1].replace('-','')

with open(CONFIG, 'r') as last_seen:
    line = last_seen.readline()
    c = ord(line[0]) - base
    p = line[1:33]
    next_hash = line[33:65]
    
if c == 0:
    print 'List exhausted'
    print('FAIL')
    sys.exit()
    
if c < 10:
    print 'Only ' + str(c) + ' passwords left' 
    
password_hash = MHASH(MHASH_RIPEMD128, p + password).hexdigest()    

for n in xrange(1, 999999):
    password_hash = MHASH(MHASH_RIPEMD128, p + password_hash).hexdigest()

if next_hash == password_hash:
    c-=1
    chmod(CONFIG, 0200) 
    with open(CONFIG, 'w') as last_seen:
        last_seen.write(chr(base + c))   
        last_seen.write(p)
        last_seen.write(password)
    chmod(CONFIG, 0400)    
    print 'PASS'
else:
    print 'FAIL'        
