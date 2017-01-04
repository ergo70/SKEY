#!/usr/bin/python
#
# Copyright 2016 Ernst-Georg Schmid
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-
"""
@author: ergo
"""

import sys
from mhash import HMAC, MHASH_RIPEMD128
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
    
password_hash = HMAC(MHASH_RIPEMD128, p , password).hexdigest()    

for n in xrange(1, 999999):
    password_hash = HMAC(MHASH_RIPEMD128, p , password_hash).hexdigest()

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
