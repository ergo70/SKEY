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
    sys.stderr.write('#')
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

sys.stderr.write('\n')

print(getfqdn()+'\n')    
    
for i in hashes:
    print str(c) +'\t' + i
    c+=1
