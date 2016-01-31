'''
Scratchpad for test-based development.

LICENSING
-------------------------------------------------

mupy: A python library for Muse object manipulation.
    Copyright (C) 2016 Muterra, Inc.
    
    Contributors
    ------------
    Nick Badger 
        badg@muterra.io | badg@nickbadger.com | nickbadger.com

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the 
    Free Software Foundation, Inc.,
    51 Franklin Street, 
    Fifth Floor, 
    Boston, MA  02110-1301 USA

------------------------------------------------------

'''

import sys
import collections

sys.path.append('../')

from mupy._smartyparse import SmartyParser
from mupy._smartyparse import ParseHelper
    
from mupy.parsers import _ParseNeat
from mupy.parsers import _ParseINT8US
from mupy.parsers import _ParseINT16US
from mupy.parsers import _ParseINT32US
from mupy.parsers import _ParseINT64US
from mupy.parsers import _ParseVersion
from mupy.parsers import _ParseCipher
from mupy.parsers import _ParseHashAlgo
from mupy.parsers import _ParseMagic
from mupy.parsers import _ParseMUID
from mupy.parsers import _ParseNone
from mupy.parsers import _ParseSignature
from mupy.parsers import _ParseKey

# ###############################################
# Testing
# ###############################################
                
if __name__ == '__main__':
    test_format = SmartyParser()
    test_format['magic'] = ParseHelper(_ParseMagic)
    test_format['version'] = ParseHelper(_ParseVersion)
    test_format['cipher'] = ParseHelper(_ParseINT8US)
    test_format['body1_length'] = ParseHelper(_ParseINT32US)
    test_format['body1'] = ParseHelper(_ParseNeat)
    test_format['body2_length'] = ParseHelper(_ParseINT32US)
    test_format['body2'] = ParseHelper(_ParseNeat)
    test_format.link_length('body1', 'body1_length')
    test_format.link_length('body2', 'body2_length')
     
    tv1 = {}
    tv1['magic'] = b'[00]'
    tv1['version'] = 1
    tv1['cipher'] = 2
    tv1['body1'] = b'[test byte string, first]'
    tv1['body2'] = b'[test byte string, 2nd]'
    
    print('-----------------------------------------------')
    print('Starting TV1...')
    print(tv1)
    print('-----------------------------------------------')
    
    bites1 = test_format.dump(tv1)
    
    print('-----------------------------------------------')
    print('Successfully dumped.')
    print(bytes(bites1))
    print('-----------------------------------------------')
    
    recycle1 = test_format.load(bites1)
    
    print('-----------------------------------------------')
    print('Successfully reloaded.')
    print(recycle1)
    print('-----------------------------------------------')
     
    tv2 = {}
    tv2['magic'] = b'[aa]'
    tv2['version'] = 1
    tv2['cipher'] = 2
    tv2['body1'] = b'[new test byte string, first]'
    tv2['body2'] = b'[new test byte string, 2nd]'
    
    print('-----------------------------------------------')
    print('Starting TV2...')
    print(tv2)
    print('-----------------------------------------------')
    
    bites2 = test_format.dump(tv2)
    
    print('-----------------------------------------------')
    print('Successfully dumped.')
    print(bytes(bites2))
    print('-----------------------------------------------')
    
    recycle2 = test_format.load(bites2)
    
    print('-----------------------------------------------')
    print('Successfully reloaded.')
    print(recycle2)
    print('-----------------------------------------------')
    
    import IPython
    IPython.embed()