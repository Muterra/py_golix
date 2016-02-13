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

from mupy._spec import _meoc, _mobs, _mobd, _mdxx, _mepr, _mpak, _mpnk

# ###############################################
# Testing
# ###############################################
                
if __name__ == '__main__':
    # MEOC test parsers
    meoc_1 = {
        'magic': None,
        'version': 14,
        'cipher': 0,
        'body': {
            'author': {'algo': 0, 'address': None},
            'payload': b'Hello world',
        },
        'muid': {'algo': 0, 'address': None},
        'signature': None
    }
    
    meoc_1p = _meoc.pack(meoc_1)
    meoc_1r = _meoc.unpack(meoc_1p)
    
    # MOBS test parsers
    mobs_1 = {
        'magic': None,
        'version': 6,
        'cipher': 0,
        'body': {
            'binder': {'algo': 0, 'address': None},
            'target': {'algo': 0, 'address': None},
        },
        'muid': {'algo': 0, 'address': None},
        'signature': None
    }
    
    mobs_1p = _mobs.pack(mobs_1)
    mobs_1r = _mobs.unpack(mobs_1p)
    
    # MOBD test parsers
    mobd_1 = {
        'magic': None,
        'version': 13,
        'cipher': 0,
        'body': {
            'binder': {'algo': 0, 'address': None},
            'history': [],
            'targets': [{'algo': 0, 'address': None}, {'algo': 0, 'address': None}],
            'muid_dynamic': {'algo': 0, 'address': None},
        },
        'muid': {'algo': 0, 'address': None},
        'signature': None
    }
    
    mobd_1p = _mobd.pack(mobd_1)
    mobd_1r = _mobd.unpack(mobd_1p)
    
    # MDXX test parsers
    mdxx_1 = {
        'magic': None,
        'version': 7,
        'cipher': 0,
        'body': {
            'debinder': {'algo': 0, 'address': None},
            'targets': [{'algo': 0, 'address': None}, {'algo': 0, 'address': None}],
        },
        'muid': {'algo': 0, 'address': None},
        'signature': None
    }
    
    mdxx_1p = _mdxx.pack(mdxx_1)
    mdxx_1r = _mdxx.unpack(mdxx_1p)
    
    # MEPR test parsers
    mepr_1 = {
        'magic': None,
        'version': 11,
        'cipher': 0,
        'body': {
            'recipient': {'algo': 0, 'address': None},
            'payload': None,
        },
        'muid': {'algo': 0, 'address': None},
        'mac': None
    }
    
    mepr_1p = _mepr.pack(mepr_1)
    mepr_1r = _mepr.unpack(mepr_1p)
    
    # MPAK test parsers
    mpak_1 = {
        'magic': None,
        'version': 6,
        'cipher': 0,
        'body': {
            'recipient': {'algo': 0, 'address': None},
            'payload': None,
        },
        'muid': {'algo': 0, 'address': None},
        'mac': None
    }
    
    mpak_1p = _mpak.pack(mpak_1)
    mpak_1r = _mpak.unpack(mpak_1p)
    
    # MPNK test parsers
    mpnk_1 = {
        'magic': None,
        'version': 6,
        'cipher': 0,
        'body': {
            'recipient': {'algo': 0, 'address': None},
            'payload': None,
        },
        'muid': {'algo': 0, 'address': None},
        'mac': None
    }
    
    mpnk_1p = _mpnk.pack(mpnk_1)
    mpnk_1r = _mpnk.unpack(mpnk_1p)
    
    import IPython
    IPython.embed()