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

from mupy._spec import _meoc, _mobs, _mobd, _mdxx, _mear, _asym_pr, _asym_ak, _asym_nk, _asym_else

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
    mear_1 = {
        'magic': None,
        'version': 12,
        'cipher': 0,
        'body': {
            'recipient': {'algo': 0, 'address': None},
            'payload': None,
        },
        'muid': {'algo': 0, 'address': None},
        'mac': None
    }
    
    mear_1p = _mear.pack(mear_1)
    mear_1r = _mear.unpack(mear_1p)
    
    # Asymmetric payload blob tests.
    asym_pr_1 = {
        'author': {'algo': 0, 'address': None},
        'id': b'PR',
        'payload': {
            'target': {'algo': 0, 'address': None},
            'key': bytes(32)
        }
    }
    asym_pr_1p = _asym_pr.pack(asym_pr_1)
    asym_pr_1r = _asym_pr.unpack(asym_pr_1p)
    
    asym_ak_2 = {
        'author': {'algo': 0, 'address': None},
        'id': b'AK',
        'payload': {
            'target': {'algo': 0, 'address': None},
            'status': 0
        }
    }
    asym_ak_2p = _asym_ak.pack(asym_ak_2)
    asym_ak_2r = _asym_ak.unpack(asym_ak_2p)
    
    asym_nk_3 = {
        'author': {'algo': 0, 'address': None},
        'id': b'NK',
        'payload': {
            'target': {'algo': 0, 'address': None},
            'status': 0
        }
    }
    asym_nk_3p = _asym_nk.pack(asym_nk_3)
    asym_nk_3r = _asym_nk.unpack(asym_nk_3p)
    
    asym_else_4 = {
        'author': {'algo': 0, 'address': None},
        'id': b'\x00\x00',
        'payload': b'Hello world'
    }
    asym_else_4p = _asym_else.pack(asym_else_4)
    asym_else_4r = _asym_else.unpack(asym_else_4p)
    
    import IPython
    IPython.embed()