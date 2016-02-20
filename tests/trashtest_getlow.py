'''
Scratchpad for test-based development. Unit tests for _getlow.py.

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

# These are normal inclusions
from mupy import Muid

# These are abnormal (don't use in production) inclusions.
from mupy._getlow import MEOC

from Crypto.PublicKey import RSA

from mupy._spec import _dummy_signature
from mupy._spec import _dummy_mac
from mupy._spec import _dummy_asym
from mupy._spec import _dummy_address

# These are soon-to-be-removed abnormal imports
from mupy._spec import _meoc, _mobs, _mobd, _mdxx, _mear, _asym_pr, _asym_ak, _asym_nk, _asym_else

# ###############################################
# Testing
# ###############################################

_dummy_muid = Muid(0, _dummy_address)
                
if __name__ == '__main__':
    # MEOC dummy test.
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    meoc_1 = MEOC(author=_dummy_muid, payload=_dummy_payload)
    meoc_1.pack(cipher=0, address_algo=0)
    meoc_1.pack_signature(_dummy_signature)
    meoc_1p = meoc_1.packed
    
    # meoc_1r = MEOC.unpack(meoc_1p)
    
    # MEOC actual test.
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    meoc_2 = MEOC(author=_dummy_muid, payload=_dummy_payload)
    meoc_2.pack(cipher=0, address_algo=1)
    meoc_2.pack_signature(_dummy_signature)
    meoc_2p = meoc_2.packed
    
    import IPython
    IPython.embed()