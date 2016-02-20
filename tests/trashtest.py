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

# These are normal inclusions
from mupy import Muid

# These are abnormal (don't use in production) inclusions.
from mupy.cipher import FirstPersonIdentity0

from mupy._getlow import MOBS

from Crypto.PublicKey import RSA

from mupy._spec import _dummy_signature
from mupy._spec import _dummy_mac
from mupy._spec import _dummy_asym
from mupy._spec import _dummy_address

# These are soon-to-be-removed abnormal imports
from mupy._getlow import MEOC

# ###############################################
# Testing
# ###############################################

_dummy_muid = Muid(0, _dummy_address)

# _test_sig_key = RSA.generate(4096)
# _test_sec_key = bytes(32)
                
if __name__ == '__main__':
    # Dummy identity test with dummy addresser.
    fakeid_1 = FirstPersonIdentity0(address_algo=0)
    
    # Dummy identity test with real addresser.
    fakeid_2 = FirstPersonIdentity0(address_algo=1)
    
    # Test them on MEOCs:
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    
    meoc_1p = fakeid_1.make_meoc(_dummy_payload)
    meoc_2p = fakeid_2.make_meoc(_dummy_payload)
    
    # meoc_1r = MEOC.unpack(meoc_1p)
    # meoc_2r = MEOC.unpack(meoc_2p)
    
    import IPython
    IPython.embed()