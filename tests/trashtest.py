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
from mupy.cipher import ThirdPersonIdentity0
from mupy.cipher import FirstPersonIdentity1
from mupy.cipher import ThirdPersonIdentity1

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
    # Check this out!
    known_third_parties = {}
    
    # Dummy first-person identity tests with real addresser.
    fake_first_id = FirstPersonIdentity0(address_algo=1)
    fake_third_id = fake_first_id.third_party
    
    # Keep them around for later!
    known_third_parties[fake_third_id.author_muid] = fake_third_id
    
    # Try it for rls
    first_id_1 = FirstPersonIdentity1(address_algo=1)
    third_id_1 = first_id_1.third_party
    
    # Test them on MEOCs:
    _dummy_payload = b'[[ Hello, world? ]]'
    
    secret1, muid1, meoc_1p = fake_first_id.make_meoc(_dummy_payload)
    secret3, muid3, meoc_3p = first_id_1.make_meoc(_dummy_payload)
    
    # Normal unpacking operation for first
    meoc_1r = MEOC.unpack(meoc_1p)
    author_1 = known_third_parties[meoc_1r.author]
    muid_1, meoc_1r_plaintext = author_1.load_meoc(secret1, meoc_1p)
    
    # Extra-normal unpacking operation for third.
    # Note that the author lookup ideally shouldn't be necessary if you already 
    # know who it is.
    muid_3, meoc_3r_plaintext = third_id_1.load_meoc(secret3, meoc_3p)
    
    import IPython
    IPython.embed()