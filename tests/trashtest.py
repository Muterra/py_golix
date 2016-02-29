'''
Scratchpad for test-based development.

LICENSING
-------------------------------------------------

golix: A python library for Golix protocol object manipulation.
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
from golix import Guid

# These are abnormal (don't use in production) inclusions.
from golix.cipher import FirstPersonIdentity0
from golix.cipher import ThirdPersonIdentity0
from golix.cipher import FirstPersonIdentity1
from golix.cipher import ThirdPersonIdentity1

from golix._getlow import GOBS

from Crypto.PublicKey import RSA

from golix._spec import _dummy_signature
from golix._spec import _dummy_mac
from golix._spec import _dummy_asym
from golix._spec import _dummy_address

# These are soon-to-be-removed abnormal imports
from golix._getlow import GEOC

# ###############################################
# Testing
# ###############################################

_dummy_guid = Guid(0, _dummy_address)

# _test_sig_key = RSA.generate(4096)
# _test_sec_key = bytes(32)
    
def run():
    # Check this out!
    known_third_parties = {}
    
    # Dummy first-person identity tests with real addresser.
    fake_first_id = FirstPersonIdentity0(address_algo=1)
    fake_third_id = fake_first_id.third_party
    
    # Keep them around for later!
    known_third_parties[fake_third_id.author_guid] = fake_third_id
    
    # Try it for rls
    first_id_1 = FirstPersonIdentity1(address_algo=1)
    third_id_1 = first_id_1.third_party
    
    # Test them on GEOCs:
    _dummy_payload = b'[[ Hello, world? ]]'
    
    secret1, guid1, geoc_1p = fake_first_id.make_object(_dummy_payload)
    secret2, guid2, geoc_2p = first_id_1.make_object(_dummy_payload)
    
    # Now try making static bindings for them.
    bind1_guid, bind1 = fake_first_id.bind_static(guid1)
    bind2_guid, bind2 = first_id_1.bind_static(guid2)
    
    # Normal unpacking operation for first
    # Should add something within firstpartyidentity that figures out the
    # author for you, so you don't have to do this bit.
    geoc_1r = GEOC.unpack(geoc_1p)
    author_1 = known_third_parties[geoc_1r.author]
    guid_1, geoc_1r_plaintext = author_1.load_geoc(secret1, geoc_1p)
    
    # Extra-normal unpacking operation for third.
    # Note that the author lookup ideally shouldn't be necessary if you already 
    # know who it is.
    guid_2, geoc_2r_plaintext = third_id_1.load_geoc(secret2, geoc_2p)
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()