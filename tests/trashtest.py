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
    first_id_2 = FirstPersonIdentity1(address_algo=1)
    third_id_1 = first_id_1.third_party
    third_id_2 = first_id_2.third_party
    
    # Test them on GEOCs:
    _dummy_payload = b'[[ Hello, world? ]]'
    _dummy_payload_2 = b'[[ Hiyaback! ]]'
    
    secret1 = fake_first_id.new_secret()
    secret1a = fake_first_id.new_secret()
    secret2 = first_id_1.new_secret()
    secret2a = first_id_1.new_secret()
    
    obj1_guid, obj1 = fake_first_id.make_object(secret1, _dummy_payload)
    obj1a_guid, obj1a = fake_first_id.make_object(secret1a, _dummy_payload_2)
    obj2_guid, obj2 = first_id_1.make_object(secret2, _dummy_payload)
    obj2a_guid, obj2a = first_id_1.make_object(secret2a, _dummy_payload_2)
    
    # Now try making static bindings for them.
    bind1_guid, bind1 = fake_first_id.make_bind_static(obj1_guid)
    bind2_guid, bind2 = first_id_1.make_bind_static(obj2_guid)
    
    # Now try making dynamic bindings for them.
    bind1d_guid1, bind1d, bind1d_guid = fake_first_id.make_bind_dynamic(obj1_guid)
    bind2d_guid1, bind2d, bind2d_guid = first_id_1.make_bind_dynamic(obj2_guid)
    
    # And try making dynamic bindings with history now.
    bind1d_guid2, bind1d2, bind1d_guidR = fake_first_id.make_bind_dynamic(
        guid = obj1a_guid,
        address = bind1d_guid,
        history = [bind1d_guid1]
    )
    assert bind1d_guidR == bind1d_guid
    
    bind2d_guid2, bind2d2, bind2d_guidR = first_id_1.make_bind_dynamic(
        guid = obj2a_guid,
        address = bind2d_guid,
        history = [bind2d_guid1]
    )
    assert bind2d_guidR == bind2d_guid
    
    # And go ahead and make debindings for everything.
    debind1_guid, debind1 = fake_first_id.make_debind(bind1_guid)
    debind1d_guid, debind1d = fake_first_id.make_debind(bind1d_guid)
    debind2_guid, debind2 = first_id_1.make_debind(bind2_guid)
    debind2d_guid, debind2d = first_id_1.make_debind(bind2d_guid)
    
    # Asymmetric handshakes
    ahand1 = fake_first_id.make_handshake(
        target = obj1_guid,
        secret = secret1
    )
    areq1a_guid, areq1a = fake_first_id.make_request(
        recipient = fake_third_id,
        request = ahand1
    )
    
    ahand2 = first_id_1.make_handshake(
        target = obj2_guid,
        secret = secret2
    )
    areq2a_guid, areq2a = first_id_1.make_request(
        recipient = third_id_2,
        request = ahand2
    )
    
    # Asymmetric ack
    aack1 = fake_first_id.make_ack(
        target = areq1a_guid
    )
    areq1b_guid, areq1b = fake_first_id.make_request(
        recipient = fake_third_id,
        request = aack1
    )
    
    aack2 = first_id_1.make_ack(
        target = areq2a_guid
    )
    areq2b_guid, areq2b = first_id_1.make_request(
        recipient = third_id_2,
        request = aack2
    )
    
    # Asymmetric nak
    anak1 = fake_first_id.make_nak(
        target = areq1a_guid
    )
    areq1c_guid, areq1c = fake_first_id.make_request(
        recipient = fake_third_id,
        request = anak1
    )
    
    anak2 = first_id_1.make_nak(
        target = areq2a_guid
    )
    areq2c_guid, areq2c = first_id_1.make_request(
        recipient = third_id_2,
        request = anak2
    )
    
    
    # -------------------------------------------------------------------------
    # Unpacking and retrieval tests
    
    # Normal unpacking operation for first
    # Should add something within firstpartyidentity that figures out the
    # author for you, so you don't have to do this bit.
    authorguid_1, geoc1 = fake_first_id.unpack_object(obj1)
    author_1 = known_third_parties[authorguid_1]
    guid_1, geoc_1r_plaintext = fake_first_id.receive_object(author_1, secret1, geoc1)
    
    # Extra-normal unpacking operation for third.
    # Note that the author lookup ideally shouldn't be necessary if you already 
    # know who it is.
    authorguid_2, geoc2 = first_id_2.unpack_object(obj2)
    guid_2, geoc_2r_plaintext = first_id_2.receive_object(third_id_1, secret2, geoc2)
    
    
    # Test all of the real (fake won't work because of the fake asym payload)
    # asymmetric requests
    authorguid_2, areq2_up = first_id_2.unpack_request(areq2a)
    areq2_rec = first_id_2.receive_request(third_id_1, areq2_up)
    
    authorguid_2, aack2_up = first_id_2.unpack_request(areq2b)
    aack2_rec = first_id_2.receive_request(third_id_1, aack2_up)
    
    authorguid_2, anak2_up = first_id_2.unpack_request(areq2c)
    anak2_rec = first_id_2.receive_request(third_id_1, anak2_up)
    
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()