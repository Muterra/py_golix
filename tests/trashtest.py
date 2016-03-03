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

# These are normal imports
from golix import Guid

# These are semi-normal imports
from golix.cipher import FirstPartyIdentity0
from golix.cipher import SecondPartyIdentity0
from golix.cipher import FirstPartyIdentity1
from golix.cipher import SecondPartyIdentity1

# These are abnormal (don't use in production) imports.
from golix._spec import _dummy_signature
from golix._spec import _dummy_mac
from golix._spec import _dummy_asym
from golix._spec import _dummy_address

# ###############################################
# Testing
# ###############################################
    
def run():
    # Check this out!
    known_third_parties = {}
    
    # Dummy first-person identity tests with real addresser.
    fake_first_id = FirstPartyIdentity0(address_algo=1)
    fake_third_id = fake_first_id.second_party
    
    # Keep them around for later!
    known_third_parties[fake_third_id.author_guid] = fake_third_id
    
    # -------------------------------------------------------------------------
    # Try it for rls
    first_id_1 = FirstPartyIdentity1(address_algo=1)
    first_id_2 = FirstPartyIdentity1(address_algo=1)
    third_id_1 = first_id_1.second_party
    third_id_2 = first_id_2.second_party
    
    # -------------------------------------------------------------------------
    # Test them on GEOCs:
    _dummy_payload = b'[[ Hello, world? ]]'
    _dummy_payload_2 = b'[[ Hiyaback! ]]'
    
    secret1 = fake_first_id.new_secret()
    secret1a = fake_first_id.new_secret()
    secret2 = first_id_1.new_secret()
    secret2a = first_id_1.new_secret()
    
    obj1_guid, obj1 = fake_first_id.make_object(
        secret = secret1, 
        plaintext = _dummy_payload
    )
    obj1a_guid, obj1a = fake_first_id.make_object(
        secret = secret1a, 
        plaintext = _dummy_payload_2
    )
    obj2_guid, obj2 = first_id_1.make_object(
        secret = secret2, 
        plaintext = _dummy_payload
    )
    obj2a_guid, obj2a = first_id_1.make_object(
        secret = secret2a, 
        plaintext = _dummy_payload_2
    )
    
    # -------------------------------------------------------------------------
    # Now try making static bindings for them.
    bind1_guid, bind1 = fake_first_id.make_bind_static(
        target = obj1_guid
    )
    bind2_guid, bind2 = first_id_1.make_bind_static(
        target = obj2_guid
    )
    
    # -------------------------------------------------------------------------
    # Now try making dynamic bindings for them.
    bind1d_guid1, bind1d, bind1d_guid = fake_first_id.make_bind_dynamic(
        target = obj1_guid
    )
    bind2d_guid1, bind2d, bind2d_guid = first_id_1.make_bind_dynamic(
        target = obj2_guid
    )
    
    # And try making dynamic bindings with history now.
    bind1d_guid2, bind1d2, bind1d_guidR = fake_first_id.make_bind_dynamic(
        target = obj1a_guid,
        address = bind1d_guid,
        history = [bind1d_guid1]
    )
    assert bind1d_guidR == bind1d_guid
    
    bind2d_guid2, bind2d2, bind2d_guidR = first_id_1.make_bind_dynamic(
        target = obj2a_guid,
        address = bind2d_guid,
        history = [bind2d_guid1]
    )
    assert bind2d_guidR == bind2d_guid
    
    # -------------------------------------------------------------------------
    # And go ahead and make debindings for everything.
    debind1_guid, debind1 = fake_first_id.make_debind(
        target = bind1_guid
    )
    debind1d_guid, debind1d = fake_first_id.make_debind(
        target = bind1d_guid
    )
    debind2_guid, debind2 = first_id_1.make_debind(
        target = bind2_guid
    )
    debind2d_guid, debind2d = first_id_1.make_debind(
        target = bind2d_guid
    )
    
    # -------------------------------------------------------------------------
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
    
    # -------------------------------------------------------------------------
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
    
    # -------------------------------------------------------------------------
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
    # -------------------------------------------------------------------------
    
    # -------------------------------------------------------------------------
    # Objects
    authorguid_1, geoc1 = fake_first_id.unpack_object(
        packed = obj1
    )
    author_1 = known_third_parties[authorguid_1]
    guid_1, geoc_1r_plaintext = fake_first_id.receive_object(
        author = author_1, 
        secret = secret1, 
        obj = geoc1
    )
    
    # Note that the author lookup ideally shouldn't be necessary if you already 
    # know who it is.
    authorguid_2, geoc2 = first_id_2.unpack_object(
        packed = obj2
    )
    author_2 = third_id_1
    guid_2, geoc_2r_plaintext = first_id_2.receive_object(
        author = author_2, 
        secret = secret2, 
        obj = geoc2
    )
    
    # -------------------------------------------------------------------------
    # Static bindings
    binder1_guid, gobs1 = fake_first_id.unpack_bind_static(
        packed = bind1
    )
    guid_3, target_s1 = fake_first_id.receive_bind_static(
        binder = author_1, 
        binding = gobs1
    )
    
    binder2_guid, gobs2 = first_id_2.unpack_bind_static(
        packed = bind2
    )
    guid_4, target_s2 = first_id_2.receive_bind_static(
        binder = author_2, 
        binding = gobs2
    )
    
    # -------------------------------------------------------------------------
    # Dynamic bindings
    # Fake, no history
    binder1d_guid, gobd1 = fake_first_id.unpack_bind_dynamic(
        packed = bind1d
    )
    guid_5, target_d1, history_1 = fake_first_id.receive_bind_dynamic(
        binder = author_1, 
        binding = gobd1
    )
    # Fake, history
    binder1d2_guid, gobd12 = fake_first_id.unpack_bind_dynamic(
        packed = bind1d
    )
    guid_5b, target_d12, history_12 = fake_first_id.receive_bind_dynamic(
        binder = author_1, 
        binding = gobd12
    )
    
    # Real, no history
    binder2d_guid, gobd2 = first_id_2.unpack_bind_dynamic(
        packed = bind2d
    )
    guid_6, target_d2, history_2 = first_id_2.receive_bind_dynamic(
        binder = author_2, 
        binding = gobd2
    )
    # Real, history
    binder2d_guid, gobd22 = first_id_2.unpack_bind_dynamic(
        packed = bind2d2
    )
    guid_6b, target_d22, history_22 = first_id_2.receive_bind_dynamic(
        binder = author_2, 
        binding = gobd22
    )
    
    # -------------------------------------------------------------------------
    # Static bindings
    debinder1_guid, gdxx1 = fake_first_id.unpack_debind(
        packed = debind1
    )
    guid_7, target_x1 = fake_first_id.receive_debind(
        debinder = author_1, 
        debinding = gdxx1
    )
    
    debinder2_guid, gdxx2 = first_id_2.unpack_debind(
        packed = debind2
    )
    guid_8, target_x2 = first_id_2.receive_debind(
        debinder = author_2, 
        debinding = gdxx2
    )
    
    # -------------------------------------------------------------------------
    # Test all of the real (fake won't work because of the fake asym payload)
    # asymmetric requests
    authorguid_2, areq2_up = first_id_2.unpack_request(
        packed = areq2a
    )
    areq2_rec = first_id_2.receive_request(
        requestor = third_id_1, 
        request = areq2_up
    )
    
    authorguid_2, aack2_up = first_id_2.unpack_request(
        packed = areq2b
    )
    aack2_rec = first_id_2.receive_request(
        requestor = third_id_1, 
        request = aack2_up
    )
    
    authorguid_2, anak2_up = first_id_2.unpack_request(
        packed = areq2c
    )
    anak2_rec = first_id_2.receive_request(
        requestor = third_id_1, 
        request = anak2_up
    )
    
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()