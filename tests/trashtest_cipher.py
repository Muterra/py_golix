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
from golix.cipher import FirstParty0
from golix.cipher import SecondParty0
from golix.cipher import ThirdParty0
from golix.cipher import FirstParty1
from golix.cipher import SecondParty1
from golix.cipher import ThirdParty1

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
    known_second_parties = {}
    
    # Dummy first-person identity tests with real addresser.
    fake_first_id = FirstParty0(address_algo=1)
    ffid_pack = fake_first_id._serialize()
    ffid_unpack = FirstParty0._from_serialized(ffid_pack)
    fake_second_id = fake_first_id.second_party
    
    # Keep them around for later!
    known_second_parties[fake_second_id.guid] = fake_second_id
    
    # -------------------------------------------------------------------------
    # Try it for rls
    first_id_1 = FirstParty1(address_algo=1)
    first_id_2 = FirstParty1(address_algo=1)
    fid1_pack = first_id_1._serialize()
    fid1_unpack = FirstParty1._from_serialized(fid1_pack)
    second_id_1 = first_id_1.second_party
    second_id_2 = first_id_2.second_party
    
    # -------------------------------------------------------------------------
    # Test them on GEOCs:
    _dummy_payload = b'[[ Hello, world? ]]'
    _dummy_payload_2 = b'[[ Hiyaback! ]]'
    
    secret1 = fake_first_id.new_secret()
    secret1a = fake_first_id.new_secret()
    secret2 = first_id_1.new_secret()
    secret2a = first_id_1.new_secret()
    
    container1 = fake_first_id.make_container(
        secret = secret1, 
        plaintext = _dummy_payload
    )
    container1a = fake_first_id.make_container(
        secret = secret1a, 
        plaintext = _dummy_payload_2
    )
    container2 = first_id_1.make_container(
        secret = secret2, 
        plaintext = _dummy_payload
    )
    container2a = first_id_1.make_container(
        secret = secret2a, 
        plaintext = _dummy_payload_2
    )
    
    # -------------------------------------------------------------------------
    # Now try making static bindings for them.
    bind1 = fake_first_id.make_bind_static(
        target = container1.guid
    )
    bind2 = first_id_1.make_bind_static(
        target = container2.guid
    )
    
    # -------------------------------------------------------------------------
    # Now try making dynamic bindings for them.
    bind1d = fake_first_id.make_bind_dynamic(
        target = container1.guid
    )
    bind2d = first_id_1.make_bind_dynamic(
        target = container2.guid
    )
    
    # And try making dynamic bindings with history now.
    bind1d2 = fake_first_id.make_bind_dynamic(
        target = container1a.guid,
        guid_dynamic = bind1d.guid_dynamic,
        history = [bind1d.guid]
    )
    assert bind1d2.guid_dynamic == bind1d.guid_dynamic
    
    bind2d2 = first_id_1.make_bind_dynamic(
        target = container2a.guid,
        guid_dynamic = bind2d.guid_dynamic,
        history = [bind2d.guid]
    )
    assert bind2d2.guid_dynamic == bind2d.guid_dynamic
    
    # -------------------------------------------------------------------------
    # And go ahead and make debindings for everything.
    debind1 = fake_first_id.make_debind(
        target = bind1.guid
    )
    debind1d = fake_first_id.make_debind(
        target = bind1d.guid_dynamic
    )
    debind2 = first_id_1.make_debind(
        target = bind2.guid
    )
    debind2d = first_id_1.make_debind(
        target = bind2d.guid_dynamic
    )
    
    # -------------------------------------------------------------------------
    # Asymmetric handshakes
    ahand1 = fake_first_id.make_handshake(
        target = container1.guid,
        secret = secret1
    )
    areq1a = fake_first_id.make_request(
        recipient = fake_second_id,
        request = ahand1
    )
    
    ahand2 = first_id_1.make_handshake(
        target = container2.guid,
        secret = secret2
    )
    areq2a = first_id_1.make_request(
        recipient = second_id_2,
        request = ahand2
    )
    
    # -------------------------------------------------------------------------
    # Asymmetric ack
    aack1 = fake_first_id.make_ack(
        target = areq1a.guid
    )
    areq1b = fake_first_id.make_request(
        recipient = fake_second_id,
        request = aack1
    )
    
    aack2 = first_id_1.make_ack(
        target = areq2a.guid
    )
    areq2b = first_id_1.make_request(
        recipient = second_id_2,
        request = aack2
    )
    
    # -------------------------------------------------------------------------
    # Asymmetric nak
    anak1 = fake_first_id.make_nak(
        target = areq1a.guid
    )
    areq1c = fake_first_id.make_request(
        recipient = fake_second_id,
        request = anak1
    )
    
    anak2 = first_id_1.make_nak(
        target = areq2a.guid
    )
    areq2c = first_id_1.make_request(
        recipient = second_id_2,
        request = anak2
    )
    
    
    # -------------------------------------------------------------------------
    # Unpacking and retrieval tests
    # -------------------------------------------------------------------------
    
    # -------------------------------------------------------------------------
    # Containers
    geoc1 = fake_first_id.unpack_container(
        packed = container1.packed
    )
    author_1 = known_second_parties[geoc1.author]
    geoc_1r_plaintext = fake_first_id.receive_container(
        author = author_1, 
        secret = secret1, 
        container = geoc1
    )
    geoc1a = fake_first_id.unpack_container(
        packed = container1a.packed
    )
    geoc_1ar_plaintext = fake_first_id.receive_container(
        author = author_1, 
        secret = secret1a, 
        container = geoc1a
    )
    
    # Note that the author lookup ideally shouldn't be necessary if you already 
    # know who it is.
    geoc2 = first_id_2.unpack_container(
        packed = container2.packed
    )
    author_2 = second_id_1
    geoc_2r_plaintext = first_id_2.receive_container(
        author = author_2, 
        secret = secret2, 
        container = geoc2
    )
    geoc2a = first_id_2.unpack_container(
        packed = container2a.packed
    )
    geoc_2ar_plaintext = first_id_2.receive_container(
        author = author_2, 
        secret = secret2a, 
        container = geoc2a
    )
    
    # -------------------------------------------------------------------------
    # Static bindings
    gobs1 = fake_first_id.unpack_bind_static(
        packed = bind1.packed
    )
    target_s1 = fake_first_id.receive_bind_static(
        binder = author_1, 
        binding = gobs1
    )
    
    gobs2 = first_id_2.unpack_bind_static(
        packed = bind2.packed
    )
    target_s2 = first_id_2.receive_bind_static(
        binder = author_2, 
        binding = gobs2
    )
    
    # -------------------------------------------------------------------------
    # Dynamic bindings
    # Fake, no history
    gobd1 = fake_first_id.unpack_bind_dynamic(
        packed = bind1d.packed
    )
    target_d1 = fake_first_id.receive_bind_dynamic(
        binder = author_1, 
        binding = gobd1
    )
    # Fake, history
    gobd12 = fake_first_id.unpack_bind_dynamic(
        packed = bind1d.packed
    )
    target_d12 = fake_first_id.receive_bind_dynamic(
        binder = author_1, 
        binding = gobd12
    )
    
    # Real, no history
    gobd2 = first_id_2.unpack_bind_dynamic(
        packed = bind2d.packed
    )
    target_d2 = first_id_2.receive_bind_dynamic(
        binder = author_2, 
        binding = gobd2
    )
    # Real, history
    gobd22 = first_id_2.unpack_bind_dynamic(
        packed = bind2d2.packed
    )
    target_d22 = first_id_2.receive_bind_dynamic(
        binder = author_2, 
        binding = gobd22
    )
    
    # -------------------------------------------------------------------------
    # Debindings
    gdxx1 = fake_first_id.unpack_debind(
        packed = debind1.packed
    )
    target_x1 = fake_first_id.receive_debind(
        debinder = author_1, 
        debinding = gdxx1
    )
    
    gdxx2 = first_id_2.unpack_debind(
        packed = debind2.packed
    )
    target_x2 = first_id_2.receive_debind(
        debinder = author_2, 
        debinding = gdxx2
    )
    
    # -------------------------------------------------------------------------
    # Test all of the real (fake won't work because of the fake asym payload)
    # asymmetric requests
    areq2_up = first_id_2.unpack_request(
        packed = areq2a.packed
    )
    areq2_rec = first_id_2.receive_request(
        requestor = second_id_1, 
        request = areq2_up
    )
    
    aack2_up = first_id_2.unpack_request(
        packed = areq2b.packed
    )
    aack2_rec = first_id_2.receive_request(
        requestor = second_id_1, 
        request = aack2_up
    )
    
    anak2_up = first_id_2.unpack_request(
        packed = areq2c.packed
    )
    anak2_rec = first_id_2.receive_request(
        requestor = second_id_1, 
        request = anak2_up
    )
    
    
    # -------------------------------------------------------------------------
    # Test all verification as a server
    
    server0 = ThirdParty0()
    server1 = ThirdParty1()
    
    # Containers
    
    server0.verify_object(
        second_party = fake_second_id,
        obj = geoc1
    )
    server0.verify_object(
        second_party = fake_second_id,
        obj = geoc1a
    )
    
    server1.verify_object(
        second_party = second_id_1, 
        obj = geoc2
    )
    server1.verify_object(
        second_party = second_id_1,
        obj = geoc2a
    )
    
    # Static bindings
    
    server0.verify_object(
        second_party = fake_second_id,
        obj = gobs1
    )
    
    server1.verify_object(
        second_party = second_id_1,
        obj = gobs2
    )
    
    # Dynamic bindings
    
    server0.verify_object(
        second_party = fake_second_id,
        obj = gobd1
    )
    server0.verify_object(
        second_party = fake_second_id,
        obj = gobd12
    )
    
    server1.verify_object(
        second_party = second_id_1,
        obj = gobd2
    )
    server1.verify_object(
        second_party = second_id_1,
        obj = gobd22
    )
    
    # Debindings
    
    server0.verify_object(
        second_party = fake_second_id,
        obj = gdxx1
    )
    
    server1.verify_object(
        second_party = second_id_1,
        obj = gdxx2
    )
    
    # Don't bother testing asymmetric in trashtest (should simply raise)
    
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()