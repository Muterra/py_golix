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

import unittest
import sys
import collections

# These are normal imports
from golix import Ghid

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


_dummy_payload = b'[[ Hello, world? ]]'
_dummy_payload_2 = b'[[ Hiyaback! ]]'
    

class CipherTest(unittest.TestCase):
    ''' Test out ciphersuites.
    '''
    
    @classmethod
    def setUpClass(cls):
        ''' Create first-person identities.
        '''
        cls.firstparty_0 = FirstParty0(address_algo=1)
        cls.secondparty_0 = cls.firstparty_0.second_party
        
        cls.firstparty_1a = FirstParty1(address_algo=1)
        cls.secondparty_1a = cls.firstparty_1a.second_party
        
        cls.firstparty_1b = FirstParty1(address_algo=1)
        cls.secondparty_1b = cls.firstparty_1b.second_party
        
        cls.thirdparty_0 = ThirdParty0()
        cls.thirdparty_1 = ThirdParty1()
    
    def test_identity_serialization_cipher0(self):
        ''' Make sure identities can serialize themselves.
        '''
        # Dummy first-person identity tests with real addresser.
        ffid_pack = self.firstparty_0._serialize()
        ffid_unpack = FirstParty0._from_serialized(ffid_pack)
    
    def test_identity_serialization_cipher1(self):
        ''' Make sure identities can serialize themselves.
        '''
        fid1_pack = self.firstparty_1a._serialize()
        fid1_unpack = FirstParty1._from_serialized(fid1_pack)
        
    def test_geoc_cipher0(self):
        secret1 = self.firstparty_0.new_secret()
        secret1a = self.firstparty_0.new_secret()
        
        container1 = self.firstparty_0.make_container(
            secret = secret1,
            plaintext = _dummy_payload
        )
        container1a = self.firstparty_0.make_container(
            secret = secret1a,
            plaintext = _dummy_payload_2
        )
        
        geoc1 = self.firstparty_0.unpack_container(
            packed = container1.packed
        )
        geoc_1r_plaintext = self.firstparty_0.receive_container(
            author = self.secondparty_0,
            secret = secret1,
            container = geoc1
        )
        geoc1a = self.firstparty_0.unpack_container(
            packed = container1a.packed
        )
        geoc_1ar_plaintext = self.firstparty_0.receive_container(
            author = self.secondparty_0,
            secret = secret1a,
            container = geoc1a
        )
        
        self.thirdparty_0.verify_object(
            second_party = self.secondparty_0,
            obj = geoc1
        )
        self.thirdparty_0.verify_object(
            second_party = self.secondparty_0,
            obj = geoc1a
        )
        
    def test_geoc_cipher1(self):
        secret2 = self.firstparty_1a.new_secret()
        secret2a = self.firstparty_1a.new_secret()
        
        container2 = self.firstparty_1a.make_container(
            secret = secret2,
            plaintext = _dummy_payload
        )
        container2a = self.firstparty_1a.make_container(
            secret = secret2a,
            plaintext = _dummy_payload_2
        )
        
        geoc2 = self.firstparty_1b.unpack_container(
            packed = container2.packed
        )
        geoc_2r_plaintext = self.firstparty_1b.receive_container(
            author = self.secondparty_1a,
            secret = secret2,
            container = geoc2
        )
        geoc2a = self.firstparty_1b.unpack_container(
            packed = container2a.packed
        )
        geoc_2ar_plaintext = self.firstparty_1b.receive_container(
            author = self.secondparty_1a,
            secret = secret2a,
            container = geoc2a
        )
        
        self.thirdparty_1.verify_object(
            second_party = self.secondparty_1a,
            obj = geoc2
        )
        self.thirdparty_1.verify_object(
            second_party = self.secondparty_1a,
            obj = geoc2a
        )
        
    def test_gobs_cipher0(self):
        bind1 = self.firstparty_0.make_bind_static(
            target = Ghid.pseudorandom(algo=1)
        )
        gobs1 = self.firstparty_0.unpack_bind_static(
            packed = bind1.packed
        )
        target_s1 = self.firstparty_0.receive_bind_static(
            binder = self.secondparty_0,
            binding = gobs1
        )
        
        self.thirdparty_0.verify_object(
            second_party = self.secondparty_0,
            obj = gobs1
        )
        
    def test_gobs_cipher1(self):
        bind2 = self.firstparty_1a.make_bind_static(
            target = Ghid.pseudorandom(algo=1)
        )
        gobs2 = self.firstparty_1b.unpack_bind_static(
            packed = bind2.packed
        )
        target_s2 = self.firstparty_1b.receive_bind_static(
            binder = self.secondparty_1a,
            binding = gobs2
        )
        
        self.thirdparty_1.verify_object(
            second_party = self.secondparty_1a,
            obj = gobs2
        )
        
    def test_gobd_cipher0(self):
        # --------------------------------------------------------------
        # Now try making dynamic bindings for them.
        bind1d = self.firstparty_0.make_bind_dynamic(
            counter = 0,
            target_vector = (Ghid.pseudorandom(algo=1),)
        )
        
        # And try making dynamic bindings with history now.
        
        bind1d2 = self.firstparty_0.make_bind_dynamic(
            ghid_dynamic = bind1d.ghid_dynamic,
            counter = 1,
            target_vector = (
                Ghid.pseudorandom(algo=1),
                Ghid.pseudorandom(algo=1)
            )
        )
        self.assertEqual(bind1d2.ghid_dynamic, bind1d.ghid_dynamic)
        
        # Fake, no history
        gobd1 = self.firstparty_0.unpack_bind_dynamic(
            packed = bind1d.packed
        )
        target_d1 = self.firstparty_0.receive_bind_dynamic(
            binder = self.secondparty_0,
            binding = gobd1
        )
        # Fake, history
        gobd12 = self.firstparty_0.unpack_bind_dynamic(
            packed = bind1d.packed
        )
        target_d12 = self.firstparty_0.receive_bind_dynamic(
            binder = self.secondparty_0,
            binding = gobd12
        )
        
        self.thirdparty_0.verify_object(
            second_party = self.secondparty_0,
            obj = gobd1
        )
        self.thirdparty_0.verify_object(
            second_party = self.secondparty_0,
            obj = gobd12
        )
        
    def test_gobd_cipher1(self):
        bind2d = self.firstparty_1a.make_bind_dynamic(
            counter = 0,
            target_vector = (Ghid.pseudorandom(algo=1),)
        )
        
        # And try making dynamic bindings with history now.
        
        bind2d2 = self.firstparty_1a.make_bind_dynamic(
            ghid_dynamic = bind2d.ghid_dynamic,
            counter = 1,
            target_vector = (
                Ghid.pseudorandom(algo=1),
                Ghid.pseudorandom(algo=1)
            )
        )
        
        self.assertEqual(bind2d2.ghid_dynamic, bind2d.ghid_dynamic)
        
        # Real, no history
        gobd2 = self.firstparty_1b.unpack_bind_dynamic(
            packed = bind2d.packed
        )
        target_d2 = self.firstparty_1b.receive_bind_dynamic(
            binder = self.secondparty_1a,
            binding = gobd2
        )
        # Real, history
        gobd22 = self.firstparty_1b.unpack_bind_dynamic(
            packed = bind2d2.packed
        )
        target_d22 = self.firstparty_1b.receive_bind_dynamic(
            binder = self.secondparty_1a,
            binding = gobd22
        )
        
        self.thirdparty_1.verify_object(
            second_party = self.secondparty_1a,
            obj = gobd2
        )
        self.thirdparty_1.verify_object(
            second_party = self.secondparty_1a,
            obj = gobd22
        )
        
    def test_gdxx_cipher0(self):
        # --------------------------------------------------------------
        # And go ahead and make debindings for everything.
        debind1 = self.firstparty_0.make_debind(
            target = Ghid.pseudorandom(algo=1)
        )
        gdxx1 = self.firstparty_0.unpack_debind(
            packed = debind1.packed
        )
        target_x1 = self.firstparty_0.receive_debind(
            debinder = self.secondparty_0,
            debinding = gdxx1
        )
        
        self.thirdparty_0.verify_object(
            second_party = self.secondparty_0,
            obj = gdxx1
        )
        
    def test_gdxx_cipher1(self):
        debind2 = self.firstparty_1a.make_debind(
            target = Ghid.pseudorandom(algo=1)
        )
        gdxx2 = self.firstparty_1b.unpack_debind(
            packed = debind2.packed
        )
        target_x2 = self.firstparty_1b.receive_debind(
            debinder = self.secondparty_1a,
            debinding = gdxx2
        )
        
        self.thirdparty_1.verify_object(
            second_party = self.secondparty_1a,
            obj = gdxx2
        )
        
    def test_garq_handshake_cipher0(self):
        # --------------------------------------------------------------
        # Asymmetric handshakes
        secret1 = self.firstparty_0.new_secret()
        
        ahand1 = self.firstparty_0.make_handshake(
            target = Ghid.pseudorandom(algo=1),
            secret = secret1
        )
        areq1a = self.firstparty_0.make_request(
            recipient = self.secondparty_0,
            request = ahand1
        )
        
    def test_garq_handshake_cipher1(self):
        secret2 = self.firstparty_1a.new_secret()
        
        ahand2 = self.firstparty_1a.make_handshake(
            target = Ghid.pseudorandom(algo=1),
            secret = secret2
        )
        areq2a = self.firstparty_1a.make_request(
            recipient = self.secondparty_1b,
            request = ahand2
        )
        areq2_up = self.firstparty_1b.unpack_request(
            packed = areq2a.packed
        )
        areq2_rec = self.firstparty_1b.receive_request(
            requestor = self.secondparty_1a,
            request = areq2_up
        )
        
    def test_garq_ack_cipher0(self):
        # --------------------------------------------------------------
        # Asymmetric ack
        aack1 = self.firstparty_0.make_ack(
            target = Ghid.pseudorandom(algo=1)
        )
        areq1b = self.firstparty_0.make_request(
            recipient = self.secondparty_0,
            request = aack1
        )
        
    def test_garq_ack_cipher1(self):
        aack2 = self.firstparty_1a.make_ack(
            target = Ghid.pseudorandom(algo=1)
        )
        areq2b = self.firstparty_1a.make_request(
            recipient = self.secondparty_1b,
            request = aack2
        )
        
        aack2_up = self.firstparty_1b.unpack_request(
            packed = areq2b.packed
        )
        aack2_rec = self.firstparty_1b.receive_request(
            requestor = self.secondparty_1a,
            request = aack2_up
        )
        
    def test_garq_nak_cipher0(self):
        # --------------------------------------------------------------
        # Asymmetric nak
        anak1 = self.firstparty_0.make_nak(
            target = Ghid.pseudorandom(algo=1)
        )
        areq1c = self.firstparty_0.make_request(
            recipient = self.secondparty_0,
            request = anak1
        )
        
    def test_garq_nak_cipher1(self):
        anak2 = self.firstparty_1a.make_nak(
            target = Ghid.pseudorandom(algo=1)
        )
        areq2c = self.firstparty_1a.make_request(
            recipient = self.secondparty_1b,
            request = anak2
        )
        anak2_up = self.firstparty_1b.unpack_request(
            packed = areq2c.packed
        )
        anak2_rec = self.firstparty_1b.receive_request(
            requestor = self.secondparty_1a,
            request = anak2_up
        )
        
    # Don't bother testing asymmetric in trashtest (should simply raise)

                
if __name__ == '__main__':
    unittest.main()
