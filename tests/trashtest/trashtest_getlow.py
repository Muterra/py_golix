'''
Scratchpad for test-based development. Unit tests for _getlow.py.

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

# These are normal inclusions
from golix import Ghid

# These are abnormal (don't use in production) inclusions.
from golix._getlow import GEOC
from golix._getlow import GIDC
from golix._getlow import GOBS
from golix._getlow import GOBD
from golix._getlow import GDXX
from golix._getlow import GARQ
from golix._getlow import GARQHandshake
from golix._getlow import GARQAck
from golix._getlow import GARQNak
from golix._getlow import GARQElse

from golix.crypto_utils import Secret
from golix.crypto_utils import _dummy_signature
from golix.crypto_utils import _dummy_mac
from golix.crypto_utils import _dummy_asym
from golix.crypto_utils import _dummy_address
from golix.crypto_utils import _dummy_pubkey
from golix.crypto_utils import _dummy_pubkey_exchange
from golix.utils import _dummy_ghid

# These are soon-to-be-removed abnormal imports
from golix._spec import _gidc, _geoc, _gobs, _gobd, _gdxx, _garq
from golix._spec import _asym_hand, _asym_ak, _asym_nk, _asym_else


# ###############################################
# Testing
# ###############################################
        
# Dummy payload and authors for GEOC objects
_dummy_payload = \
    b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
_dummy_author = Ghid.placeholder()
_rls_author = Ghid.pseudorandom(1)


class TestLow(unittest.TestCase):
    ''' Test everything within _getlow.
    '''
    
    def test_gidc_placeholder_address(self):
        # GIDC dummy address test.
        gidc_1 = GIDC(
            signature_key = _dummy_pubkey,
            encryption_key = _dummy_pubkey,
            exchange_key = _dummy_pubkey_exchange,
        )
        gidc_1.pack(cipher=0, address_algo=0)
        gidc_1p = gidc_1.packed
        gidc_1r = GIDC.unpack(gidc_1p)
        
        self.assertEqual(gidc_1, gidc_1r)
        
    def test_gidc_real_address(self):
        # GIDC actual address test.
        gidc_2 = GIDC(
            signature_key = _dummy_pubkey,
            encryption_key = _dummy_pubkey,
            exchange_key = _dummy_pubkey_exchange,
        )
        gidc_2.pack(cipher=0, address_algo=1)
        gidc_2p = gidc_2.packed
        gidc_2r = GIDC.unpack(gidc_2p)
        
        self.assertEqual(gidc_2, gidc_2r)
        
    def test_geoc_placeholder_address(self):
        # GEOC dummy address test.
        geoc_1 = GEOC(author=_dummy_author, payload=_dummy_payload)
        geoc_1.pack(cipher=0, address_algo=0)
        geoc_1.pack_signature(_dummy_signature)
        geoc_1p = geoc_1.packed
        geoc_1r = GEOC.unpack(geoc_1p)
        
        self.assertEqual(geoc_1, geoc_1r)
        
    def test_geoc_real_address(self):
        # GEOC actual address test.
        geoc_2 = GEOC(author=_rls_author, payload=_dummy_payload)
        geoc_2.pack(cipher=0, address_algo=1)
        geoc_2.pack_signature(_dummy_signature)
        geoc_2p = geoc_2.packed
        geoc_2r = GEOC.unpack(geoc_2p)
        
        self.assertEqual(geoc_2, geoc_2r)
        
    def test_gobs_placeholder_address(self):
        # GOBS dummy address test.
        gobs_1 = GOBS(
            binder=_dummy_author,
            target=_dummy_ghid
        )
        gobs_1.pack(cipher=0, address_algo=0)
        gobs_1.pack_signature(_dummy_signature)
        gobs_1p = gobs_1.packed
        gobs_1r = GOBS.unpack(gobs_1p)
        
        self.assertEqual(gobs_1, gobs_1r)
        
    def test_gobs_real_address(self):
        # GOBS actual address test.
        gobs_2 = GOBS(
            binder=_rls_author,
            target=_dummy_ghid
        )
        gobs_2.pack(cipher=0, address_algo=1)
        gobs_2.pack_signature(_dummy_signature)
        gobs_2p = gobs_2.packed
        gobs_2r = GOBS.unpack(gobs_2p)
        
        self.assertEqual(gobs_2, gobs_2r)
        
    def test_gobd_placeholder_address(self):
        # GOBD dummy address test.
        gobd_1 = GOBD(
            binder = _dummy_author,
            counter = 0,
            target_vector = (_dummy_ghid,)
        )
        gobd_1.pack(cipher=0, address_algo=0)
        gobd_1.pack_signature(_dummy_signature)
        gobd_1p = gobd_1.packed
        gobd_1r = GOBD.unpack(gobd_1p)
        
        self.assertEqual(gobd_1, gobd_1r)
        
    def test_gobd_real_address(self):
        # GOBD actual address test.
        gobd_2 = GOBD(
            binder = _rls_author,
            counter = 0,
            target_vector = (_dummy_ghid,)
        )
        gobd_2.pack(cipher=0, address_algo=1)
        gobd_2.pack_signature(_dummy_signature)
        gobd_2p = gobd_2.packed
        gobd_2r = GOBD.unpack(gobd_2p)
        
        self.assertEqual(gobd_2, gobd_2r)
        
    def test_gobd_real_address_with_history(self):
        # GOBD actual address test, with history
        gobd_3 = GOBD(
            binder = _rls_author,
            counter = 0,
            target_vector = (_dummy_ghid, _dummy_ghid),
            ghid_dynamic = Ghid.pseudorandom(1)
        )
        gobd_3.pack(cipher=0, address_algo=1)
        gobd_3.pack_signature(_dummy_signature)
        gobd_3p = gobd_3.packed
        gobd_3r = GOBD.unpack(gobd_3p)
        
        self.assertEqual(gobd_3, gobd_3r)
        
    def test_gdxx_placeholder_address(self):
        # GDXX dummy address test.
        gdxx_1 = GDXX(
            debinder=_dummy_author,
            target=_dummy_ghid
        )
        gdxx_1.pack(cipher=0, address_algo=0)
        gdxx_1.pack_signature(_dummy_signature)
        gdxx_1p = gdxx_1.packed
        gdxx_1r = GDXX.unpack(gdxx_1p)
        
        self.assertEqual(gdxx_1, gdxx_1r)
        
    def test_gdxx_real_address(self):
        # GDXX actual address test.
        gdxx_2 = GDXX(
            debinder=_rls_author,
            target=_dummy_ghid
        )
        gdxx_2.pack(cipher=0, address_algo=1)
        gdxx_2.pack_signature(_dummy_signature)
        gdxx_2p = gdxx_2.packed
        gdxx_2r = GDXX.unpack(gdxx_2p)
        
        self.assertEqual(gdxx_2, gdxx_2r)
        
    def test_garq_placeholder_address(self):
        # GARQ dummy address test.
        garq_1 = GARQ(
            recipient=_dummy_author,
            payload=_dummy_asym
        )
        garq_1.pack(cipher=0, address_algo=0)
        garq_1.pack_signature(_dummy_mac)
        garq_1p = garq_1.packed
        garq_1r = GARQ.unpack(garq_1p)
        
        self.assertEqual(garq_1, garq_1r)
        
    def test_garq_real_address(self):
        # GARQ actual address test.
        garq_2 = GARQ(
            recipient=_rls_author,
            payload=_dummy_asym
        )
        garq_2.pack(cipher=0, address_algo=1)
        garq_2.pack_signature(_dummy_mac)
        garq_2p = garq_2.packed
        garq_2r = GARQ.unpack(garq_2p)
        
        self.assertEqual(garq_2, garq_2r)
        
    def test_handshake(self):
        # Asym request testing
        asrq_1 = GARQHandshake(
            author=_dummy_author,
            target=_dummy_ghid,
            secret=Secret(
                cipher = 1,
                key = b'[--Check out my sweet key, yo!-]',
                seed = b'[And my seed...]'
            ))
        asrq_1.pack()
        asrq_1p = asrq_1.packed
        asrq_1r = GARQHandshake.unpack(asrq_1p)
        
        self.assertEqual(asrq_1, asrq_1r)
        
    def test_ack(self):
        # Asym ack testing
        asak_1 = GARQAck(
            author=_dummy_author,
            target=_dummy_ghid,
            status=5
        )
        asak_1.pack()
        asak_1p = asak_1.packed
        asak_1r = GARQAck.unpack(asak_1p)
        
        self.assertEqual(asak_1, asak_1r)
        
    def test_nak(self):
        # Asym ack testing
        asnk_1 = GARQNak(
            author=_dummy_author,
            target=_dummy_ghid,
            status=7
        )
        asnk_1.pack()
        asnk_1p = asnk_1.packed
        asnk_1r = GARQNak.unpack(asnk_1p)
        
        self.assertEqual(asnk_1, asnk_1r)
        
    def test_asymelse(self):
        # Asym else testing
        asel_1 = GARQElse(
            author=_dummy_author,
            payload=b'Hello world'
        )
        asel_1.pack()
        asel_1p = asel_1.packed
        asel_1r = GARQElse.unpack(asel_1p)
        
        self.assertEqual(asel_1, asel_1r)


if __name__ == '__main__':
    unittest.main()
