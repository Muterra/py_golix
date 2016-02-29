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

import sys
import collections

# These are normal inclusions
from golix import Guid

# These are abnormal (don't use in production) inclusions.
from golix._getlow import GEOC
from golix._getlow import GIDC
from golix._getlow import GOBS
from golix._getlow import GOBD
from golix._getlow import GDXX
from golix._getlow import GARQ
from golix._getlow import AsymRequest
from golix._getlow import AsymAck
from golix._getlow import AsymNak
from golix._getlow import AsymElse

from golix.utils import Secret
from golix.utils import _dummy_signature
from golix.utils import _dummy_mac
from golix.utils import _dummy_asym
from golix.utils import _dummy_address
from golix.utils import _dummy_pubkey
from golix.utils import _dummy_guid

# These are soon-to-be-removed abnormal imports
from golix._spec import _gidc, _geoc, _gobs, _gobd, _gdxx, _garq
from golix._spec import _asym_rq, _asym_ak, _asym_nk, _asym_else

# ###############################################
# Testing
# ###############################################
    
def run():
    # GIDC dummy address test.
    gidc_1 = GIDC(
        signature_key=_dummy_pubkey,
        encryption_key=_dummy_pubkey,
        exchange_key=_dummy_pubkey,
    )
    gidc_1.pack(cipher=0, address_algo=0)
    gidc_1p = gidc_1.packed
    gidc_1r = GIDC.unpack(gidc_1p)
    
    # GIDC actual address test.
    gidc_2 = GIDC(
        signature_key=_dummy_pubkey,
        encryption_key=_dummy_pubkey,
        exchange_key=_dummy_pubkey,
    )
    gidc_2.pack(cipher=0, address_algo=1)
    gidc_2p = gidc_2.packed
    gidc_2r = GIDC.unpack(gidc_2p)
    
    # Dummy payload and authors for GEOC objects
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    _dummy_author = gidc_1.guid
    _rls_author = gidc_2.guid
    
    # GEOC dummy address test.
    geoc_1 = GEOC(author=_dummy_author, payload=_dummy_payload)
    geoc_1.pack(cipher=0, address_algo=0)
    geoc_1.pack_signature(_dummy_signature)
    geoc_1p = geoc_1.packed
    geoc_1r = GEOC.unpack(geoc_1p)
    
    # GEOC actual address test.
    geoc_2 = GEOC(author=_rls_author, payload=_dummy_payload)
    geoc_2.pack(cipher=0, address_algo=1)
    geoc_2.pack_signature(_dummy_signature)
    geoc_2p = geoc_2.packed
    geoc_2r = GEOC.unpack(geoc_2p)
    
    # GOBS dummy address test.
    gobs_1 = GOBS(
        binder=_dummy_author, 
        target=_dummy_guid
    )
    gobs_1.pack(cipher=0, address_algo=0)
    gobs_1.pack_signature(_dummy_signature)
    gobs_1p = gobs_1.packed
    gobs_1r = GOBS.unpack(gobs_1p)
    
    # GOBS actual address test.
    gobs_2 = GOBS(
        binder=_rls_author, 
        target=_dummy_guid
    )
    gobs_2.pack(cipher=0, address_algo=1)
    gobs_2.pack_signature(_dummy_signature)
    gobs_2p = gobs_2.packed
    gobs_2r = GOBS.unpack(gobs_2p)
    
    # GOBD dummy address test.
    gobd_1 = GOBD(
        binder=_dummy_author, 
        targets=[_dummy_guid, _dummy_guid]
    )
    gobd_1.pack(cipher=0, address_algo=0)
    gobd_1.pack_signature(_dummy_signature)
    gobd_1p = gobd_1.packed
    gobd_1r = GOBD.unpack(gobd_1p)
    
    # GOBD actual address test.
    gobd_2 = GOBD(
        binder=_rls_author, 
        targets=[_dummy_guid, _dummy_guid]
    )
    gobd_2.pack(cipher=0, address_algo=1)
    gobd_2.pack_signature(_dummy_signature)
    gobd_2p = gobd_2.packed
    gobd_2r = GOBD.unpack(gobd_2p)
    
    # GOBD actual address test, with history
    gobd_3 = GOBD(
        binder=_rls_author, 
        targets=[_dummy_guid, _dummy_guid],
        dynamic_address=gobd_2.dynamic_address,
        history=[gobd_2.guid]
    )
    gobd_3.pack(cipher=0, address_algo=1)
    gobd_3.pack_signature(_dummy_signature)
    gobd_3p = gobd_3.packed
    gobd_3r = GOBD.unpack(gobd_3p)
    
    # GDXX dummy address test.
    gdxx_1 = GDXX(
        debinder=_dummy_author, 
        target=_dummy_guid
    )
    gdxx_1.pack(cipher=0, address_algo=0)
    gdxx_1.pack_signature(_dummy_signature)
    gdxx_1p = gdxx_1.packed
    gdxx_1r = GDXX.unpack(gdxx_1p)
    
    # GDXX actual address test.
    gdxx_2 = GDXX(
        debinder=_rls_author, 
        target=_dummy_guid
    )
    gdxx_2.pack(cipher=0, address_algo=1)
    gdxx_2.pack_signature(_dummy_signature)
    gdxx_2p = gdxx_2.packed
    gdxx_2r = GDXX.unpack(gdxx_2p)
    
    # GARQ dummy address test.
    garq_1 = GARQ(
        recipient=_dummy_author, 
        payload=_dummy_asym
    )
    garq_1.pack(cipher=0, address_algo=0)
    garq_1.pack_signature(_dummy_mac)
    garq_1p = garq_1.packed
    garq_1r = GARQ.unpack(garq_1p)
    
    # GARQ actual address test.
    garq_2 = GARQ(
        recipient=_rls_author, 
        payload=_dummy_asym
    )
    garq_2.pack(cipher=0, address_algo=1)
    garq_2.pack_signature(_dummy_mac)
    garq_2p = garq_2.packed
    garq_2r = GARQ.unpack(garq_2p)
    
    # Asym request testing
    asrq_1 = AsymRequest(
        author=_dummy_author,
        target=_dummy_guid, 
        secret=Secret(
            cipher = 1,
            key = b'[--Check out my sweet key, yo!-]',
            seed = b'[And my seed...]'
        ))
    asrq_1.pack()
    asrq_1p = asrq_1.packed
    asrq_1r = AsymRequest.unpack(asrq_1p)
    
    # Asym ack testing
    asak_1 = AsymAck(
        author=_dummy_author,
        target=_dummy_guid, 
        status=5
    )
    asak_1.pack()
    asak_1p = asak_1.packed
    asak_1r = AsymAck.unpack(asak_1p)
    
    # Asym ack testing
    asnk_1 = AsymNak(
        author=_dummy_author,
        target=_dummy_guid, 
        status=7
    )
    asnk_1.pack()
    asnk_1p = asnk_1.packed
    asnk_1r = AsymNak.unpack(asnk_1p)
    
    # Asym else testing
    asel_1 = AsymElse(
        author=_dummy_author,
        payload=b'Hello world'
    )
    asel_1.pack()
    asel_1p = asel_1.packed
    asel_1r = AsymElse.unpack(asel_1p)
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()