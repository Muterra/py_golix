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
from mupy._getlow import MIDC
from mupy._getlow import MOBS
from mupy._getlow import MOBD
from mupy._getlow import MDXX
from mupy._getlow import MEAR
from mupy._getlow import AsymRequest
from mupy._getlow import AsymAck
from mupy._getlow import AsymNak
from mupy._getlow import AsymElse

from mupy.utils import Secret
from mupy.utils import _dummy_signature
from mupy.utils import _dummy_mac
from mupy.utils import _dummy_asym
from mupy.utils import _dummy_address
from mupy.utils import _dummy_pubkey
from mupy.utils import _dummy_muid

# These are soon-to-be-removed abnormal imports
from mupy._spec import _midc, _meoc, _mobs, _mobd, _mdxx, _mear
from mupy._spec import _asym_rq, _asym_ak, _asym_nk, _asym_else

# ###############################################
# Testing
# ###############################################
                
if __name__ == '__main__':
    # MIDC dummy address test.
    midc_1 = MIDC(
        signature_key=_dummy_pubkey,
        encryption_key=_dummy_pubkey,
        exchange_key=_dummy_pubkey,
    )
    midc_1.pack(cipher=0, address_algo=0)
    midc_1p = midc_1.packed
    midc_1r = MIDC.unpack(midc_1p)
    
    # MIDC actual address test.
    midc_2 = MIDC(
        signature_key=_dummy_pubkey,
        encryption_key=_dummy_pubkey,
        exchange_key=_dummy_pubkey,
    )
    midc_2.pack(cipher=0, address_algo=1)
    midc_2p = midc_2.packed
    midc_2r = MIDC.unpack(midc_2p)
    
    # Dummy payload and authors for MEOC objects
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    _dummy_author = midc_1.muid
    _rls_author = midc_2.muid
    
    # MEOC dummy address test.
    meoc_1 = MEOC(author=_dummy_author, payload=_dummy_payload)
    meoc_1.pack(cipher=0, address_algo=0)
    meoc_1.pack_signature(_dummy_signature)
    meoc_1p = meoc_1.packed
    meoc_1r = MEOC.unpack(meoc_1p)
    
    # MEOC actual address test.
    meoc_2 = MEOC(author=_rls_author, payload=_dummy_payload)
    meoc_2.pack(cipher=0, address_algo=1)
    meoc_2.pack_signature(_dummy_signature)
    meoc_2p = meoc_2.packed
    meoc_2r = MEOC.unpack(meoc_2p)
    
    # MOBS dummy address test.
    mobs_1 = MOBS(
        binder=_dummy_author, 
        target=_dummy_muid
    )
    mobs_1.pack(cipher=0, address_algo=0)
    mobs_1.pack_signature(_dummy_signature)
    mobs_1p = mobs_1.packed
    mobs_1r = MOBS.unpack(mobs_1p)
    
    # MOBS actual address test.
    mobs_2 = MOBS(
        binder=_rls_author, 
        target=_dummy_muid
    )
    mobs_2.pack(cipher=0, address_algo=1)
    mobs_2.pack_signature(_dummy_signature)
    mobs_2p = mobs_2.packed
    mobs_2r = MOBS.unpack(mobs_2p)
    
    # MOBD dummy address test.
    mobd_1 = MOBD(
        binder=_dummy_author, 
        targets=[_dummy_muid, _dummy_muid]
    )
    mobd_1.pack(cipher=0, address_algo=0)
    mobd_1.pack_signature(_dummy_signature)
    mobd_1p = mobd_1.packed
    mobd_1r = MOBD.unpack(mobd_1p)
    
    # MOBD actual address test.
    mobd_2 = MOBD(
        binder=_rls_author, 
        targets=[_dummy_muid, _dummy_muid]
    )
    mobd_2.pack(cipher=0, address_algo=1)
    mobd_2.pack_signature(_dummy_signature)
    mobd_2p = mobd_2.packed
    mobd_2r = MOBD.unpack(mobd_2p)
    
    # MOBD actual address test, with history
    mobd_3 = MOBD(
        binder=_rls_author, 
        targets=[_dummy_muid, _dummy_muid],
        dynamic_address=mobd_2.dynamic_address,
        history=[mobd_2.muid]
    )
    mobd_3.pack(cipher=0, address_algo=1)
    mobd_3.pack_signature(_dummy_signature)
    mobd_3p = mobd_3.packed
    mobd_3r = MOBD.unpack(mobd_3p)
    
    # MDXX dummy address test.
    mdxx_1 = MDXX(
        debinder=_dummy_author, 
        targets=[_dummy_muid]
    )
    mdxx_1.pack(cipher=0, address_algo=0)
    mdxx_1.pack_signature(_dummy_signature)
    mdxx_1p = mdxx_1.packed
    mdxx_1r = MDXX.unpack(mdxx_1p)
    
    # MDXX actual address test.
    mdxx_2 = MDXX(
        debinder=_rls_author, 
        targets=[_dummy_muid]
    )
    mdxx_2.pack(cipher=0, address_algo=1)
    mdxx_2.pack_signature(_dummy_signature)
    mdxx_2p = mdxx_2.packed
    mdxx_2r = MDXX.unpack(mdxx_2p)
    
    # MEAR dummy address test.
    mear_1 = MEAR(
        recipient=_dummy_author, 
        payload=_dummy_asym
    )
    mear_1.pack(cipher=0, address_algo=0)
    mear_1.pack_signature(_dummy_mac)
    mear_1p = mear_1.packed
    mear_1r = MEAR.unpack(mear_1p)
    
    # MEAR actual address test.
    mear_2 = MEAR(
        recipient=_rls_author, 
        payload=_dummy_asym
    )
    mear_2.pack(cipher=0, address_algo=1)
    mear_2.pack_signature(_dummy_mac)
    mear_2p = mear_2.packed
    mear_2r = MEAR.unpack(mear_2p)
    
    # Asym request testing
    asrq_1 = AsymRequest(
        author=_dummy_author,
        target=_dummy_muid, 
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
        target=_dummy_muid, 
        status=5
    )
    asak_1.pack()
    asak_1p = asak_1.packed
    asak_1r = AsymAck.unpack(asak_1p)
    
    # Asym ack testing
    asnk_1 = AsymNak(
        author=_dummy_author,
        target=_dummy_muid, 
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
    
    import IPython
    IPython.embed()