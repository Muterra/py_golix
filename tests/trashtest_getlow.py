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

from mupy.utils import _dummy_signature
from mupy.utils import _dummy_mac
from mupy.utils import _dummy_asym
from mupy.utils import _dummy_address
from mupy.utils import _dummy_pubkey
from mupy.utils import _dummy_muid

# These are soon-to-be-removed abnormal imports
from mupy._spec import _midc, _meoc, _mobs, _mobd, _mdxx, _mear
from mupy._spec import _asym_pr, _asym_ak, _asym_nk, _asym_else

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
    
    import IPython
    IPython.embed()