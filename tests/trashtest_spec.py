'''
Scratchpad for test-based development. Unit tests for _spec.py.

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
from golix import Ghid

# These are abnormal (don't use in production) inclusions
from golix._spec import _gidc, _geoc, _gobs, _gobd, _gdxx, _garq
from golix._spec import _asym_hand, _asym_ak, _asym_nk, _asym_else
from golix.utils import _dummy_signature
from golix.utils import _dummy_mac
from golix.utils import _dummy_asym
from golix.utils import _dummy_address
from golix.utils import _dummy_pubkey

# ###############################################
# Testing
# ###############################################

_dummy_ghid = Ghid(0, _dummy_address)
    
def run():
    # GIDC test parsers
    gidc_1 = {
        'magic': b'GIDC',
        'version': 2,
        'cipher': 0,
        'body': {
            'signature_key': _dummy_pubkey,
            'encryption_key': _dummy_pubkey,
            'exchange_key': _dummy_pubkey,
        },
        'ghid': _dummy_ghid,
        'signature': None
    }
    
    gidc_1p = _gidc.pack(gidc_1)
    gidc_1r = _gidc.unpack(gidc_1p)
    
    # GEOC test parsers
    geoc_1 = {
        'magic': b'GEOC',
        'version': 14,
        'cipher': 0,
        'body': {
            'author': _dummy_ghid,
            'payload': b'Hello world',
        },
        'ghid': _dummy_ghid,
        'signature': _dummy_signature
    }
    
    geoc_1p = _geoc.pack(geoc_1)
    geoc_1r = _geoc.unpack(geoc_1p)
    
    # GOBS test parsers
    gobs_1 = {
        'magic': b'GOBS',
        'version': 6,
        'cipher': 0,
        'body': {
            'binder': _dummy_ghid,
            'target': _dummy_ghid,
        },
        'ghid': _dummy_ghid,
        'signature': _dummy_signature
    }
    
    gobs_1p = _gobs.pack(gobs_1)
    gobs_1r = _gobs.unpack(gobs_1p)
    
    # GOBD test parsers
    gobd_1 = {
        'magic': b'GOBD',
        'version': 15,
        'cipher': 0,
        'body': {
            'binder': _dummy_ghid,
            'history': [],
            'target': _dummy_ghid,
        },
        'ghid_dynamic': _dummy_ghid,
        'ghid': _dummy_ghid,
        'signature': _dummy_signature
    }
    
    gobd_1p = _gobd.pack(gobd_1)
    gobd_1r = _gobd.unpack(gobd_1p)
    
    # GDXX test parsers
    gdxx_1 = {
        'magic': b'GDXX',
        'version': 9,
        'cipher': 0,
        'body': {
            'debinder': _dummy_ghid,
            'target': _dummy_ghid,
        },
        'ghid': _dummy_ghid,
        'signature': _dummy_signature
    }
    
    gdxx_1p = _gdxx.pack(gdxx_1)
    gdxx_1r = _gdxx.unpack(gdxx_1p)
    
    # MEPR test parsers
    garq_1 = {
        'magic': b'GARQ',
        'version': 12,
        'cipher': 0,
        'body': {
            'recipient': _dummy_ghid,
            'payload': _dummy_asym,
        },
        'ghid': _dummy_ghid,
        'signature': _dummy_mac
    }
    
    garq_1p = _garq.pack(garq_1)
    garq_1r = _garq.unpack(garq_1p)
    
    # Asymmetric payload blob tests.
    asym_hand_1 = {
        'author': _dummy_ghid,
        'magic': b'HS',
        'payload': {
            'target': _dummy_ghid,
            'secret': bytes(32)
        }
    }
    asym_hand_1p = _asym_hand.pack(asym_hand_1)
    asym_hand_1r = _asym_hand.unpack(asym_hand_1p)
    
    asym_ak_2 = {
        'author': _dummy_ghid,
        'magic': b'AK',
        'payload': {
            'target': _dummy_ghid,
            'status': 0
        }
    }
    asym_ak_2p = _asym_ak.pack(asym_ak_2)
    asym_ak_2r = _asym_ak.unpack(asym_ak_2p)
    
    asym_nk_3 = {
        'author': _dummy_ghid,
        'magic': b'NK',
        'payload': {
            'target': _dummy_ghid,
            'status': 0
        }
    }
    asym_nk_3p = _asym_nk.pack(asym_nk_3)
    asym_nk_3r = _asym_nk.unpack(asym_nk_3p)
    
    asym_else_4 = {
        'author': _dummy_ghid,
        'magic': b'\x00\x00',
        'payload': b'Hello world'
    }
    asym_else_4p = _asym_else.pack(asym_else_4)
    asym_else_4r = _asym_else.unpack(asym_else_4p)
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()