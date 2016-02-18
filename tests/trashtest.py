'''
Scratchpad for test-based development.

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

from Crypto.PublicKey import RSA

from mupy._spec import _dummy_signature
from mupy._spec import _dummy_mac
from mupy._spec import _dummy_asym
from mupy._spec import _dummy_address

# These are soon-to-be-removed abnormal imports
from mupy._spec import _meoc, _mobs, _mobd, _mdxx, _mear, _asym_pr, _asym_ak, _asym_nk, _asym_else

# ###############################################
# Testing
# ###############################################

_dummy_muid = Muid(0, _dummy_address)

_test_sig_key = RSA.generate(4096)
_test_sec_key = bytes(32)
                
if __name__ == '__main__':
    # MEOC dummy test.
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    meoc_1 = MEOC(author=_dummy_muid, payload=_dummy_payload)
    meoc_1.pack(cipher=0, address_algo=0)
    meoc_1.pack_signature(_dummy_signature)
    meoc_1p = meoc_1.packed
    
    # meoc_1r = MEOC.unpack(meoc_1p)
    
    # MEOC actual test.
    _dummy_payload = b'[[ PLACEHOLDER ENCRYPTED SYMMETRIC MESSAGE. Hello, world? ]]'
    meoc_2 = MEOC(author=_dummy_muid, payload=_dummy_payload)
    meoc_2.pack(cipher=0, address_algo=1)
    meoc_2.pack_signature(_dummy_signature)
    meoc_2p = meoc_2.packed
    
    # meoc_2r = MEOC.unpack(meoc_2p)
    
    # # MEOC dummy test object
    # meoc_1 = MEOC(author=_dummy_muid, plaintext=b'Hello world')
    # meoc_1p = meoc_1.finalize(private_key=None, secret_key=None, cipher=0, address_algo=0)
    # # Need to hammer out how to generate a secret from here.
    
    # meoc_1r = MEOC.unpack(meoc_1p)
    # # This would be the step where you get the public key for the author
    # meoc_1r.verify(public_key=None)
    # meoc_1r.decrypt(secret_key=None)
    # # And as a full test
    # meoc_1rr = MEOC.load(public_key=None, secret_key=None, data=meoc_1p)
    
    # # MEOC hashed test object
    # meoc_2 = MEOC(author=_dummy_muid, plaintext=b'Hello worlddddddddd')
    # meoc_2p = meoc_2.finalize(private_key=None, secret_key=None, cipher=0, address_algo=1)
    
    # meoc_2r = MEOC.unpack(meoc_2p)
    # # This would be the step where you get the public key for the author
    # meoc_2r.verify(public_key=None)
    # meoc_2r.decrypt(secret_key=None)
    # # And as a full test
    # meoc_2rr = MEOC.load(public_key=None, secret_key=None, data=meoc_2p)
    
    # MOBS test parsers
    mobs_1 = {
        'magic': b'MOBS',
        'version': 6,
        'cipher': 0,
        'body': {
            'binder': _dummy_muid,
            'target': _dummy_muid,
        },
        'muid': _dummy_muid,
        'signature': _dummy_signature
    }
    
    mobs_1p = _mobs.pack(mobs_1)
    mobs_1r = _mobs.unpack(mobs_1p)
    
    # MOBD test parsers
    mobd_1 = {
        'magic': b'MOBD',
        'version': 13,
        'cipher': 0,
        'body': {
            'binder': _dummy_muid,
            'history': [],
            'targets': [_dummy_muid, _dummy_muid],
            'muid_dynamic': _dummy_muid,
        },
        'muid': _dummy_muid,
        'signature': _dummy_signature
    }
    
    mobd_1p = _mobd.pack(mobd_1)
    mobd_1r = _mobd.unpack(mobd_1p)
    
    # MDXX test parsers
    mdxx_1 = {
        'magic': b'MDXX',
        'version': 7,
        'cipher': 0,
        'body': {
            'debinder': _dummy_muid,
            'targets': [_dummy_muid, _dummy_muid],
        },
        'muid': _dummy_muid,
        'signature': _dummy_signature
    }
    
    mdxx_1p = _mdxx.pack(mdxx_1)
    mdxx_1r = _mdxx.unpack(mdxx_1p)
    
    # MEPR test parsers
    mear_1 = {
        'magic': b'MEAR',
        'version': 12,
        'cipher': 0,
        'body': {
            'recipient': _dummy_muid,
            'payload': _dummy_asym,
        },
        'muid': _dummy_muid,
        'signature': _dummy_mac
    }
    
    mear_1p = _mear.pack(mear_1)
    mear_1r = _mear.unpack(mear_1p)
    
    # Asymmetric payload blob tests.
    asym_pr_1 = {
        'author': _dummy_muid,
        'id': b'PR',
        'payload': {
            'target': _dummy_muid,
            'key': bytes(32)
        }
    }
    asym_pr_1p = _asym_pr.pack(asym_pr_1)
    asym_pr_1r = _asym_pr.unpack(asym_pr_1p)
    
    asym_ak_2 = {
        'author': _dummy_muid,
        'id': b'AK',
        'payload': {
            'target': _dummy_muid,
            'status': 0
        }
    }
    asym_ak_2p = _asym_ak.pack(asym_ak_2)
    asym_ak_2r = _asym_ak.unpack(asym_ak_2p)
    
    asym_nk_3 = {
        'author': _dummy_muid,
        'id': b'NK',
        'payload': {
            'target': _dummy_muid,
            'status': 0
        }
    }
    asym_nk_3p = _asym_nk.pack(asym_nk_3)
    asym_nk_3r = _asym_nk.unpack(asym_nk_3p)
    
    asym_else_4 = {
        'author': _dummy_muid,
        'id': b'\x00\x00',
        'payload': b'Hello world'
    }
    asym_else_4p = _asym_else.pack(asym_else_4)
    asym_else_4r = _asym_else.unpack(asym_else_4p)
    
    import IPython
    IPython.embed()