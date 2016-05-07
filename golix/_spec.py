'''
Spec-based definition of Golix objects. It sure ain't beautiful, but it's 
getting the job done for now.

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

from smartyparse import ParseHelper
from smartyparse import SmartyParser
from smartyparse import ListyParser
from smartyparse import parsers
from smartyparse import references

from .utils import Ghid

from .utils import _gen_dispatch
from .utils import _gen_body_update
from .utils import _callback_multi

from .utils import _dummy_asym
from .utils import _dummy_mac
from .utils import _dummy_signature
from .utils import _dummy_address
from .utils import _dummy_ghid
from .utils import _dummy_pubkey
from .utils import generate_ghid_parser
from .utils import generate_ghidlist_parser

# ----------------------------------------------------------------------
# Crypto parsers definition block

_signature_parsers = {}
_signature_parsers[0] = ParseHelper(parsers.Literal(_dummy_signature, verify=False))
_signature_parsers[1] = ParseHelper(parsers.Blob(length=512))
_signature_parsers[2] = ParseHelper(parsers.Blob(length=512))

_mac_parsers = {}
_mac_parsers[0] = ParseHelper(parsers.Literal(_dummy_mac, verify=False))
_mac_parsers[1] = ParseHelper(parsers.Blob(length=64))
_mac_parsers[2] = ParseHelper(parsers.Blob(length=64))

_asym_parsers = {}
_asym_parsers[0] = ParseHelper(parsers.Literal(_dummy_asym, verify=False))
_asym_parsers[1] = ParseHelper(parsers.Blob(length=512))
_asym_parsers[2] = ParseHelper(parsers.Blob(length=512))

_pubkey_parsers_sig = {}
_pubkey_parsers_sig[0] = ParseHelper(parsers.Literal(_dummy_pubkey, verify=False))
_pubkey_parsers_sig[1] = ParseHelper(parsers.Blob(length=512))
_pubkey_parsers_sig[2] = ParseHelper(parsers.Blob(length=512))

_pubkey_parsers_encrypt = {}
_pubkey_parsers_encrypt[0] = ParseHelper(parsers.Literal(_dummy_pubkey, verify=False))
_pubkey_parsers_encrypt[1] = ParseHelper(parsers.Blob(length=512))
_pubkey_parsers_encrypt[2] = ParseHelper(parsers.Blob(length=512))

_pubkey_parsers_exchange = {}
_pubkey_parsers_exchange[0] = ParseHelper(parsers.Literal(_dummy_pubkey, verify=False))
_pubkey_parsers_exchange[1] = ParseHelper(parsers.Blob(length=32))
_pubkey_parsers_exchange[2] = ParseHelper(parsers.Blob(length=32))

# ----------------------------------------------------------------------
# Use this whenever a GHID list is required

_ghidlist = generate_ghidlist_parser()

# ----------------------------------------------------------------------
# GIDC format blocks

_gidc = SmartyParser()
_gidc['magic'] = ParseHelper(parsers.Literal(b'GIDC'))
_gidc['version'] = ParseHelper(parsers.Int32(signed=False))
_gidc['cipher'] = ParseHelper(parsers.Int8(signed=False))
_gidc['body'] = None
_gidc['ghid'] = generate_ghid_parser()
_gidc['signature'] = ParseHelper(parsers.Null())

_gidc_lookup = {}
_gidc_lookup[2] = SmartyParser()
_gidc_lookup[2]['signature_key'] = None
_gidc_lookup[2]['encryption_key'] = None
_gidc_lookup[2]['exchange_key'] = None

_gidc_cipher_update = _callback_multi(
    _gen_body_update(_gidc, _pubkey_parsers_sig, 'signature_key'),
    _gen_body_update(_gidc, _pubkey_parsers_encrypt, 'encryption_key'),
    _gen_body_update(_gidc, _pubkey_parsers_exchange, 'exchange_key')
)

_gidc['version'].register_callback('prepack', _gen_dispatch(_gidc, _gidc_lookup, 'body'))
_gidc['version'].register_callback('postunpack', _gen_dispatch(_gidc, _gidc_lookup, 'body'))
_gidc['cipher'].register_callback('prepack', _gidc_cipher_update)
_gidc['cipher'].register_callback('postunpack', _gidc_cipher_update)

_gidc.latest = max(list(_gidc_lookup))
_gidc.versions = set(_gidc_lookup)

# ----------------------------------------------------------------------
# GEOC format blocks

_geoc = SmartyParser()
_geoc['magic'] = ParseHelper(parsers.Literal(b'GEOC'))
_geoc['version'] = ParseHelper(parsers.Int32(signed=False))
_geoc['cipher'] = ParseHelper(parsers.Int8(signed=False))
_geoc['body'] = None
_geoc['ghid'] = generate_ghid_parser()
_geoc['signature'] = None

_geoc_lookup = {}
_geoc_lookup[14] = SmartyParser()
_geoc_lookup[14]['author'] = generate_ghid_parser()
_geoc_lookup[14]['len_payload'] = ParseHelper(parsers.Int64(signed=False))
_geoc_lookup[14]['payload'] = ParseHelper(parsers.Blob())
_geoc_lookup[14].link_length('payload', 'len_payload')
    
_geoc['version'].register_callback('prepack', _gen_dispatch(_geoc, _geoc_lookup, 'body'))
_geoc['version'].register_callback('postunpack', _gen_dispatch(_geoc, _geoc_lookup, 'body'))
_geoc['cipher'].register_callback('prepack', _gen_dispatch(_geoc, _signature_parsers, 'signature'))
_geoc['cipher'].register_callback('postunpack', _gen_dispatch(_geoc, _signature_parsers, 'signature'))

_geoc.latest = max(list(_geoc_lookup))
_geoc.versions = set(_geoc_lookup)

# ----------------------------------------------------------------------
# GOBS format blocks

_gobs = SmartyParser()
_gobs['magic'] = ParseHelper(parsers.Literal(b'GOBS'))
_gobs['version'] = ParseHelper(parsers.Int32(signed=False))
_gobs['cipher'] = ParseHelper(parsers.Int8(signed=False))
_gobs['body'] = None
_gobs['ghid'] = generate_ghid_parser()
_gobs['signature'] = None

_gobs_lookup = {}
_gobs_lookup[6] = SmartyParser()
_gobs_lookup[6]['binder'] = generate_ghid_parser()
_gobs_lookup[6]['target'] = generate_ghid_parser()
    
_gobs['version'].register_callback('prepack', _gen_dispatch(_gobs, _gobs_lookup, 'body'))
_gobs['version'].register_callback('postunpack', _gen_dispatch(_gobs, _gobs_lookup, 'body'))
_gobs['cipher'].register_callback('prepack', _gen_dispatch(_gobs, _signature_parsers, 'signature'))
_gobs['cipher'].register_callback('postunpack', _gen_dispatch(_gobs, _signature_parsers, 'signature'))

_gobs.latest = max(list(_gobs_lookup))
_gobs.versions = set(_gobs_lookup)

# ----------------------------------------------------------------------
# GOBD format blocks

_gobd = SmartyParser()
_gobd['magic'] = ParseHelper(parsers.Literal(b'GOBD'))
_gobd['version'] = ParseHelper(parsers.Int32(signed=False))
_gobd['cipher'] = ParseHelper(parsers.Int8(signed=False))
_gobd['body'] = None
_gobd['ghid_dynamic'] = generate_ghid_parser()
_gobd['ghid'] = generate_ghid_parser()
_gobd['signature'] = None

_gobd_lookup = {}
_gobd_lookup[15] = SmartyParser()
_gobd_lookup[15]['binder'] = generate_ghid_parser()
_gobd_lookup[15]['history_length'] = ParseHelper(parsers.Int16(signed=False))
_gobd_lookup[15]['history'] = _ghidlist
_gobd_lookup[15]['target'] = generate_ghid_parser()
_gobd_lookup[15].link_length('history', 'history_length')
    
_gobd['version'].register_callback('prepack', _gen_dispatch(_gobd, _gobd_lookup, 'body'))
_gobd['version'].register_callback('postunpack', _gen_dispatch(_gobd, _gobd_lookup, 'body'))
_gobd['cipher'].register_callback('prepack', _gen_dispatch(_gobd, _signature_parsers, 'signature'))
_gobd['cipher'].register_callback('postunpack', _gen_dispatch(_gobd, _signature_parsers, 'signature'))

_gobd.latest = max(list(_gobd_lookup))
_gobd.versions = set(_gobd_lookup)

# ----------------------------------------------------------------------
# GDXX format blocks

_gdxx = SmartyParser()
_gdxx['magic'] = ParseHelper(parsers.Literal(b'GDXX'))
_gdxx['version'] = ParseHelper(parsers.Int32(signed=False))
_gdxx['cipher'] = ParseHelper(parsers.Int8(signed=False))
_gdxx['body'] = None
_gdxx['ghid'] = generate_ghid_parser()
_gdxx['signature'] = None

_gdxx_lookup = {}
_gdxx_lookup[9] = SmartyParser()
_gdxx_lookup[9]['debinder'] = generate_ghid_parser()
_gdxx_lookup[9]['target'] = generate_ghid_parser()
    
_gdxx['version'].register_callback('prepack', _gen_dispatch(_gdxx, _gdxx_lookup, 'body'))
_gdxx['version'].register_callback('postunpack', _gen_dispatch(_gdxx, _gdxx_lookup, 'body'))
_gdxx['cipher'].register_callback('prepack', _gen_dispatch(_gdxx, _signature_parsers, 'signature'))
_gdxx['cipher'].register_callback('postunpack', _gen_dispatch(_gdxx, _signature_parsers, 'signature'))

_gdxx.latest = max(list(_gdxx_lookup))
_gdxx.versions = set(_gdxx_lookup)

# ----------------------------------------------------------------------
# GARQ format blocks

_garq = SmartyParser()
_garq['magic'] = ParseHelper(parsers.Literal(b'GARQ'))
_garq['version'] = ParseHelper(parsers.Int32(signed=False))
_garq['cipher'] = ParseHelper(parsers.Int8(signed=False))
_garq['body'] = None
_garq['ghid'] = generate_ghid_parser()
_garq['signature'] = None

_garq_lookup = {}
_garq_lookup[12] = SmartyParser()
_garq_lookup[12]['recipient'] = generate_ghid_parser()
_garq_lookup[12]['payload'] = None

_garq_cipher_update = _callback_multi(
    _gen_dispatch(_garq, _mac_parsers, 'signature'), 
    _gen_body_update(_garq, _asym_parsers, 'payload')
)
_garq['version'].register_callback('prepack', _gen_dispatch(_garq, _garq_lookup, 'body'))
_garq['version'].register_callback('postunpack', _gen_dispatch(_garq, _garq_lookup, 'body'))
_garq['cipher'].register_callback('prepack', _garq_cipher_update)
_garq['cipher'].register_callback('postunpack', _garq_cipher_update)

_garq.latest = max(list(_garq_lookup))
_garq.versions = set(_garq_lookup)

# ----------------------------------------------------------------------
# Asymmetric payload format blocks

_asym_hand_payload = SmartyParser()
_asym_hand_payload['target'] = generate_ghid_parser()
_asym_hand_payload['secret_length'] = ParseHelper(parsers.Int8(signed=False))
_asym_hand_payload['secret'] = ParseHelper(parsers.Blob())
_asym_hand_payload.link_length('secret', 'secret_length')

_asym_ak_payload = SmartyParser()
_asym_ak_payload['target'] = generate_ghid_parser()
_asym_ak_payload['status'] = ParseHelper(parsers.Int32(signed=False))

_asym_nk_payload = SmartyParser()
_asym_nk_payload['target'] = generate_ghid_parser()
_asym_nk_payload['status'] = ParseHelper(parsers.Int32(signed=False))

_asym_hand = SmartyParser()
_asym_hand['author'] = generate_ghid_parser()
_asym_hand['magic'] = ParseHelper(parsers.Literal(b'HS'))
_asym_hand['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_hand['payload'] = _asym_hand_payload
_asym_hand.link_length('payload', 'payload_length')

_asym_ak = SmartyParser()
_asym_ak['author'] = generate_ghid_parser()
_asym_ak['magic'] = ParseHelper(parsers.Literal(b'AK'))
_asym_ak['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_ak['payload'] = _asym_ak_payload
_asym_ak.link_length('payload', 'payload_length')

_asym_nk = SmartyParser()
_asym_nk['author'] = generate_ghid_parser()
_asym_nk['magic'] = ParseHelper(parsers.Literal(b'NK'))
_asym_nk['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_nk['payload'] = _asym_nk_payload
_asym_nk.link_length('payload', 'payload_length')

_asym_else = SmartyParser()
_asym_else['author'] = generate_ghid_parser()
_asym_else['magic'] = ParseHelper(parsers.Literal(b'\x00\x00'))
_asym_else['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_else['payload'] = ParseHelper(parsers.Blob())
_asym_else.link_length('payload', 'payload_length')