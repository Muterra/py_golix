'''
Spec-based definition of Muse objects. It sure ain't beautiful, but it's 
getting the job done for now.

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

from smartyparse import ParseHelper
from smartyparse import SmartyParser
from smartyparse import ListyParser
from smartyparse import parsers
from smartyparse import references

# ----------------------------------------------------------------------
# Hash algo identifier / length block

_dummy_address = b'[[ Start hash -- ' + bytes(32) + b' -- End hash ]]'

_hash_algo_lookup = {
    0: ParseHelper(parsers.Literal(_dummy_address))
    1: ParseHelper(parsers.Blob(length=64))
}

# ----------------------------------------------------------------------
# MUID parsing block

def generate_muid_parser():
    muid_parser = SmartyParser()
    muid_parser['algo'] = ParseHelper(parsers.Int8(signed=False))
    muid_parser['address'] = None

    @references(muid_parser)
    def _muid_format(self, algo):
        try:
            self['address'] = _hash_algo_lookup[algo]
        except KeyError as e:
            raise ValueError('Improper hash algorithm declaration.') from e
            
    muid_parser['algo'].register_callback('prepack', _muid_format)
    parent['algo'].register_callback('postunpack', _muid_format)
    
    return muid_parser

# ----------------------------------------------------------------------
# Cipher length lookup block

cipher_length_lookup = {
    0: {
        'key': 32,
        'sig': 512,
        'mac': 64,
        'asym': 512,
        'nonce': 16
    },
    1: {
        'key': 32,
        'sig': 512,
        'mac': 64,
        'asym': 512,
        'nonce': 16
    },
    2: {
        'key': 64,
        'sig': 512,
        'mac': 64,
        'asym': 512,
        'nonce': 0
    }
}

_dummy_signature = b'[[ Start signature -- ' + bytes(470) +  b' -- End signature ]]'

_signature_parsers = {}
_signature_parsers[0] = ParseHelper(parsers.Literal(_dummy_signature))
_signature_parsers[1] = ParseHelper(parsers.Blob(length=512))
_signature_parsers[2] = ParseHelper(parsers.Blob(length=512))

# def generate_crypto_parser(cipher, component):
#     try:
#         cs_dec = cipher_length_lookup[cipher]
#     except KeyError as e:
#         raise ValueError('Improper cipher suite declaration.') from e
#     try:
#         length = cs_dev[component]
#     except KeyError as e:
#         raise KeyError('Bad crypto component selection.') from e
#     return ParseHelper(parsers.Blob(length=length))

# ----------------------------------------------------------------------
# Use this whenever a MUID list is required

_muidlist = ListyParser(parsers=[generate_muid_parser()])

# ----------------------------------------------------------------------
# Generalized object dispatcher

def _gen_dispatch(header, lookup):
    @references(header)
    def _dispatch_obj(self, version):
        try:
            self['body'] = lookup[version]
        except KeyError:
            raise parsers.ParseError('No matching version number available.')
    return _dispatch_obj

# ----------------------------------------------------------------------
# MEOC format blocks

_meoc = SmartyParser()
_meoc['magic'] = ParseHelper(parsers.Literal(b'MEOC'))
_meoc['version'] = ParseHelper(parsers.Int32(signed=False))
_meoc['cipher'] = ParseHelper(parsers.Int8(signed=False))
_meoc['body'] = None
_meoc['muid'] = generate_muid_parser()
_meoc['signature'] = None

_meoc_lookup = {}
_meoc_lookup[14] = SmartyParser()
_meoc_lookup[14]['author'] = generate_muid_parser()
_meoc_lookup[14]['len_payload'] = ParseHelper(parsers.Int64(signed=False))
_meoc_lookup[14]['payload'] = ParseHelper(parsers.Blob())
_meoc_lookup[14].link_length('payload', 'len_payload')
    
_meoc['version'].register_callback('prepack', _gen_dispatch(_meoc, _meoc_lookup))
_meoc['version'].register_callback('postunpack', _gen_dispatch(_meoc, _meoc_lookup))
_meoc['cipher'].register_callback('prepack', _gen_dispatch(_meoc, _signature_parsers))
_meoc['cipher'].register_callback('postunpack', _gen_dispatch(_meoc, _signature_parsers))

# ----------------------------------------------------------------------
# MOBS format blocks

_mobs = SmartyParser()
_mobs['magic'] = ParseHelper(parsers.Literal(b'MOBS'))
_mobs['version'] = ParseHelper(parsers.Int32(signed=False))
_mobs['cipher'] = ParseHelper(parsers.Int8(signed=False))
_mobs['body'] = None
_mobs['muid'] = generate_muid_parser()
_mobs['signature'] = None

_mobs_lookup = {}
_mobs_lookup[6] = SmartyParser()
_mobs_lookup[6]['binder'] = generate_muid_parser()
_mobs_lookup[6]['target'] = generate_muid_parser()
    
_mobs['version'].register_callback('prepack', _gen_dispatch(_mobs, _mobs_lookup))
_mobs['version'].register_callback('postunpack', _gen_dispatch(_mobs, _mobs_lookup))
_mobs['cipher'].register_callback('prepack', _gen_dispatch(_mobs, _signature_parsers))
_mobs['cipher'].register_callback('postunpack', _gen_dispatch(_mobs, _signature_parsers))

# ----------------------------------------------------------------------
# MOBD format blocks

_mobd = SmartyParser()
_mobd['magic'] = ParseHelper(parsers.Literal(b'MOBD'))
_mobd['version'] = ParseHelper(parsers.Int32(signed=False))
_mobd['cipher'] = ParseHelper(parsers.Int8(signed=False))
_mobd['body'] = None
_mobd['muid'] = generate_muid_parser()
_mobd['signature'] = None

_mobd_lookup = {}
_mobd_lookup[13] = SmartyParser()
_mobd_lookup[13]['binder'] = generate_muid_parser()
_mobd_lookup[13]['history_length'] = ParseHelper(parsers.Int16(signed=False))
_mobd_lookup[13]['history'] = _muidlist
_mobd_lookup[13]['targets_length'] = ParseHelper(parsers.Int32(signed=False))
_mobd_lookup[13]['targets'] = _muidlist
_mobd_lookup[13]['muid_dynamic'] = generate_muid_parser()
    
_mobd['version'].register_callback('prepack', _gen_dispatch(_mobd, _mobd_lookup))
_mobd['version'].register_callback('postunpack', _gen_dispatch(_mobd, _mobd_lookup))
_mobd['cipher'].register_callback('prepack', _gen_dispatch(_mobd, _signature_parsers))
_mobd['cipher'].register_callback('postunpack', _gen_dispatch(_mobd, _signature_parsers))