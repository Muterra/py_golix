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
from smartyparse import parsers

# ----------------------------------------------------------------------
# Hash algo identifier / length block

hash_length_lookup = {
    1: 64
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
            self['address'] = ParseHelper(Blob(length=hash_length_lookup[algo]))
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

def generate_crypto_parser(cipher, component):
    try:
        cs_dec = cipher_length_lookup[cipher]
    except KeyError as e:
        raise ValueError('Improper cipher suite declaration.') from e
    try:
        length = cs_dev[component]
    except KeyError as e:
        raise KeyError('Bad crypto component selection.') from e
    return ParseHelper(parsers.Blob(length=length))

# ----------------------------------------------------------------------
# MEOC format blocks

_meoc14 = SmartyParser()
_meoc14['author'] = generate_muid_parser()
_meoc14['len_payload'] = parsers.Int64(signed=False)
_meoc14['payload'] = parsers.Blob()
_meoc14['muid'] = generate_muid_parser()
_meoc14['signature'] = None
_meoc14.link_length('payload', 'len_payload')

# ----------------------------------------------------------------------
# MOBS format blocks

_mobs6 = SmartyParser()
_mobs6['binder'] = generate_muid_parser()
_mobs6['target'] = generate_muid_parser()
_mobs6['muid'] = generate_muid_parser()
_mobs6['signature'] = None

# ----------------------------------------------------------------------
# Lookup block

format_lookup = {
    b'MEOC': {
        14: _meoc14
    },
    b'MOBS': {
        6: _mobs6
    },
}

# ----------------------------------------------------------------------
# Parser generation block

def generate_muse_parser(magic, cipher, version):
    try:
        obj_lookup = format_lookup[magic]
    except KeyError as e:
        raise ValueError('Improper magic number.') from e
    try:
        obj = obj_lookup[version]
    except KeyError as e:
        raise ValueError('Improper Muse object version.') from e
        
    if 'signature' in obj:
        obj['signature'] = generate_crypto_parser(cipher, 'sig')
    
    return obj