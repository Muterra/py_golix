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

_dummy_address = b'[[ Start hash ' + (b'-' * 38) + b' End hash ]]'

_hash_algo_lookup = {
    0: ParseHelper(parsers.Literal(_dummy_address)),
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
            print(algo)
            raise ValueError('Improper hash algorithm declaration.') from e
            
    muid_parser['algo'].register_callback('prepack', _muid_format)
    muid_parser['algo'].register_callback('postunpack', _muid_format)
    
    return muid_parser

# ----------------------------------------------------------------------
# Generalized object dispatcher

def _gen_dispatch(header, lookup, key):
    @references(header)
    def _dispatch_obj(self, version, key=key):
        try:
            self[key] = lookup[version]
        except KeyError:
            raise parsers.ParseError('No matching version number available.')
    return _dispatch_obj
    
def _callback_multi(*funcs):
    def generated_callback(value):
        for f in funcs:
            f(value)
    return generated_callback

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

_dummy_signature = b'[[ Start signature ' + (b'-' * 476) + b' End signature ]]'

_signature_parsers = {}
_signature_parsers[0] = ParseHelper(parsers.Literal(_dummy_signature))
_signature_parsers[1] = ParseHelper(parsers.Blob(length=512))
_signature_parsers[2] = ParseHelper(parsers.Blob(length=512))

_dummy_mac = b'[[ Start MAC ' + (b'-' * 40) + b' End MAC ]]'

_mac_parsers = {}
_mac_parsers[0] = ParseHelper(parsers.Literal(_dummy_mac))
_mac_parsers[1] = ParseHelper(parsers.Blob(length=64))
_mac_parsers[2] = ParseHelper(parsers.Blob(length=64))

_dummy_asym = b'[[ Start asymmetric payload ' + (b'-' * 458) + b' End asymmetric payload ]]'

_asym_parsers = {}
_asym_parsers[0] = ParseHelper(parsers.Literal(_dummy_asym))
_asym_parsers[1] = ParseHelper(parsers.Blob(length=512))
_asym_parsers[2] = ParseHelper(parsers.Blob(length=512))

# ----------------------------------------------------------------------
# Use this whenever a MUID list is required

_muidlist = ListyParser(parsers=[generate_muid_parser()])

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
    
_meoc['version'].register_callback('prepack', _gen_dispatch(_meoc, _meoc_lookup, 'body'))
_meoc['version'].register_callback('postunpack', _gen_dispatch(_meoc, _meoc_lookup, 'body'))
_meoc['cipher'].register_callback('prepack', _gen_dispatch(_meoc, _signature_parsers, 'signature'))
_meoc['cipher'].register_callback('postunpack', _gen_dispatch(_meoc, _signature_parsers, 'signature'))

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
    
_mobs['version'].register_callback('prepack', _gen_dispatch(_mobs, _mobs_lookup, 'body'))
_mobs['version'].register_callback('postunpack', _gen_dispatch(_mobs, _mobs_lookup, 'body'))
_mobs['cipher'].register_callback('prepack', _gen_dispatch(_mobs, _signature_parsers, 'signature'))
_mobs['cipher'].register_callback('postunpack', _gen_dispatch(_mobs, _signature_parsers, 'signature'))

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
_mobd_lookup[13].link_length('history', 'history_length')
_mobd_lookup[13].link_length('targets', 'targets_length')
    
_mobd['version'].register_callback('prepack', _gen_dispatch(_mobd, _mobd_lookup, 'body'))
_mobd['version'].register_callback('postunpack', _gen_dispatch(_mobd, _mobd_lookup, 'body'))
_mobd['cipher'].register_callback('prepack', _gen_dispatch(_mobd, _signature_parsers, 'signature'))
_mobd['cipher'].register_callback('postunpack', _gen_dispatch(_mobd, _signature_parsers, 'signature'))

# ----------------------------------------------------------------------
# MDXX format blocks

_mdxx = SmartyParser()
_mdxx['magic'] = ParseHelper(parsers.Literal(b'MDXX'))
_mdxx['version'] = ParseHelper(parsers.Int32(signed=False))
_mdxx['cipher'] = ParseHelper(parsers.Int8(signed=False))
_mdxx['body'] = None
_mdxx['muid'] = generate_muid_parser()
_mdxx['signature'] = None

_mdxx_lookup = {}
_mdxx_lookup[7] = SmartyParser()
_mdxx_lookup[7]['debinder'] = generate_muid_parser()
_mdxx_lookup[7]['targets_length'] = ParseHelper(parsers.Int32(signed=False))
_mdxx_lookup[7]['targets'] = _muidlist
_mdxx_lookup[7].link_length('targets', 'targets_length')
    
_mdxx['version'].register_callback('prepack', _gen_dispatch(_mdxx, _mdxx_lookup, 'body'))
_mdxx['version'].register_callback('postunpack', _gen_dispatch(_mdxx, _mdxx_lookup, 'body'))
_mdxx['cipher'].register_callback('prepack', _gen_dispatch(_mdxx, _signature_parsers, 'signature'))
_mdxx['cipher'].register_callback('postunpack', _gen_dispatch(_mdxx, _signature_parsers, 'signature'))

# ----------------------------------------------------------------------
# MEAR format blocks

_mear = SmartyParser()
_mear['magic'] = ParseHelper(parsers.Literal(b'MEAR'))
_mear['version'] = ParseHelper(parsers.Int32(signed=False))
_mear['cipher'] = ParseHelper(parsers.Int8(signed=False))
_mear['body'] = None
_mear['muid'] = generate_muid_parser()
_mear['mac'] = None

_mear_lookup = {}
_mear_lookup[12] = SmartyParser()
_mear_lookup[12]['recipient'] = generate_muid_parser()
_mear_lookup[12]['payload'] = None
    
# This should keep working even with the addition of new version numbers
def _generate_asym_update(container):
    def _update_asym(cipher):
        container['body']['payload'] = _asym_parsers[cipher]
    return _update_asym

_mear_cipher_update = _callback_multi(
    _gen_dispatch(_mear, _mac_parsers, 'mac'), 
    _generate_asym_update(_mear))
_mear['version'].register_callback('prepack', _gen_dispatch(_mear, _mear_lookup, 'body'))
_mear['version'].register_callback('postunpack', _gen_dispatch(_mear, _mear_lookup, 'body'))
_mear['cipher'].register_callback('prepack', _mear_cipher_update)
_mear['cipher'].register_callback('postunpack', _mear_cipher_update)

# ----------------------------------------------------------------------
# Asymmetric payload format blocks

_asym_pr_payload = SmartyParser()
_asym_pr_payload['target'] = generate_muid_parser()
_asym_pr_payload['key_length'] = ParseHelper(parsers.Int8(signed=False))
_asym_pr_payload['key'] = ParseHelper(parsers.Blob())
_asym_pr_payload.link_length('key', 'key_length')

_asym_ak_payload = SmartyParser()
_asym_ak_payload['target'] = generate_muid_parser()
_asym_ak_payload['status'] = ParseHelper(parsers.Int32(signed=False))

_asym_nk_payload = SmartyParser()
_asym_nk_payload['target'] = generate_muid_parser()
_asym_nk_payload['status'] = ParseHelper(parsers.Int32(signed=False))

_asym_pr = SmartyParser()
_asym_pr['author'] = generate_muid_parser()
_asym_pr['id'] = ParseHelper(parsers.Literal(b'PR'))
_asym_pr['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_pr['payload'] = _asym_pr_payload
_asym_pr.link_length('payload', 'payload_length')

_asym_ak = SmartyParser()
_asym_ak['author'] = generate_muid_parser()
_asym_ak['id'] = ParseHelper(parsers.Literal(b'AK'))
_asym_ak['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_ak['payload'] = _asym_ak_payload
_asym_ak.link_length('payload', 'payload_length')

_asym_nk = SmartyParser()
_asym_nk['author'] = generate_muid_parser()
_asym_nk['id'] = ParseHelper(parsers.Literal(b'NK'))
_asym_nk['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_nk['payload'] = _asym_nk_payload
_asym_nk.link_length('payload', 'payload_length')

_asym_else = SmartyParser()
_asym_else['author'] = generate_muid_parser()
_asym_else['id'] = ParseHelper(parsers.Literal(b'\x00\x00'))
_asym_else['payload_length'] = ParseHelper(parsers.Int16(signed=False))
_asym_else['payload'] = ParseHelper(parsers.Blob())
_asym_else.link_length('payload', 'payload_length')