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

from .utils import Muid
from .utils import _dummy_asym
from .utils import _dummy_mac
from .utils import _dummy_signature
from .utils import _dummy_address
from .utils import _dummy_muid
from .utils import _dummy_pubkey

# ----------------------------------------------------------------------
# Hash algo identifier / length block

_hash_algo_lookup = {
    0: ParseHelper(parsers.Literal(_dummy_address, verify=False)),
    1: ParseHelper(parsers.Blob(length=64))
}

# ----------------------------------------------------------------------
# MUID parsing block

def _muid_transform(unpacked_spo):
    ''' Transforms an unpacked SmartyParseObject into a .utils.Muid.
    If using algo zero, also eliminates the address and replaces with
    None.
    '''
    muid = Muid(algo=unpacked_spo['algo'], address=unpacked_spo['address'])
    
    if muid.algo == 0:
        muid.address = None
        
    return muid

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
    
    # Don't forget to transform the object back to a utils.Muid
    muid_parser.register_callback('postunpack', _muid_transform, modify=True)
    
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
    
# This should keep working even with the addition of new version numbers
def _gen_body_update(header, lookup, key):
    @references(header)
    def _update_body(self, parsed, key=key):
        try:
            self['body'][key] = lookup[parsed]
        except KeyError:
            raise parsers.ParseError('No matching object body key available.')
    return _update_body
    
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
# Use this whenever a MUID list is required

_muidlist = ListyParser(parsers=[generate_muid_parser()])

# ----------------------------------------------------------------------
# MIDC format blocks

_midc = SmartyParser()
_midc['magic'] = ParseHelper(parsers.Literal(b'MIDC'))
_midc['version'] = ParseHelper(parsers.Int32(signed=False))
_midc['cipher'] = ParseHelper(parsers.Int8(signed=False))
_midc['body'] = None
_midc['muid'] = generate_muid_parser()
_midc['signature'] = ParseHelper(parsers.Null())

_midc_lookup = {}
_midc_lookup[2] = SmartyParser()
_midc_lookup[2]['signature_key'] = None
_midc_lookup[2]['encryption_key'] = None
_midc_lookup[2]['exchange_key'] = None

_midc_cipher_update = _callback_multi(
    _gen_body_update(_midc, _pubkey_parsers_sig, 'signature_key'),
    _gen_body_update(_midc, _pubkey_parsers_encrypt, 'encryption_key'),
    _gen_body_update(_midc, _pubkey_parsers_exchange, 'exchange_key')
)

_midc['version'].register_callback('prepack', _gen_dispatch(_midc, _midc_lookup, 'body'))
_midc['version'].register_callback('postunpack', _gen_dispatch(_midc, _midc_lookup, 'body'))
_midc['cipher'].register_callback('prepack', _midc_cipher_update)
_midc['cipher'].register_callback('postunpack', _midc_cipher_update)

_midc.latest = max(list(_midc_lookup))
_midc.versions = set(_midc_lookup)

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

_meoc.latest = max(list(_meoc_lookup))
_meoc.versions = set(_meoc_lookup)

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

_mobs.latest = max(list(_mobs_lookup))
_mobs.versions = set(_mobs_lookup)

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

_mobd.latest = max(list(_mobd_lookup))
_mobd.versions = set(_mobd_lookup)

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

_mdxx.latest = max(list(_mdxx_lookup))
_mdxx.versions = set(_mdxx_lookup)

# ----------------------------------------------------------------------
# MEAR format blocks

_mear = SmartyParser()
_mear['magic'] = ParseHelper(parsers.Literal(b'MEAR'))
_mear['version'] = ParseHelper(parsers.Int32(signed=False))
_mear['cipher'] = ParseHelper(parsers.Int8(signed=False))
_mear['body'] = None
_mear['muid'] = generate_muid_parser()
_mear['signature'] = None

_mear_lookup = {}
_mear_lookup[12] = SmartyParser()
_mear_lookup[12]['recipient'] = generate_muid_parser()
_mear_lookup[12]['payload'] = None

_mear_cipher_update = _callback_multi(
    _gen_dispatch(_mear, _mac_parsers, 'signature'), 
    _gen_body_update(_mear, _asym_parsers, 'payload')
)
_mear['version'].register_callback('prepack', _gen_dispatch(_mear, _mear_lookup, 'body'))
_mear['version'].register_callback('postunpack', _gen_dispatch(_mear, _mear_lookup, 'body'))
_mear['cipher'].register_callback('prepack', _mear_cipher_update)
_mear['cipher'].register_callback('postunpack', _mear_cipher_update)

_mear.latest = max(list(_mear_lookup))
_mear.versions = set(_mear_lookup)

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