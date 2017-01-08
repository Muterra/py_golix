'''
Cross-library utilities excluded from core.py or cipher.py to avoid
circular imports.

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
import abc
import base64
# This is just used for ghids.
import random

from collections import namedtuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from smartyparse import SmartyParser
from smartyparse import ListyParser
from smartyparse import ParseHelper
from smartyparse import parsers
from smartyparse import references

from .utils import Ghid
from .exceptions import SecurityError

# ----------------------------------------------------------------------
# Address algorithms


class _AddressAlgoBase(metaclass=abc.ABCMeta):
    @classmethod
    def create(cls, data):
        ''' Creates an address (note: not the whole ghid) from data.
        '''
        h = hashes.Hash(cls._HASH_ALGO(), backend=default_backend())
        h.update(data)
        digest = h.finalize()
        # So this isn't really making much of a difference, necessarily, but
        # it's good insurance against (accidental or malicious) length
        # extension problems.
        del h
        return digest
        
    @classmethod
    def verify(cls, address, data):
        ''' Verifies an address (note: not the whole ghid) from data.
        '''
        test = cls.create(data)
        if test != address:
            raise SecurityError('Failed to verify address integrity.')
        else:
            return True
    
    
class AddressAlgo0(_AddressAlgoBase):
    ''' FOR TESTING PURPOSES ONLY.
    
    Entirely inoperative. Correct API, but ignores all input, creating
    only a symbolic output.
    '''
    _HASH_ALGO = None
    ADDRESS_LENGTH = 64
    
    @classmethod
    def create(cls, data):
        return _dummy_address
        
    @classmethod
    def verify(cls, address, data):
        return True
    
    
class AddressAlgo1(_AddressAlgoBase):
    ''' SHA512
    '''
    _HASH_ALGO = hashes.SHA512
    ADDRESS_LENGTH = _HASH_ALGO.digest_size


# Zero should be rendered inop, IE ignore all input data and generate
# symbolic representations
ADDRESS_ALGOS = {
    0: AddressAlgo0,
    1: AddressAlgo1
}


def hash_lookup(num):
    try:
        return ADDRESS_ALGOS[num]
    except KeyError as exc:
        raise ValueError(
            'Address algo "' + str(num) + '" is undefined.'
        ) from exc


# ----------------------------------------------------------------------
# Mock objects for zeroth hash/ciphersuites


_dummy_address = \
    b'[[ Start hash ' + (b'-' * 38) + b' End hash ]]'
_dummy_signature = \
    b'[[ Start signature ' + (b'-' * 476) + b' End signature ]]'
_dummy_mac = \
    b'[[ Start MAC ' + (b'-' * 40) + b' End MAC ]]'
_dummy_asym = \
    b'[[ Start asymmetric payload ' + (b'-' * 458) + \
    b' End asymmetric payload ]]'
_dummy_pubkey = \
    b'[ ' + (b'-') * 245 + b' MOCK PUBLIC KEY ' + (b'-') * 246 + b' ]'
_dummy_pubkey_exchange = \
    b'[ ' + (b'-') * 6 + b' MOCK PUBLIC KEY ' + (b'-') * 5 + b' ]'


# ----------------------------------------------------------------------
# Hash algo identifier / length block


_hash_algo_lookup = {
    0: ParseHelper(parsers.Blob(length=len(_dummy_address))),
    1: ParseHelper(parsers.Blob(length=64))
}


# ----------------------------------------------------------------------
# Generalized object dispatchers


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
        'seed': 0
    },
    1: {
        'key': 32,
        'sig': 512,
        'mac': 64,
        'asym': 512,
        'seed': 16
    },
    2: {
        'key': 64,
        'sig': 512,
        'mac': 64,
        'asym': 512,
        'seed': 0
    }
}


# ----------------------------------------------------------------------
# Misc objects


def _ghid_transform(unpacked_spo):
    ''' Transforms an unpacked SmartyParseObject into a .utils.Ghid.
    If using algo zero, also eliminates the address and replaces with
    None.
    '''
    ghid = Ghid(algo=unpacked_spo['algo'], address=unpacked_spo['address'])
        
    return ghid


def generate_ghid_parser():
    ghid_parser = SmartyParser()
    ghid_parser['algo'] = ParseHelper(parsers.Int8(signed=False))
    ghid_parser['address'] = None

    @references(ghid_parser)
    def _ghid_format(self, algo):
        try:
            self['address'] = _hash_algo_lookup[algo]
        except KeyError as e:
            print(algo)
            raise ValueError('Improper hash algorithm declaration.') from e
            
    ghid_parser['algo'].register_callback('prepack', _ghid_format)
    ghid_parser['algo'].register_callback('postunpack', _ghid_format)
    
    # Don't forget to transform the object back to a utils.Ghid
    ghid_parser.register_callback('postunpack', _ghid_transform, modify=True)
    
    return ghid_parser
    
    
def generate_ghidlist_parser():
    return ListyParser(parsers=[generate_ghid_parser()])
    
    
_secret_parser = SmartyParser()
_secret_parser['magic'] = ParseHelper(parsers.Literal(b'SH'))
_secret_parser['version'] = ParseHelper(parsers.Int16(signed=False))
_secret_parser['cipher'] = ParseHelper(parsers.Int8(signed=False))
_secret_parser['key'] = None
_secret_parser['seed'] = None


def _secret_cipher_update(cipher):
    key_length = cipher_length_lookup[cipher]['key']
    seed_length = cipher_length_lookup[cipher]['seed']
    _secret_parser['key'] = ParseHelper(parsers.Blob(length=key_length))
    _secret_parser['seed'] = ParseHelper(parsers.Blob(length=seed_length))

_secret_parser['cipher'].register_callback(
    'prepack',
    _secret_cipher_update
)
_secret_parser['cipher'].register_callback(
    'postunpack',
    _secret_cipher_update
)

# Hard code this in for now
_secret_parsers = {
    2: _secret_parser
}

_secret_latest = max(list(_secret_parsers))
_secret_versions = set(_secret_parsers)
    
    
class Secret:
    ''' All secrets have a key. Some have a nonce or IV (seed). All must
    be able to be condensed into __bytes__. All must also be retrievable
    from a bytes object.
    '''
    # We expect to have a lot of secrets, so let's add slots. Also, there's
    # a case to be made for discouraging people from using Secrets for
    # anything other than, well, secrets.
    __slots__ = ['_key', '_seed', '_version', '_cipher', '__weakref__']
    MAGIC = _secret_parser['magic'].parser.value
    
    def __init__(self, cipher, key, seed=None, version='latest'):
        # Most of these checks should probably be moved into property
        # setters.
        if seed is None:
            seed = b''
            
        if version == 'latest':
            version = _secret_latest
        elif version not in _secret_versions:
            raise ValueError('Improper Secret version declaration.')
            
        if cipher not in cipher_length_lookup:
            raise ValueError('Unsupported cipher declaration.')
        
        if len(key) != cipher_length_lookup[cipher]['key']:
            raise ValueError(
                'Key must be of proper length for the declared '
                'ciphersuite.'
            )
        
        if len(seed) != cipher_length_lookup[cipher]['seed']:
            raise ValueError(
                'Seed must be of proper length for the declared '
                'ciphersuite.'
            )
            
        self._cipher = cipher
        self._version = version
        self._key = key
        self._seed = seed
       
    @property
    def key(self):
        return self._key
        
    @property
    def seed(self):
        return self._seed
    
    def __bytes__(self):
        return bytes(self._parser.pack(self._control))
        
    @classmethod
    def from_bytes(cls, data):
        # Okay, this is hard-coding in version 2 as the unpacker. Oh well.
        obj = _secret_parser.unpack(data)
        return cls(
            cipher = obj['cipher'],
            key = bytes(obj['key']),
            seed = bytes(obj['seed']),
            version = obj['version']
        )
        
    @property
    def version(self):
        return self._version
        
    @property
    def cipher(self):
        return self._cipher
        
    @property
    def _parser(self):
        return _secret_parsers[self.version]
        
    @property
    def _control(self):
        return {
            'magic': self.MAGIC,
            'version': self.version,
            'cipher': self.cipher,
            'key': self.key,
            'seed': self.seed
        }
            
    def __repr__(self):
        c = type(self).__name__
        return (
            c +
            '(cipher=' + repr(self.cipher) + ', '
            'key=' + repr(self.key) + ', '
            'seed=' + repr(self.seed) + ', '
            'version=' + repr(self.version) + ')'
        )
        
    def __hash__(self):
        return (
            hash(self.cipher) ^
            hash(self.version) ^
            hash(self.key) ^
            hash(self.seed)
        )
        
    def __eq__(self, other):
        try:
            return (
                self.cipher == other.cipher and
                self.version == other.version and
                self.key == other.key and
                self.seed == other.seed
            )
        except (AttributeError, TypeError) as e:
            raise TypeError(
                'Cannot compare Secret objects to non-Secret-like objects.'
            ) from e
        
    def as_str(self):
        ''' Encodes the ghid as a urlsafe-base64 string.
        '''
        return base64.urlsafe_b64encode(bytes(self)).decode()
        
    @classmethod
    def from_str(cls, b64):
        ''' Returns a ghid built from the urlsafe-base64 string b64.
        '''
        raw = base64.urlsafe_b64decode(b64)
        return cls.from_bytes(raw)


# ----------------------------------------------------------------------
# Various response objects


AsymHandshake = namedtuple('AsymHandshake', ['author', 'target', 'secret'])
AsymAck = namedtuple('AsymAck', ['author', 'target', 'status'])
AsymNak = namedtuple('AsymNak', ['author', 'target', 'status'])
