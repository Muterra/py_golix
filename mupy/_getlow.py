'''
Low-level Muse network objects. Not intended for general usage.

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

# Housekeeping
DEFAULT_CIPHER = 1

# Control * imports
__all__ = ['MEOC', 'MOBS', 'MOBD', 'MDXX', 'MEAR']

# Global dependencies
import abc
import collections
import inspect

# Not sure if these are still used
import struct
import os
from warnings import warn


from ._spec import _meoc
from ._spec import _mobs
from ._spec import _mobd
from ._spec import _mdxx
from ._spec import _mear
from ._spec import _asym_pr
from ._spec import _asym_ak
from ._spec import _asym_nk
from ._spec import _asym_else

# Accommodate SP
from ._spec import cipher_length_lookup

from .cipher import cipher_lookup
from .cipher import hash_lookup
from .cipher import DEFAULT_ADDRESSER
from .cipher import DEFAULT_CIPHER
from .cipher import SecurityError

from .utils import Muid

        
# ###############################################
# Utilities
# ###############################################

# ----------------------------------------------------------------------
# THIS MAKES ME FEEL DIRTY.
# This is a total hack-up job to bend the smartyparse library to my will,
# until such time as it can be rewritten to support more powerful callback
# syntax, and access to global pack_into data for nested smartyparsers,
# as well as some other issues. This isn't *exactly* a monkeypatch, but
# it's close enough that I'll go ahead and monkeypatch the definition of
# the word monkeypatch to suit my needs. In other news, the MetaPolice are
# coming for me, and I have no defense lawyer.
        
# Strategy for gratuitous duck-punching: 
# 1. Declare a mutable caching object: []
# 2. Generate a caching callback on the fly, referencing that object
# 3. Register that callback on the fly as postpack on muid, with modify=False
# 4. That callback appends the muid's offset to the cache object
# 5. Register a second callback on the entire _control
# 6. That callback uses the offset to rewrite the hash with an actual hash
# 7. Rewrite signature using the length of the hash and the cached hash offset

# For other places this affects, search for "# Accommodate SP"
        
# This gets called postpack with modify=True on ['muid'], referencing
# the _control object.
def _generate_offset_cacher(cache, muid_parser):
    # Relies upon late-binding closures to access the correct offset
    def offset_cacher(*args, **kwargs):
        start = muid_parser.offset + 1
        cache.append(start)
    return offset_cacher

def _generate_muid_rewriter(parent_smartyparser, addresser):
    def muid_rewriter(muid):
        size = parent_smartyparser['muid'].length
        section = slice(len(muid) - size, None)
        muid[section] = addresser.create()


# ###############################################
# Helper objects and functions
# ###############################################


def _attempt_asym_unpack(data):
    for fmt in (_asym_pr, _asym_ak, _asym_nk, _asym_else):
        try:
            result = fmt.unpack(data)
            break
        except parsers.ParseError:
            pass
    # This means unsuccessful iteration through all parsers
    else:
        raise parsers.ParseError('Improperly formed asymmetric payload.')
    return result


# ###############################################
# Low-level Muse object interfaces
# ###############################################
    

class _MuseObjectBase(metaclass=abc.ABCMeta):
    ''' Muse object bases should handle all of the parsing/building 
    dispatch. From there, the subclasses handle object creation, roughly
    equivalent to the object defs spat out by the smartyparsers.
    
    Will this need a helper metaclass to do all of the callbacks for the
    parse handling? Or should that be @staticmethod?
    '''
    
    def __init__(self, version='latest'):   
        # Do this first to initialize state.
        self._control = {
            # This gets the value of the literal from the parser
            'magic': self.PARSER['magic'].parser.value,
            'version': None,
            'cipher': None,
            'body': {},
            'muid': None,
            'signature': None
        }
             
        # Handle the version infos, adjusting if version is latest
        if version == 'latest':
            version = self.PARSER.latest
        self._control['version'] = version
        
    @property
    def signature(self):
        return self._control['signature']
        
    @signature.setter
    def signature(self, value):
        self._control['signature'] = value
        
    @property
    def muid(self):
        return self._control['muid']
        
    @muid.setter
    def muid(self, value):
        self._control['muid'] = value
        
    @property
    def version(self):
        return self._control['version']
        
    @version.setter
    def version(self, value):
        self._control['version'] = value
        
    @property
    def cipher(self):
        return self._control['cipher']
        
    @cipher.setter
    def cipher(self, value):
        self._control['cipher'] = value
        
    @property
    def _cipherer(self):
        return cipher_lookup(self.cipher)
        
    @property
    def _addresser(self):
        return hash_lookup(self.address_algo)
        
    def _pack(self):
        ''' Performs raw packing using the smartyparser in self.PARSER.
        '''
        # Accommodate SP
        _offset_cache = []
        offset_cacher = _generate_offset_cacher(_offset_cache, self.PARSER['muid'])
        self.PARSER['muid'].register_callback('postpack', offset_cacher)
        
        return self.PARSER.pack(self._control), _offset_cache
        
        # # Normal
        # return self.PARSER.pack(self._control)
        
    @classmethod
    @abc.abstractmethod
    def unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        # Accommodate SP
        _offset_cache = []
        offset_cacher = _generate_offset_cacher(_offset_cache, cls.PARSER['muid'])
        cls.PARSER['muid'].register_callback('postunpack', offset_cacher)
        return cls.PARSER.unpack(data), _offset_cache
        
        # # Normal
        # return cls.PARSER.unpack(data)
        
    @abc.abstractmethod
    def verify(self, *args, **kwargs):
        ''' Verifies the public parts of the object.
        '''
        pass
        
    @abc.abstractmethod
    def finalize(self, cipher='default', address_algo='default', *args, **kwargs):
        ''' Encrypts, signs, etc. One-stop shop for object completion.
        Returns bytes.
        '''
        # Adjustment for defaults.
        if cipher == 'default':
            cipher = DEFAULT_CIPHER
        if address_algo == 'default':
            address_algo = DEFAULT_ADDRESSER
        
        self.cipher = cipher
        self._address_algo = address_algo
        
    @classmethod
    @abc.abstractmethod
    def load(cls, data, *args, **kwargs):
        ''' Decrypts, verifies, etc. One-stop shop for object loading.
        Returns a generated object (MEOC, MOBS, etc) instance. Requires
        pre-existing knowledge of the author's identity.
        '''
        pass
        
    @property
    def address_algo(self):
        if self.muid != None:
            return self.muid.algo
        elif self._address_algo != None:
            return self._address_algo
        else:
            raise RuntimeError('Address algorithm not yet defined.')
       

class MEOC(_MuseObjectBase):
    ''' Muse encrypted object container.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management; simply transitions between encrypted bytes
    and unencrypted bytes.
    '''
    PARSER = _meoc
    
    def __init__(self, author, plaintext, *args, **kwargs):
        ''' Generates MEOC object.
        
        Author should be a utils.Muid object (or similar).
        '''
        super().__init__(*args, **kwargs)
        
        self.author = author
        self.plaintext = plaintext
        
    @property
    def payload(self):
        # This should never not be defined, but subclasses might screw with
        # that assumption.
        try:
            return self._control['body']['payload']
        except KeyError as e:
            raise AttributeError('Payload not yet defined.') from e
            
    @payload.setter
    def payload(self, value):
        # DON'T implement a deleter, because without a payload, this is
        # meaningless. Use None for temporary payloads.
        self._control['body']['payload'] = value
        
    @property
    def author(self):
        # This should never not be defined, but subclasses might screw with
        # that assumption.
        try:
            return self._control['body']['author']
        except KeyError as e:
            raise AttributeError('Author not yet defined.') from e
            
    @author.setter
    def author(self, value):
        # DON'T implement a deleter, because without a payload, this is
        # meaningless. Use None for temporary payloads.
        self._control['body']['author'] = value
        
    @classmethod
    def unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        # # Normal
        # unpacked = super().unpack(data)
        
        # Accommodate SP
        unpacked, offset_cache = super().unpack(data)
        address_offset = offset_cache.pop()
        
        # Normal
        # Extract args for cls()
        author = unpacked['body']['author']
        version = unpacked['version']
        plaintext = None
        obj = cls(author, plaintext, version=version)
        
        # Accommodate SP
        obj._cache_address_offset = address_offset
        obj._cache_raw = memoryview(data)
        
        # Normal
        # Iterate through and assign all body fields
        for fieldname in unpacked['body']:
            obj._control['body'][fieldname] = unpacked['body'][fieldname]
        
        # The below also cannot be folded into super(), because cls() needs args
        obj.cipher = unpacked['cipher']
        obj.muid = unpacked['muid']
        obj.signature = unpacked['signature']
        
        # Don't forget this part.
        return obj
        
    def verify(self, public_key, *args, **kwargs):
        ''' Requires existing knowledge of the public key (does not 
        perform any kind of lookup).
        '''
        # Accommodate SP
        address_offset = self._cache_address_offset
        address_data = bytes(self._cache_raw[:address_offset])
        
        # Normal-ish
        self._addresser.verify(self.muid.address, address_data)
        # Normal
        self._cipherer.verifier(public_key, self.signature, data=self.muid.address)
        
    def decrypt(self, secret_key):
        self.plaintext = self._cipherer.symmetric_decryptor(secret_key, self.payload)
        del secret_key
        
    @classmethod
    def load(cls, public_key, secret_key, data):
        ''' Decrypts, verifies, etc. One-stop shop for object loading.
        Returns a generated object (MEOC, MOBS, etc) instance.
        '''
        obj = cls.unpack(data)
        obj.verify(public_key)
        obj.decrypt(secret_key)
        del secret_key
        return obj
        
    def finalize(self, private_key, secret_key, *args, **kwargs):
        ''' Encrypts, signs, etc. One-stop shop for object completion.
        Returns bytes.
        '''
        # Call this to handle defaults for cipher='default' and address_algo='default'
        super().finalize(*args, **kwargs)
        
        self.payload = self._cipherer.symmetric_encryptor(secret_key, self.plaintext)
        del secret_key
        
        # Accommodate SP
        muid_padding = bytes(self._addresser.ADDRESS_LENGTH)
        self.muid = Muid(self.address_algo, muid_padding)
        sig_padding = bytes(cipher_length_lookup[self.cipher]['sig'])
        self.signature = sig_padding
        
        # # Normal
        # del private_key
        # packed = self._pack()
        
        # Accommodate SP
        packed, _offset_cache = self._pack()
        address_offset = _offset_cache.pop()
        sig_offset = address_offset + self._addresser.ADDRESS_LENGTH
        # Hash the packed data, until the appropriate point, and then sign
        # Conversion to bytes necessary for PyCryptoDome API
        address = self._addresser.create(bytes(packed[:address_offset]))
        signature = self._cipherer.signer(private_key, address)
        del private_key
        # Rewrite packed with the hash and signature
        packed[address_offset:sig_offset] = address
        packed[sig_offset:] = signature
        # Useful for anything referencing this post-build
        self.muid = Muid(self.address_algo, address)
        self.signature = signature
        
        # Normal
        return packed
        

class MOBS(_MuseObjectBase):
    ''' Muse object binding, static.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _mobs
    
    def __init__(self, binder, target, *args, **kwargs):
        ''' Generates object and readies it for signing.
        '''
        super().__init__(*args, **kwargs)
        

class MOBD(_MuseObjectBase):
    ''' Muse object binding, dynamic.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _mobd
    
    def __init__(self, binder, targets, history=None, dynamic_address=None, *args, **kwargs):
        ''' Generates object and readies it for signing.
        
        Target must be list. History, if defined, must be list.
        '''
        super().__init__(*args, **kwargs)
        

class MDXX(_MuseObjectBase):
    ''' Muse object debinding.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _mdxx
    
    def __init__(self, debinder, targets, *args, **kwargs):
        ''' Generates object and readies it for signing.
        
        Target must be list.
        '''
        super().__init__(*args, **kwargs)
        

class MEAR(_MuseObjectBase):
    ''' Muse encrypted pipe request.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _mear
    
    def __init__(self, recipient, author, payload_id, payload, *args, **kwargs):
        ''' Generates object and readies it for signing.
        
        Target must be list.
        '''
        super().__init__(*args, **kwargs)


def _attempt_asym_unpack(data):
    for fmt in (_asym_pr, _asym_ak, _asym_nk, _asym_else):
        try:
            result = fmt.unpack(data)
            break
        except parsers.ParseError:
            pass
    # This means unsuccessful iteration through all parsers
    else:
        raise parsers.ParseError('Improperly formed asymmetric payload.')
    return result


def unpack_any(data):
    for fmt in (MEOC, MOBS, MOBD, MDXX, MEAR):
        try:
            result = fmt.unpack(data)
            break
        except parsers.ParseError:
            pass
    # This means unsuccessful iteration through all parsers
    else:
        raise parsers.ParseError('Data does not appear to be a Muse object.')
    return result
        