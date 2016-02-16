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

        
# ###############################################
# Utilities
# ###############################################


# ###############################################
# Helper objects and functions
# ###############################################


from ._spec import _meoc
from ._spec import _mobs
from ._spec import _mobd
from ._spec import _mdxx
from ._spec import _mear
from ._spec import _asym_pr
from ._spec import _asym_ak
from ._spec import _asym_nk
from ._spec import _asym_else

from .cipher import cipher_lookup
from .cipher import hash_lookup
from .cipher import DEFAULT_ADDRESSER
from .cipher import DEFAULT_CIPHER

from .utils import Muid


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
        return self.PARSER.pack(self._control)
        
    @classmethod
    @abc.abstractmethod
    def unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        return cls.PARSER.unpack(data)
        
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
        self.address_algo = address_algo
        
    @classmethod
    @abc.abstractmethod
    def load(cls, data, *args, **kwargs):
        ''' Decrypts, verifies, etc. One-stop shop for object loading.
        Returns a generated object (MEOC, MOBS, etc) instance. Requires
        pre-existing knowledge of the author's identity.
        '''
        pass
       

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
        unpacked = super().unpack(data)
        
        # Extract args for cls()
        author = unpacked['body']['author']
        version = unpacked['version']
        plaintext = None
        obj = cls(author, plaintext, version=version)
        
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
        self._cipherer.verifier(public_key, self.signature, data=self.muid)
        
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
        # Generate the muid from the desired algo and the passed data
        hash_data = None
        self.muid = Muid(self.address_algo, self._addresser.create(hash_data))
        self.signature = self._cipherer.signer(private_key, self.muid)
        del private_key
        return self._pack()
        

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
        