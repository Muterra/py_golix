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
    def _unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        return cls.PARSER.unpack(data)
        
    @abc.abstractmethod
    def verify(self, *args, **kwargs):
        pass
        
    @abc.abstractmethod
    def finalize(self, data, cipher='default', address_algo='default', *args, **kwargs):
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
        
        # Generate the muid from the desired algo and the passed data
        self.muid = Muid(self.address_algo, self._addresser.create(data))
        
    @classmethod
    @abc.abstractmethod
    def load(self, *args, **kwargs):
        ''' Decrypts, verifies, etc. One-stop shop for object loading.
        Returns a generated object (MEOC, MOBS, etc) instance.
        '''
        pass
       

class MEOC(_MuseObjectBase):
    ''' Muse encrypted object container.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management; simply transitions between encrypted bytes
    and unencrypted bytes.
    '''
    PARSER = _meoc
    
    def __init__(self, author, payload, *args, **kwargs):
        ''' Generates MEOC object.
        
        Author should be a utils.Muid object (or similar).
        '''
        super().__init__(*args, **kwargs)
        
        self.author = author
        self.payload = payload
        
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
        
    def verify(self, *args, **kwargs):
        pass
        
    @classmethod
    def load(self, *args, **kwargs):
        ''' Decrypts, verifies, etc. One-stop shop for object loading.
        Returns a generated object (MEOC, MOBS, etc) instance.
        '''
        pass
        
    def finalize(self, private_key, *args, **kwargs):
        ''' Encrypts, signs, etc. One-stop shop for object completion.
        Returns bytes.
        '''
        # This is here temporarily, until proper data collation has been added
        # Call this first, so that we have data to pass to super()
        data = None
        
        super().finalize(data=data, *args, **kwargs)
        self.signature = self._cipherer.signer(private_key, data)
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
        