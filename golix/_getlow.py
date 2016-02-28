'''
Low-level Golix network objects. Not intended for general usage.

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

# Control * imports
__all__ = ['GIDC', 'GEOC', 'GOBS', 'GOBD', 'GDXX', 'GARQ']

# Global dependencies
import abc
import collections
import inspect

# Not sure if these are still used
import struct
import os
from warnings import warn

from ._spec import _gidc
from ._spec import _geoc
from ._spec import _gobs
from ._spec import _gobd
from ._spec import _gdxx
from ._spec import _garq
from ._spec import _asym_rq
from ._spec import _asym_ak
from ._spec import _asym_nk
from ._spec import _asym_else

# Accommodate SP
from .utils import cipher_length_lookup
from .utils import hash_lookup

# Normal
from .utils import Guid
from .utils import SecurityError
from .utils import Secret

        
# ###############################################
# Utilities
# ###############################################

# ----------------------------------------------------------------------
# THIS MAKES ME FEEL DIRTY.

# We need to refactor once smartyparse is rewritten to modify the same
# object continuously. Currently, smartyparse handles nested smartyparsers
# as their own independent unit, so you can't register a callback on the
# whole set of data. Which is a problem. Basically, nested SP's have no
# awareness of their surrounding file context, so you can't do a callback
# to pull in their context. So currently, you have to do it as a multi-pass
# thingajobber.

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
# 3. Register that callback on the fly as postpack on guid, with modify=False
# 4. That callback appends the guid's offset to the cache object
# 5. Register a second callback on the entire _control
# 6. That callback uses the offset to rewrite the hash with an actual hash
# 7. Rewrite signature using the length of the hash and the cached hash offset

# For other places this affects, search for "# Accommodate SP"
        
# This gets called postpack with modify=True on ['guid'], referencing
# the _control object.
def _generate_offset_cacher(cache, guid_parser):
    # Relies upon late-binding closures to access the correct offset
    def offset_cacher(*args, **kwargs):
        start = guid_parser.offset + 1
        cache.append(start)
    return offset_cacher

def _generate_guid_rewriter(parent_smartyparser, addresser):
    def guid_rewriter(guid):
        size = parent_smartyparser['guid'].length
        section = slice(len(guid) - size, None)
        guid[section] = addresser.create()


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
# Low-level Golix object interfaces
# ###############################################
    

class _GolixObjectBase(metaclass=abc.ABCMeta):
    ''' Golix object bases should handle all of the parsing/building 
    dispatch. From there, the subclasses handle object creation, roughly
    equivalent to the object defs spat out by the smartyparsers.
    
    Will this need a helper metaclass to do all of the callbacks for the
    parse handling? Or should that be @staticmethod?
    '''
    
    def __init__(self, version='latest', _control=None):   
        # Do this first to initialize state.
        self._address_algo = None
        self._signed = False
        self._packed = None
        
        # If we're creating an object from an unpacked one, just load directly
        if _control:
            self._control = _control
            
        # Creating from scratch. Now we have some actual work to do.
        else:
            # We need to do some checking here.
            # Handle the version infos, adjusting if version is latest
            version = self._handle_version(version)
            
            # All checks passed, go ahead and load the 
            self._control = {
                # This gets the value of the literal from the parser
                'magic': self.PARSER['magic'].parser.value,
                'version': version,
                'cipher': None,
                'body': {},
                'guid': None,
                'signature': None
            }
            
    def _handle_version(self, version):
        if version == 'latest':
            version = self.PARSER.latest
        if version not in self.PARSER.versions:
            raise ValueError('Object version unavailable: ' + str(version))
        return version
        
    @property
    def packed(self):
        ''' Returns the packed object if and only if it has been packed
        and signed.
        '''
        if self._signed:
            return self._packed
        else:
            raise RuntimeError(
                'Packed object unavailable until packed and signed.'
            )
        
    @property
    def signature(self):
        return self._control['signature']
        
    @signature.setter
    def signature(self, value):
        self._control['signature'] = value
        
    @property
    def guid(self):
        return self._control['guid']
        
    @guid.setter
    def guid(self, value):
        self._control['guid'] = value
        
    @property
    def version(self):
        return self._control['version']
        
    @version.setter
    def version(self, value):
        self._control['version'] = value
        
    @property
    def cipher(self):
        if self._control['cipher'] != None:
            return self._control['cipher']
        else:
            raise RuntimeError('Cipher has not yet been defined.')
        
    @cipher.setter
    def cipher(self, value):
        self._control['cipher'] = value
        
    @property
    def _addresser(self):
        return hash_lookup(self.address_algo)
        
    @property
    def address_algo(self):
        if self.guid is not None:
            return self.guid.algo
        elif self._address_algo != None:
            return self._address_algo
        else:
            raise RuntimeError('Address algorithm not yet defined.')
    
    def _get_sig_length(self):
        ''' Quick and dirty way to get the object's signature length; 
        easily overwritten when it's not the cipher defined (eg: gidc, 
        garq).
        
        # Accommodate SP on the whole damn thing currently.
        '''
        return cipher_length_lookup[self.cipher]['sig']
        
    def pack(self, address_algo, cipher):
        ''' Performs raw packing using the smartyparser in self.PARSER.
        Generates a GUID as well.
        '''
        # Normal
        self.cipher = cipher
        self._address_algo = address_algo
        
        # Accommodate SP
        # This is really simple and is hard-coding a reliance on the order
        # of signature and hash in relation to the rest of the formats.
        # It's quick and dirty but effective and less prone to bugs than fancy
        # things, especially with smartyparse not as reliable as I'd like.
        sig_length = self._get_sig_length()
        sig_padding = bytes(sig_length)
        self.signature = sig_padding
        hash_length = self._addresser.ADDRESS_LENGTH
        guid_padding = bytes(hash_length)
        self.guid = Guid(self.address_algo, guid_padding)
        
        # Normal
        packed = self.PARSER.pack(self._control)
        
        # Accommodate SP
        final_size = len(packed)
        sig_slice = slice(
            final_size - sig_length,
            None
        )
        hash_slice = slice(
            sig_slice.start - hash_length,
            sig_slice.start
        )
        calc_slice = slice(
            0,
            hash_slice.start
        )
        self._sig_slice = sig_slice
        
        # Hash the packed data, until the appropriate point, and then sign
        # Conversion to bytes necessary for PyCryptoDome API
        address = self._addresser.create(bytes(packed[calc_slice]))
        packed[hash_slice] = address
        self.guid = Guid(self.address_algo, address)
        
        # Normal-ish, courtesy of above
        self._packed = packed
        self.signature = None
        
    def pack_signature(self, signature):
        if not self._packed:
            raise RuntimeError(
                'Signature cannot be packed without first calling pack().'
            )
        self.signature = signature
        self._packed[self._sig_slice] = signature
        self._signed = True
        del self._sig_slice
        
    @classmethod
    def unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        # Accommodate SP
        offset_cache = []
        offset_cacher = _generate_offset_cacher(offset_cache, cls.PARSER['guid'])
        cls.PARSER['guid'].register_callback('preunpack', offset_cacher)
        
        # Normal
        unpacked = cls.PARSER.unpack(data)
        self = cls(_control=unpacked)
        self._packed = memoryview(data)
        
        # Accommodate SP
        address_offset = offset_cache.pop()
        address_data = self._packed[:address_offset].tobytes()
        
        # Normal-ish
        self._addresser.verify(self.guid.address, address_data)
        
        # Don't forget this part.
        return self
       

class GIDC(_GolixObjectBase):
    ''' Golix identity container.
    
    Low level object. In most cases, you don't want this.
    '''
    PARSER = _gidc
    
    def __init__(self, 
                signature_key=None, 
                encryption_key=None, 
                exchange_key=None, 
                _control=None, *args, **kwargs):
        ''' Generates GIDC object. Keys must be suitable for the 
        declared ciphersuite.
        '''
        super().__init__(_control=_control, *args, **kwargs)
        
        # Don't overwrite anything we loaded from _control!
        if not _control:
            self.signature_key = signature_key
            self.encryption_key = encryption_key
            self.exchange_key = exchange_key
        
    @property
    def signature_key(self):
        # This should never not be defined, but subclasses might screw with
        # that assumption.
        try:
            return self._control['body']['signature_key']
        except KeyError as e:
            raise AttributeError('Signature key not yet defined.') from e
            
    @signature_key.setter
    def signature_key(self, value):
        # DON'T implement a deleter, because without a payload, this is
        # meaningless. Use None for temporary payloads.
        self._control['body']['signature_key'] = value
        
    @property
    def encryption_key(self):
        # This should never not be defined, but subclasses might screw with
        # that assumption.
        try:
            return self._control['body']['encryption_key']
        except KeyError as e:
            raise AttributeError('Encryption key not yet defined.') from e
            
    @encryption_key.setter
    def encryption_key(self, value):
        # DON'T implement a deleter, because without a payload, this is
        # meaningless. Use None for temporary payloads.
        self._control['body']['encryption_key'] = value
        
    @property
    def exchange_key(self):
        # This should never not be defined, but subclasses might screw with
        # that assumption.
        try:
            return self._control['body']['exchange_key']
        except KeyError as e:
            raise AttributeError('exchange key not yet defined.') from e
            
    @exchange_key.setter
    def exchange_key(self, value):
        # DON'T implement a deleter, because without a payload, this is
        # meaningless. Use None for temporary payloads.
        self._control['body']['exchange_key'] = value
        
    def pack(self, *args, **kwargs):
        ''' Quick and dirty packing, which immediately sets self._signed
        to true. Will exactly mimic behavior of super, except for that.
        '''
        result = super().pack(*args, **kwargs)
        self._signed = True
        return result
        
    def _get_sig_length(self):
        # Accommodate SP
        return 0
       

class GEOC(_GolixObjectBase):
    ''' Golix encrypted object container.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management; simply transitions between encrypted bytes
    and unencrypted bytes.
    '''
    PARSER = _geoc
    
    def __init__(self, author=None, payload=None, _control=None, *args, **kwargs):
        ''' Generates GEOC object.
        
        Author should be a utils.Guid object (or similar).
        '''
        super().__init__(_control=_control, *args, **kwargs)
        
        # Don't overwrite anything we loaded from _control!
        if not _control:
            self.payload = payload
            self.author = author
        
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
        

class GOBS(_GolixObjectBase):
    ''' Golix object binding, static.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _gobs
    
    def __init__(self, binder=None, target=None, _control=None, *args, **kwargs):
        ''' Generates GOBS object.
        
        Binder and target should be a utils.Guid object (or similar).
        '''
        super().__init__(_control=_control, *args, **kwargs)
        
        # Don't overwrite anything we loaded from _control!
        if not _control:
            self.binder = binder
            self.target = target
        
    @property
    def binder(self):
        try:
            return self._control['body']['binder']
        except KeyError as e:
            raise AttributeError('Binder not yet defined.') from e
            
    @binder.setter
    def binder(self, value):
        self._control['body']['binder'] = value
        
    @property
    def target(self):
        try:
            return self._control['body']['target']
        except KeyError as e:
            raise AttributeError('Target not yet defined.') from e
            
    @target.setter
    def target(self, value):
        self._control['body']['target'] = value
        

class GOBD(_GolixObjectBase):
    ''' Golix object binding, dynamic.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _gobd
    
    def __init__(self, 
                binder=None, 
                history=None, 
                targets=None, 
                dynamic_address=None, 
                _control=None, *args, **kwargs):
        ''' Generates GOBS object.
        
        Binder, targets, and dynamic_address should be a utils.Guid 
        object (or similar).
        '''
        super().__init__(_control=_control, *args, **kwargs)
        
        # Don't overwrite anything we loaded from _control!
        if not _control:
            self.binder = binder
            self.targets = targets
            self.dynamic_address = dynamic_address
            self.history = history
        
    @property
    def binder(self):
        try:
            return self._control['body']['binder']
        except KeyError as e:
            raise AttributeError('Binder not yet defined.') from e
            
    @binder.setter
    def binder(self, value):
        self._control['body']['binder'] = value
        
    @property
    def targets(self):
        try:
            return self._control['body']['targets']
        except KeyError as e:
            raise AttributeError('Targets not yet defined.') from e
            
    @targets.setter
    def targets(self, value):
        self._control['body']['targets'] = value
        
    @property
    def dynamic_address(self):
        try:
            return self._control['guid_dynamic']
        except KeyError as e:
            raise AttributeError('Dynamic address not yet defined.') from e
            
    @dynamic_address.setter
    def dynamic_address(self, value):
        self._control['guid_dynamic'] = value
        
    @property
    def history(self):
        try:
            return self._control['body']['history']
        except KeyError as e:
            raise AttributeError('History not yet defined.') from e
            
    @history.setter
    def history(self, value):
        self._control['body']['history'] = value
        
    def pack(self, address_algo, cipher):
        ''' Overwrite super() to support dynamic address generation.
        Awkward, largely violates Don'tRepeatYourself, but quickest way
        to work around SmartyParse's current limitations.
        '''
        # Normal
        # First we need to check some things.
        if self.history and self.dynamic_address:
            # Accommodate SP
            calculate_dynamic = False
        # Normal
        elif self.history or self.dynamic_address:
            raise ValueError(
                'History and dynamic address must both be defined, or '
                'undefined. One cannot exist without the other.')
        # In this case, we need to prepare to generate a dynamic address
        else:
            # Accommodate SP
            calculate_dynamic = True
            
        # Normal
        self.cipher = cipher
        self._address_algo = address_algo
        
        # Accommodate SP
        # This is really simple and is hard-coding a reliance on the order
        # of signature and hash in relation to the rest of the formats.
        # It's quick and dirty but effective and less prone to bugs than fancy
        # things, especially with smartyparse not as reliable as I'd like.
        sig_length = cipher_length_lookup[self.cipher]['sig']
        sig_padding = bytes(sig_length)
        self.signature = sig_padding
        hash_length = self._addresser.ADDRESS_LENGTH
        guid_padding = bytes(hash_length)
        self.guid = Guid(self.address_algo, guid_padding)
        
        # Accommodate SP
        if calculate_dynamic:
            self.history = []
            self.dynamic_address = Guid(self.address_algo, guid_padding)
        
        # Normal
        packed = self.PARSER.pack(self._control)
        
        # Accommodate SP
        final_size = len(packed)
        sig_slice = slice(
            final_size - sig_length,
            None
        )
        hash_slice_static = slice(
            sig_slice.start - hash_length,
            sig_slice.start
        )
        calc_slice_static = slice(
            0,
            hash_slice_static.start
        )
        hash_slice_dynamic = slice(
            # Don't forget the extra byte for the address algo denotation
            hash_slice_static.start - 1 - hash_length,
            hash_slice_static.start - 1
        )
        calc_slice_dynamic = slice(
            0,
            hash_slice_dynamic.start
        )
        self._sig_slice = sig_slice
        
        if calculate_dynamic:
            address_dynamic = self._addresser.create(
                bytes(packed[calc_slice_dynamic])
            )
            packed[hash_slice_dynamic] = address_dynamic
            self.dynamic_address = Guid(self.address_algo, address_dynamic)
        
        # Hash the packed data, until the appropriate point, and then sign
        # Conversion to bytes necessary for PyCryptoDome API
        address = self._addresser.create(bytes(packed[calc_slice_static]))
        packed[hash_slice_static] = address
        self.guid = Guid(self.address_algo, address)
        
        # Normal-ish, courtesy of above
        self._packed = packed
        self.signature = None
        
    @classmethod
    def unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        # Accommodate SP
        offset_cache_static = []
        offset_cacher_static = _generate_offset_cacher(
            offset_cache_static, 
            cls.PARSER['guid']
        )
        cls.PARSER['guid'].register_callback(
            'preunpack', 
            offset_cacher_static
        )
        
        offset_cache_dynamic = []
        offset_cacher_dynamic = _generate_offset_cacher(
            offset_cache_dynamic, 
            cls.PARSER['guid_dynamic']
        )
        cls.PARSER['guid_dynamic'].register_callback(
            'preunpack', 
            offset_cacher_dynamic
        )
        
        # Normal
        unpacked = cls.PARSER.unpack(data)
        self = cls(_control=unpacked)
        self._packed = memoryview(data)
        
        # Accommodate SP
        address_offset_static = offset_cache_static.pop()
        address_data_static = self._packed[:address_offset_static].tobytes()
        
        address_offset_dynamic = offset_cache_dynamic.pop()
        address_data_dynamic = self._packed[:address_offset_dynamic].tobytes()
        
        # Verify the initial hash if history is undefined
        if not self.history:
            self._addresser.verify(
                self.dynamic_address.address, 
                address_data_dynamic
            )
        
        # Normal-ish
        self._addresser.verify(self.guid.address, address_data_static)
        
        # Don't forget this part.
        return self
        

class GDXX(_GolixObjectBase):
    ''' Golix object debinding.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _gdxx
    
    def __init__(self, debinder=None, targets=None, _control=None, *args, **kwargs):
        ''' Generates GDXX object.
        
        Binder and target should be a utils.Guid object (or similar).
        '''
        super().__init__(_control=_control, *args, **kwargs)
        
        # Don't overwrite anything we loaded from _control!
        if not _control:
            self.debinder = debinder
            self.targets = targets
        
    @property
    def debinder(self):
        try:
            return self._control['body']['debinder']
        except KeyError as e:
            raise AttributeError('Debinder not yet defined.') from e
            
    @debinder.setter
    def debinder(self, value):
        self._control['body']['debinder'] = value
        
    @property
    def targets(self):
        try:
            return self._control['body']['targets']
        except KeyError as e:
            raise AttributeError('Targets not yet defined.') from e
            
    @targets.setter
    def targets(self, value):
        self._control['body']['targets'] = value
        

class GARQ(_GolixObjectBase):
    ''' Golix encrypted asymmetric request.
    
    Low level object. In most cases, you don't want this. Does not
    perform state management.
    '''
    PARSER = _garq
    
    def __init__(self, recipient=None, payload=None, _control=None, *args, **kwargs):
        ''' Generates GARQ object.
        
        Recipient must be a utils.Guid object (or similar). 
        Payload must be bytes-like.
        '''
        super().__init__(_control=_control, *args, **kwargs)
        
        # Don't overwrite anything we loaded from _control!
        if not _control:
            self.recipient = recipient
            self.payload = payload
        
    @property
    def recipient(self):
        try:
            return self._control['body']['recipient']
        except KeyError as e:
            raise AttributeError('Recipient not yet defined.') from e
            
    @recipient.setter
    def recipient(self, value):
        self._control['body']['recipient'] = value
        
    @property
    def payload(self):
        try:
            return self._control['body']['payload']
        except KeyError as e:
            raise AttributeError('Payload not yet defined.') from e
            
    @payload.setter
    def payload(self, value):
        self._control['body']['payload'] = value
    
    # # None of this is useful. Pass it pre-encrypted payload instead.
    # # AKA, handle upstream. 
        
    # @property
    # def payload(self):
    #     try:
    #         return self._payload_obj
    #     except AttributeError as e:
    #         raise AttributeError('Payload not yet defined.') from e
            
    # @payload.setter
    # def payload(self, value):
    #     if not isinstance(value, _AsymBase):
    #         raise TypeError(
    #             'Payload must be an AsymRequest, AsymAck, AsymNak, or '
    #             'AsymElse object.'
    #         )
    #     self._payload_obj = value   
        
    # def pack(self, *args, **kwargs):
    #     ''' Initialize output of payload, and then call super.
    #     '''
    #     self._control['body']['payload'] = self._payload_obj.pack()
    #     super().pack(*args, **kwargs)
        
    # @classmethod
    # def unpack(cls, *args, **kwargs):
    #     obj = super().unpack(*args, **kwargs)
    #     # Automatically parse whichever payload is there
    #     payload = _attempt_asym_unpack(obj._control['body']['payload'])
        
    def _get_sig_length(self):
        # Accommodate SP
        return cipher_length_lookup[self.cipher]['mac']
        

class _AsymBase():
    ''' AsymBase class should handle all of the parsing/building 
    dispatch. From there, the subclasses handle object creation, roughly
    equivalent to the object defs spat out by the smartyparsers.
    '''
    
    def __init__(self, author=None, _control=None):
        # If we're creating an object from an unpacked one, just load directly
        if _control:
            self._control = _control
            
        # Creating from scratch. Now we have some actual work to do.
        else:            
            # All checks passed, go ahead and load the 
            self._control = {
                # This gets the value of the literal from the parser
                'author': author,
                'magic': self.PARSER['magic'].parser.value,
                'payload': None
            }
        
    @property
    def packed(self):
        ''' Returns the packed object if and only if it has been packed
        and signed.
        '''
        try:
            return self._packed
        except AttributeError as e:
            raise RuntimeError('Object has not yet been packed.') from e
        
    @property
    def author(self):
        return self._control['author']
        
    @author.setter
    def author(self, value):
        self._control['author'] = value
        
    @property
    def magic(self):
        return self._control['magic']
        
    def pack(self):
        ''' Performs raw packing using the smartyparser in self.PARSER.
        '''
        self._packed = self.PARSER.pack(self._control)
        return self._packed
        
    @classmethod
    def unpack(cls, data):
        ''' Performs raw unpacking with the smartyparser in self.PARSER.
        '''
        unpacked = cls.PARSER.unpack(data)
        self = cls(_control=unpacked)
        self._packed = memoryview(data)
        
        return self


class AsymRequest(_AsymBase):
    ''' Asymmetric pipe request. Used as payload in GARQ objects.
    '''
    PARSER = _asym_rq
    
    def __init__(self, target=None, secret=None, _control=None, *args, **kwargs):
        super().__init__(_control=_control, *args, **kwargs)
        if _control is None:
            self._control['payload'] = {}
            self.target = target
            self.secret = secret
        
    @property
    def target(self):
        try:
            return self._control['payload']['target']
        except KeyError as e:
            raise AttributeError('Target not yet defined.') from e
            
    @target.setter
    def target(self, value):
        self._control['payload']['target'] = value
            
    @property
    def secret(self):
        return self._secret
        
    @secret.setter
    def secret(self, value):
        if value is not None and not isinstance(value, Secret):
            raise TypeError('Can only assign secret as a Secret-like object.')
        else:
            self._secret = value
            
    def pack(self, *args, **kwargs):
        self._control['payload']['target'] = self.target
        self._control['payload']['secret'] = bytes(self.secret)
        super().pack(*args, **kwargs)
        
    @classmethod
    def unpack(cls, *args, **kwargs):
        self = super().unpack(*args, **kwargs)
        self._secret = Secret.from_bytes(self._control['payload']['secret'])
        self._target = self._control['payload']['target']
        
        return self
        

class AsymAck(_AsymBase):
    ''' Asymmetric pipe acknowledgement. 
    Used as payload in GARQ objects.
    '''
    PARSER = _asym_ak
    
    def __init__(self, target=None, status=0, _control=None, *args, **kwargs):
        super().__init__(_control=_control, *args, **kwargs)
        if _control is None:
            self._control['payload'] = {}
            self.target = target
            self.status = status
        
    @property
    def target(self):
        try:
            return self._control['payload']['target']
        except KeyError as e:
            raise AttributeError('Target not yet defined.') from e
            
    @target.setter
    def target(self, value):
        self._control['payload']['target'] = value
            
    @property
    def status(self):
        return self._status
        
    @status.setter
    def status(self, value):
        # if value is not None and not isinstance(value, Secret):
        #     raise TypeError('Can only assign secret as a Secret-like object.')
        # else:
        #     self._status = value
        self._status = value
            
    def pack(self, *args, **kwargs):
        self._control['payload']['target'] = self.target
        self._control['payload']['status'] = self.status
        super().pack(*args, **kwargs)
        
    @classmethod
    def unpack(cls, *args, **kwargs):
        self = super().unpack(*args, **kwargs)
        self._status = self._control['payload']['status']
        self._target = self._control['payload']['target']
        
        return self


class AsymNak(AsymAck):
    ''' Asymmetric pipe non-acknowledgement. 
    Used as payload in GARQ objects.
    Other than magic, identical to AsymAck.
    '''
    PARSER = _asym_nk


class AsymElse(_AsymBase):
    ''' Asymmetric arbitrary payload. Used as payload in GARQ objects.
    '''
    PARSER = _asym_else
    
    def __init__(self, payload=None, _control=None, *args, **kwargs):
        super().__init__(_control=_control, *args, **kwargs)
        if _control is None:
            self.payload = payload
        
    @property
    def payload(self):
        return self._control['payload']
        
    @payload.setter
    def payload(self, value):
        self._control['payload'] = value