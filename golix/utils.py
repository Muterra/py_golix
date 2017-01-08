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
import base64
# This is just used for ghids.
import random

from .exceptions import InvalidGhidAlgo
from .exceptions import InvalidGhidAddress


# ----------------------------------------------------------------------
# Ghids and parsers therefore.


_hash_len_lookup = {
    0: 64,
    1: 64
}


class Ghid:
    ''' Extremely lightweight class for GHIDs. Implements __hash__ to
    allow it to be used as a dictionary key.
    
    TODO: make algo and address immutable
    TODO: alias "address" to "digest"
    '''
    __slots__ = ['_algo', '_address', '__weakref__']
    
    def __init__(self, algo, address, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.algo = algo
        self.address = bytes(address)
        
    def __getitem__(self, item):
        ''' DEPRECATED! Should be removed, but is being used internally,
        so we're holding off on this.
        '''
        return getattr(self, item)
        
    def __setitem__(self, item, value):
        ''' DEPRECATED! Should be removed, but is being used internally,
        so we're holding off on this.
        '''
        setattr(self, item, value)
        
    def __hash__(self):
        # XOR the algo's hash with the address' hash
        return hash(self.algo) ^ hash(self.address)
        
    def __eq__(self, other):
        try:
            return (self.algo == other.algo and self.address == other.address)
        except (AttributeError, TypeError) as e:
            raise TypeError(
                'Cannot compare Ghid objects to non-Ghid-like objects.'
            ) from e
            
    def __repr__(self):
        c = type(self).__name__
        return (
            c +
            '(algo=' + repr(self.algo) + ', '
            'address=' + repr(self.address) + ')'
        )
        
    @property
    def algo(self):
        ''' Algo is the integer algorithm.
        '''
        return self._algo
        
    @algo.setter
    def algo(self, value):
        if value in _hash_len_lookup:
            self._algo = value
        else:
            raise InvalidGhidAlgo(value)
            
    @property
    def address(self):
        ''' Address is the bytes-like address component.
        '''
        return self._address
            
    @address.setter
    def address(self, address):
        expected_length = _hash_len_lookup[self.algo]
        
        if len(address) != expected_length:
            raise InvalidGhidAddress('Bad length: ' + str(address)) from None
        
        else:
            self._address = address
            
    def __bytes__(self):
        ''' For now, quick and dirty like.
        '''
        return int.to_bytes(self.algo, length=1, byteorder='big') + \
            self.address
        
    @classmethod
    def from_bytes(cls, data, autoconsume=False):
        ''' Trashy method for building a Ghid from bytes. Should
        probably rework to do some type checking or summat, or use the
        good ole smartyparser. For now, quick and dirty like.
        '''
        algo = int.from_bytes(data[0:1], byteorder='big')
        address = bytes(data[1:])
        return cls(algo=algo, address=address)
        
    def __str__(self):
        c = type(self).__name__
        b64 = base64.urlsafe_b64encode(bytes(self)).decode()
        # Skip the first character, because it's always A.
        return c + '(\'' + b64[1:6] + '...\')'
        
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
    
    @classmethod
    def placeholder(cls):
        ''' Create a dummy ghid for hex inspection.
        '''
        return cls(
            algo = 0,
            address = b'[[ Start hash ' + (b'-' * 38) + b' End hash ]]'
        )
        
    @classmethod
    def pseudorandom(cls, algo):
        ''' Create a pseudorandom ghid for the specified algo. WARNING:
        THIS IS NOT CSRNG! DO NOT USE THIS FOR ANYTHING EXCEPT TESTING!
        '''
        try:
            addy_len = _hash_len_lookup[algo]
        
        except (KeyError, TypeError):
            raise InvalidGhidAlgo(algo) from None
        
        return cls(
            algo = algo,
            address = bytes([random.randint(0, 255) for i in range(addy_len)])
        )
        
        
_dummy_ghid = Ghid.placeholder()
