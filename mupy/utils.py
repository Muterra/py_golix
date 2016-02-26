'''
Cross-library utilities excluded from core.py or cipher.py to avoid 
circular imports.

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
import abc
from Crypto.Hash import SHA512


# ----------------------------------------------------------------------
# Misc objects


class SecurityError(RuntimeError):
    pass


class Muid():
    ''' Extremely lightweight class for MUIDs. Implements __hash__ to 
    allow it to be used as a dictionary key.
    '''
    __slots__ = ['algo', '_address']
    
    def __init__(self, algo, address):
        self.algo = algo
        self.address = address
        
    def __getitem__(self, item):
        return getattr(self, item)
        
    def __setitem__(self, item, value):
        setattr(self, item, value)
        
    def __hash__(self):
        address = self.address or b''
        condensed = int.to_bytes(self.algo, length=1, byteorder='big') + address
        return hash(condensed)
        
    def __eq__(self, other):
        try:
            return (self.algo == other.algo and self.address == other.address)
        except AttributeError as e:
            raise TypeError(
                'Cannot compare Muid objects to non-Muid-like objects.'
            ) from e
            
    @property
    def address(self):
        if self.algo == 0:
            return _dummy_address
        else:
            return self._address
            
    @address.setter
    def address(self, address):
        if self.algo == 0:
            pass
        else:
            self._address = address
    
    
class Secret():
    ''' All secrets have a key. Some have a nonce or IV (seed). All must 
    be able to be condensed into __bytes__. All must also be retrievable 
    from a bytes object.
    '''
    # We expect to have a lot of secrets, so let's add slots. Also, there's
    # a case to be made for discouraging people from using Secrets for
    # anything other than, well, secrets.
    __slots__ = ['_key', '_seed']
    
    def __init__(self, key, seed=None):
        if seed is None:
            seed = b''
            
        self._key = key
        self._seed = seed
    
    def __bytes__(self):
        raise NotImplementedError('Bytes representation not yet supported.')
       
    @property
    def key(self):
        return self._key
        
    @property
    def seed(self):
        return self._seed
        
    @classmethod
    def from_bytes(cls, data):
        raise NotImplementedError('Cannot yet load secrets from bytes.')


# ----------------------------------------------------------------------
# Mock objects for zeroth hash/ciphersuites

_dummy_address = b'[[ Start hash ' + (b'-' * 38) + b' End hash ]]'
_dummy_muid = Muid(0, _dummy_address)
_dummy_signature = b'[[ Start signature ' + (b'-' * 476) + b' End signature ]]'
_dummy_mac = b'[[ Start MAC ' + (b'-' * 40) + b' End MAC ]]'
_dummy_asym = b'[[ Start asymmetric payload ' + (b'-' * 458) + b' End asymmetric payload ]]'
_dummy_pubkey = b'[ ' + (b'-') * 21 + b' MOCK PUBLIC KEY ' + (b'-') * 22 + b' ]'

# ----------------------------------------------------------------------
# Address algorithms

class _AddressAlgoBase(metaclass=abc.ABCMeta):
    @classmethod
    def create(cls, data):
        ''' Creates an address (note: not the whole muid) from data.
        '''
        h = cls._HASH_ALGO.new(data)
        # Give it the bytes
        h.update(data)
        digest = bytes(h.digest())
        # So this isn't really making much of a difference, necessarily, but
        # it's good insurance against (accidental or malicious) length
        # extension problems.
        del h
        return digest
        
    @classmethod
    def verify(cls, address, data):
        ''' Verifies an address (note: not the whole muid) from data.
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
    ADDRESS_LENGTH = len(_dummy_address)
    
    @classmethod
    def create(cls, data):
        return _dummy_address
        
    @classmethod
    def verify(cls, address, data):
        return True
    
    
class AddressAlgo1(_AddressAlgoBase):
    ''' SHA512
    '''
    _HASH_ALGO = SHA512
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
    except KeyError as e:
        raise ValueError('Address algo "' + str(num) + '" is undefined.') from e