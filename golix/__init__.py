'''
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

# Add in core module
from .core import *

# Submodules
from . import _getlow
from . import _spec
from . import cipher
from . import utils


class HowIWantObjectsToWork:
    ''' The interface on all of this stuff currently sucks. I want it to
    be less shitty. This is how I want that to look.
    '''
    
    def __init__(self, ghid, version, cipher, body, etc):
        self.ghid = ghid
        self.version = version
        self.cipher = cipher
        self.etc = etc
        
    async def pack(self):
        return self._parser.pack()
        
    @classmethod
    async def unpack(cls, data):
        unpacked = self._parser.unpack()
        return cls(unpacked)
        
    async def hash(self):
        ''' Generate the ghid hash for the object by iterating over its
        parts.
        '''
    
    async def sign(self, identity):
        ''' Generate a signature for the object, where applicable, using
        the identity. Shortcut to self.signature = await identity.sign
        with various state checking and stuff.
        '''
        
    async def verify(self, identity):
        ''' The other half of the above.
        '''
        
        
class HowIWantCryptoToWork1:
    ''' The crypto interface on this stuff also currently sucks. I want
    it to be less shitty as well.
    '''
    CIPHER_IDENTIFIER = 1
    
    def __init__(self, secret_key_1, secret_key_2, secret_key_3):
        ''' Create a private identity.
        '''
    
    async def sign(self, ghid):
        ''' Sign a ghid.
        '''
        
        
class HowIWantCryptoToWork2:
    ''' The crypto interface on this stuff also currently sucks. I want
    it to be less shitty as well.
    '''
    CIPHER_IDENTIFIER = 1
    
    def __init__(self, public_key_1, public_key_2, public_key_3):
        ''' Create a public identity.
        '''
        
    async def verify(self, ghid, signature):
        '''
        '''
        
        
class HowIWantSecretsToWork:
    ''' Secrets can encrypt/decrypt objects.
    '''
    CIPHER_IDENTIFIER = 1
    
    def __init__(self, seed, key):
        ''' Identical to existing.
        '''
        
    async def encrypt(self, data):
        ''' Do the thing with the stuff.
        '''
        
    async def decrypt(self, data):
        ''' More of the stuff with the thing.
        '''
