'''
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

# Global dependencies
import struct
import abc
import collections

# Package dependencies
from .cipher import CIPHER_SUITES
from .cipher import ADDRESS_ALGOS

# ###############################################
# Parsers
# ###############################################


class _ParserBase(metaclass=abc.ABCMeta):
    LENGTH = None
    
    @staticmethod
    @abc.abstractmethod
    def load(data):
        ''' Loads raw bytes into python objects.
        '''
        pass
        
    @staticmethod
    @abc.abstractmethod
    def dump(obj):
        ''' Dumps python objects into raw bytes.
        '''
        # Note that the super() implementation here makes it possible for
        # children to support callables when parsing.
        # If a child parser wants to customize handling a callable, don't
        # call super(). Take extra care with callable classes.
        if callable(obj):
            return obj()
        else:
            return obj
        

class _ParseNeat(_ParserBase):
    ''' Class for no parsing necessary. Creates a bytes object from a 
    memoryview, and a memoryview from bytes.
    '''    
    @staticmethod
    def load(data):
        return bytes(data)
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        # This might be a good place for some type checking to fail quickly
        # if it's not bytes-like
        return memoryview(obj)
        
        
class _ParseMagic(_ParseNeat):
    LENGTH = 4
        

class _ParseINT8US(_ParserBase):
    ''' Parse an 8-bit unsigned integer.
    '''
    PACKER = struct.Struct('>B')
    LENGTH = PACKER.size
    
    @classmethod
    def load(cls, data):
        return cls.PACKER.unpack(data)[0]
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        return cls.PACKER.pack(obj)
        

class _ParseINT16US(_ParserBase):
    ''' Parse a 16-bit unsigned integer.
    '''
    PACKER = struct.Struct('>H')
    LENGTH = PACKER.size
    
    @classmethod
    def load(cls, data):
        return cls.PACKER.unpack(data)[0]
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        return cls.PACKER.pack(obj)
        

class _ParseINT32US(_ParserBase):
    ''' Parse a 32-bit unsigned integer.
    '''
    PACKER = struct.Struct('>I')
    LENGTH = PACKER.size
    
    @classmethod
    def load(cls, data):
        return cls.PACKER.unpack(data)[0]
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        return cls.PACKER.pack(obj)
        

class _ParseINT64US(_ParserBase):
    ''' Parse a 64-bit unsigned integer.
    '''
    PACKER = struct.Struct('>Q')
    LENGTH = PACKER.size
    
    @classmethod
    def load(cls, data):
        return cls.PACKER.unpack(data)[0]
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        return cls.PACKER.pack(obj)

 
class _ParseVersion(_ParseINT32US):
    ''' Packs and unpacks the appropriate 32-bit field for the version.
    
    Subclassed for clarity and future flexibility.
    '''
    pass


class _ParseCipher(_ParserBase):
    ''' Packs and unpacks the appropriate 8-bit field for the cipher.
    
    For packing, format input as the integer representation. 
    When loading, returns ciphersuite object.
    '''
    _PARSER = _ParseINT8US
    LENGTH = _PARSER.LENGTH
    
    @classmethod
    def load(cls, data):
        # # Check to see if it's the cipher number (already int).
        # if data in CIPHER_SUITES:
        #     cipher = cls.CIPHER_LOOKUP[data]
        # # Check to see if it's an actual cipher class.
        # elif data in cls.LOOKUP_CIPHER:
        #     cipher = data
        # # If not, try parsing it as bytes.
        # else:
        
        try:
            # Get the number
            cipher_num = cls._PARSER.load(data)
            # Convert it to the cipher.
            cipher = CIPHER_SUITES[cipher_num]
        except KeyError:
            raise TypeError('CipherSuite not supported: ' + repr(data))
        
        # Return whatever is left.
        return cipher
        
    @classmethod
    def dump(cls, obj):
        # Check if the cipher is a number and valid.
        if obj in CIPHER_SUITES:
            # It's the number.
            cipher_num = obj
        # Check if the cipher is (or subclasses) a valid ciphersuite
        # elif obj in cls.LOOKUP_CIPHER:
        #     cipher_num = cls.LOOKUP_CIPHER[obj]
        # Else can't pack it.
        else:
            raise ValueError('Improper cipher: ' + repr(obj))
            
        return cls._PARSER.dump(cipher_num)

        
class _ParseHashAlgo(_ParserBase):
    ''' Packs and unpacks the appropriate 8-bit field for the cipher.
    
    For packing, format input as the integer representation. 
    When loading, returns ciphersuite object.
    '''
    _PARSER = _ParseINT8US
    LENGTH = _PARSER.LENGTH
    
    @classmethod
    def load(cls, data):
        try:
            # Get the number
            addresser_num = cls._PARSER.load(data)
            # Convert it to the cipher.
            addresser = ADDRESS_ALGOS[addresser_num]
        except KeyError:
            raise TypeError('Address algorithm not supported: ' + repr(data))
        
        # Return whatever is left.
        return addresser
        
    @classmethod
    def dump(cls, obj):
        # Check if the cipher is a number and valid.
        if obj in ADDRESS_ALGOS:
            addresser_num = obj
        else:
            raise ValueError('Improper address algorithm: ' + repr(obj))
            
        return cls._PARSER.dump(addresser_num)
        

class _ParseMUID(_ParserBase):
    LENGTH = 66
    
    @classmethod
    def load(cls, data):
        # Quick and dirty.
        temp = bytes(data)
        if len(temp) != cls.LENGTH:
            raise ValueError('Muid of improper length.')
            
        # Convert an empty muid to None
        if temp == bytes(cls.LENGTH):
            temp = None
        
        # Return
        return temp
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        # Also quick and dirty.
        if obj == None:
            temp = bytes(cls.LENGTH)
        else:
            temp = bytes(obj)
        
        if len(temp) != cls.LENGTH:
            raise ValueError('Muid of improper length.')
            
        return temp
        
        
class _ParseSignature(_ParseNeat):
    LENGTH = 512

    
class _ParseKey(_ParseNeat):
    LENGTH = 32
    

class _ParseNone(_ParserBase):
    ''' Parses nothing. Load returns None, dump returns b''
    '''
    LENGTH = 0
    
    @classmethod
    def load(cls, data):
        return None
        
    @classmethod
    def dump(cls, obj):
        obj = super().dump(obj)
        return b''