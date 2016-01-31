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

DANGER DANGER DANGER: problem with PyCrypto on Windows. See:
http://stackoverflow.com/
    questions/24804829/another-one-about-pycrypto-and-paramiko
    
todo: transition this to a single crypto library.
'''

# Control * imports
__all__ = ['CIPHER_SUITES', 'ADDRESS_ALGOS', 'AddressAlgo1', 'CipherSuite1', 'CipherSuite2']

# Global dependencies
import io
import struct
import collections
import abc
import json
import base64
import os
from warnings import warn
import hashlib
# import Crypto
# import simpleubjson as ubj
# from Crypto.Random import random
# from Crypto.Hash import SHA256
# # hasher = SHA256.new()
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA as rsa2
from Crypto.Cipher import PKCS1_OAEP as oaep
from Crypto.Signature import pss

# def MGF1_SHA512(*args):
#     return PKCS1_PSS.MGF1(*args, hash=SHA512)


class _AddressAlgoBase(metaclass=abc.ABCMeta):
    pass
    
    
class AddressAlgo0(_AddressAlgoBase):
    ''' FOR TESTING PURPOSES ONLY. 
    
    Entirely inoperative. Correct API, but ignores all input, creating
    only a symbolic output.
    '''
    pass
    
    
class AddressAlgo1(_AddressAlgoBase):
    ''' SHA512
    '''
    pass


class _CipherSuiteBase(metaclass=abc.ABCMeta):
    ''' Abstract base class for all cipher suite objects.
    
    CipherSuite:
        def hasher              (data):
        def signer              (data, private_key):
        def verifier            (data, public_key, signature):
        def public_encryptor    (data, public_key):
        def private_decryptor   (data, private_key):
        def symmetric_encryptor (data, key):
        def symmetric_decryptor (data, key):
    '''    
    @staticmethod
    @abc.abstractmethod
    def hasher(data):
        ''' The hasher used for information addressing.
        '''
        pass
    
    @staticmethod
    @abc.abstractmethod
    def signer(data, private_key):
        ''' Placeholder signing method.
        
        Data must be bytes-like. Private key should be a dictionary 
        formatted with all necessary components for a private key (?).
        '''
        pass
        
    @staticmethod
    @abc.abstractmethod
    def verifier(data, public_key, signature):
        ''' Verifies an author's signature against bites. Errors out if 
        unsuccessful. Returns True if successful.
        
        Data must be bytes-like. public_key should be a dictionary 
        formatted with all necessary components for a public key (?).
        Signature must be bytes-like.
        '''
        pass
        
    @staticmethod
    @abc.abstractmethod
    def public_encryptor(data, public_key):
        ''' Placeholder asymmetric encryptor.
        
        Data should be bytes-like. Public key should be a dictionary 
        formatted with all necessary components for a public key.
        '''
        pass
        
    @staticmethod
    @abc.abstractmethod
    def private_decryptor(data, private_key):
        ''' Placeholder asymmetric decryptor.
        
        Data should be bytes-like. Public key should be a dictionary 
        formatted with all necessary components for a public key.
        '''
        pass
        
    @staticmethod
    @abc.abstractmethod
    def symmetric_encryptor(data, key):
        ''' Placeholder symmetric encryptor.
        
        Data should be bytes-like. Key should be bytes-like.
        '''
        pass
        
    @staticmethod
    @abc.abstractmethod
    def symmetric_decryptor(data, key):
        ''' Placeholder symmetric decryptor.
        
        Data should be bytes-like. Key should be bytes-like.
        '''
        pass
        
    @property
    def cipher_number(self):
        ''' Returns the cipher number.
        '''
        return self._CIPHER_NUMBER
        
        
class CipherSuite0(_CipherSuiteBase):
    ''' FOR TESTING PURPOSES ONLY. 
    
    Entirely inoperative. Correct API, but ignores all input, creating
    only a symbolic output.
    '''
    pass


class CipherSuite1(_CipherSuiteBase):
    ''' SHA512, AES256-SIV, RSA-4096, ECDH-C25519
    
    Generic, all-static-method class for cipher suite #1.
    '''
    @staticmethod
    def hasher(data):
        ''' Man, this bytes.'''
        # Create the hash. This may move to cryptography.io in the future.
        h = hashlib.sha512()
        # Give it the bytes
        h.update(data)

        # Finalize that shit and return
        return h.digest()
        
    @classmethod
    def signer(cls, data, private_key):
        pre_tuple = []
        
        # Extract the needed values and construct the private key
        pre_tuple.append(private_key['modulus']) # n
        pre_tuple.append(private_key['publicExponent']) # e
        pre_tuple.append(private_key['privateExponent']) # d
        # If missing primes, recover them.
        try:
            pre_tuple.extend(None, None)
            pre_tuple[3] = private_key['prime1']
            pre_tuple[4] = private_key['prime2']
        except KeyError:
            del pre_tuple[3], pre_tuple[4]
        # Should add CRT coefficient U in here, but maybe later
        if len(pre_tuple) > 3:
            try:
                pre_tuple.append(private_key['keyerror'])
            except KeyError:
                pass
        
        # Now generate the key.
        key = rsa2.construct(pre_tuple)
        
        # rsa2 stuff follows
        # key = rsa2.construct((n, e, d, p, q, u))
        # Build the signer using the MGF1 SHA512
        # eh, do this shit later
        # signer = PKCS1_PSS.new(key, MGF1_SHA512)
        # DOES PKCS1_PSS HASH INTERNALLY??
        
        # FILE MARKER
        # LEFT OFF HERE
        # OTHER SEARCH TERMS
        # HELLO
        # HASHTAG BADGER
        # Okay but seriously, this presents something of a problem that I'm not
        # entirely sure how to handle. In the future there may be multiple hashes -- 
        # I mean is the future really even relevant? -- but in the future there might
        # be multiple hashes and that would create a problem. Because this library doesn't
        # distinguish between signing hashes and signing data. It generates its own hash.
        # Wait a second, is that right? Is it actually hashing the data, or just using
        # the hash as a hash function generator? I mean, I'd assume the former, buuuut...
        
        digest = cls.hasher()
        
        signer = key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        signer.update(data)
        signature = signer.finalize()
        del signer, key, data, private_key, n, e, d, p, q, dmp1, dmq1, iqmp
        
        return signature

    @classmethod
    def verifier(cls, data, public_key, signature):
        ''' Verifies an author's signature against bites. Errors out if 
        unsuccessful. Returns True if successful.
        '''
        # pseudocode: return rsa2048verify(bites, pubkey, signature)
        # Extract needed values from the dictionary and create a public key
        n = public_key['modulus']
        e = public_key['publicExponent']
        pubkey = rsa.RSAPublicNumbers(e, n).public_key(cls.BACKEND)
        # Create the verifier
        verifier = pubkey.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        verifier.update(data)
        verifier.verify()
        # That will error out if bad. Might want to provide a custom, crypto
        # library-independed error to raise.
        
        # Success!
        return True

    @staticmethod
    def public_encryptor(data, public_key):
        # Extract needed values from the dictionary and create a public key
        n = public_key['modulus']
        e = public_key['publicExponent']
        pubkey = rsa2.construct((n, e))
        # Encrypt
        cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA512)
        return cipher.encrypt(data)

    @staticmethod
    def private_decryptor(data, private_key):
        ''' Implements the EICa standard to unencrypt the payload, then 
        immediately deletes the key.
        '''
        # These will always be present in the private_key. Not currently
        # bothering with the rest.
        n = private_key['modulus']
        e = private_key['publicExponent']
        d = private_key['privateExponent']
        q = private_key['prime1']
        p = private_key['prime2']
        iqmp = private_key['iqmp']
        
        # Construct the key.
        key = rsa2.construct((n, e, d, p, q, iqmp))
        
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA512)
        plaintext = cipher.decrypt(data)
        del private_key, cipher, n, e, d, key
        return plaintext
        
    @classmethod
    def symmetric_encryptor(cls, data, key):
        ''' Performs symmetric encryption of the supplied payload using 
        the supplied symmetric key.
        '''
        #self.check_symkey(sym_key)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), 
                        backend=cls.BACKEND)
        del key
        encryptor = cipher.encryptor()
        # Note that update returns value immediately, but finalize should (at 
        # least in CTR mode) return nothing.
        ct = encryptor.update(data) + encryptor.finalize()
        # Don't forget to prepend the nonce
        payload = nonce + ct
        # Delete these guys for some reassurrance
        del data, cipher, encryptor, nonce, ct
        return payload

    @classmethod
    def symmetric_decryptor(cls, data, key):
        ''' Performs symmetric decryption of the supplied payload using
        the supplied symmetric key.
        '''
        nonce = data[0:16]
        payload = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), 
                        backend=cls.BACKEND)
        del key
        decryptor = cipher.decryptor()
        payload = decryptor.update(payload) + decryptor.finalize()
        del decryptor, cipher, nonce
        return payload
        
        
class CipherSuite2(_CipherSuiteBase):
    ''' SHA512, AES256-CTR, RSA-4096, ECDH-C25519
    
    Generic, all-static-method class for cipher suite #1.
    '''
    pass
    
  
# Zero should be rendered inop, IE ignore all input data and generate
# symbolic representations
CIPHER_SUITES = {
    0: CipherSuite0,
    1: CipherSuite1,
    2: CipherSuite2
}

# Zero should be rendered inop, IE ignore all input data and generate
# symbolic representations
ADDRESS_ALGOS = {
    0: AddressAlgo0,
    1: AddressAlgo1
}