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

# Control * imports. Therefore controls what is available to toplevel
# package through __init__.py
__all__ = [
    'SecurityError', 
    'ParseError',
    'Guid', 
    'Secret',
    'FirstParty',
    'SecondParty',
    'ThirdParty',
    'firstparty_factory',
    'thirdparty_factory'
]

# Global dependencies
# import collections
from smartyparse import ParseError

# Inter-package dependencies that pass straight through to __all__
from .utils import Guid
from .utils import SecurityError
from .utils import Secret

# Inter-package dependencies that are only used locally
from .cipher import FirstParty1 as FirstParty
from .cipher import SecondParty1 as SecondParty
from .cipher import ThirdParty1 as ThirdParty

        
# ###############################################
# Utilities, etc
# ###############################################


from .cipher import DEFAULT_CIPHER

# Note that these will need to change their mapping value if the "import as"
# ever changes due to additional ciphersuites.
FIRST_PARTY_LOOKUP = {
    1: FirstParty
}
SECOND_PARTY_LOOKUP = {
    1: SecondParty
}
THIRD_PARTY_LOOKUP = {
    1: ThirdParty
}


def firstparty_factory(cipher='default', *args, **kwargs):
    ''' Generator for FirstParty objects based on cipher declaration.
    Behaves like a class, so it's being named like one.
    '''
    
    if cipher == 'default':
        cipher = DEFAULT_CIPHER
        
    try:
        cls = FIRST_PARTY_LOOKUP[cipher]
    except (KeyError, TypeError) as e:
        raise ValueError('Improper cipher declaration.') from e
        
    return cls(*args, **kwargs)


def thirdparty_factory(cipher='default', *args, **kwargs):
    ''' Generator for ThirdParty objects based on cipher declaration.
    Behaves like a class, so it's being named like one.
    '''
    
    if cipher == 'default':
        cipher = DEFAULT_CIPHER
        
    try:
        cls = THIRD_PARTY_LOOKUP[cipher]
    except (KeyError, TypeError) as e:
        raise ValueError('Improper cipher declaration.') from e
        
    return cls(*args, **kwargs)