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


class GolixException(Exception):
    ''' Catchall for Golix problems.
    '''


class SecurityError(GolixException):
    ''' Raised when crypto operations fail.
    '''
    pass
    
    
class InvalidGhidAlgo(GolixException, ValueError):
    ''' Raised for improper address algorithms in Ghid.
    '''
    
    
class InvalidGhidAddress(GolixException, ValueError):
    ''' Raised for improper addresses in Ghid.
    '''
