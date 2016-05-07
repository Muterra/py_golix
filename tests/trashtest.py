'''
Scratchpad for test-based development.

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

import sys
import collections

# These are normal imports
from golix import Ghid
from golix import ThirdParty
from golix import SecondParty
from golix import FirstParty

# ###############################################
# Testing
# ###############################################
    
def run():
    # Check this out!
    known_second_parties = {}
    # known_second_parties[fake_second_id.ghid] = fake_second_id
    
    server1 = ThirdParty()
    
    agent1 = FirstParty()
    agent2 = FirstParty()
    
    reader1 = agent1.second_party
    reader2 = agent2.second_party
    # Test loading from file
    packed_id = reader2.packed
    unpacked_id = server1.unpack_object(packed_id)
    
    reader2 = SecondParty.from_identity(unpacked_id)
    
    # import IPython
    # IPython.embed()
                
if __name__ == '__main__':
    run()