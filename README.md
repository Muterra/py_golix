py_golix
====

Golix: Python.

A python library for [Golix protocol](https://github.com/Muterra/doc-golix) objects that is in dire need of a complete rewrite.

[![Code Climate](https://codeclimate.com/github/Muterra/py_golix/badges/gpa.svg)](https://codeclimate.com/github/Muterra/py_golix)

# Notes

# Todo (no particular order)

+ DOCUMENTATION.
+ Ensure immutability of all objects that define ```__hash__```
+ Packed lowlevel objects should probably be immutable.
+ Reassess return API for receiving things as a FirstPersonID. Should it return a tuple, as it is right now, or not? Should the object return be different from the payload return? Unpacking extracts pretty much everything you can get that's not protected by crypto. **I think probably transition API to "unpack" for the object, "receive" for the content.** And then receive will always return a single item.
+ Change hash generation to use hash.update method, and then finally call a .finalize
+ Test vectors for all crypto operations
+ Need ThirdPartyID for servers
    + Cannot create anything
    + Has no keys
    + Copies most of the methods from FirstPartyID for unpacking, etc
    + Can also verify objects
+ Should EVERYONE verify the entire dynamic chain (particularly re: consistent author), or just servers? Probably everyone. Which means that needs to be added. Except, because that is a state preservation issue, that needs to be handled downstream.
+ Consider wrapping all parsing errors in SecurityError
+ Consider adding functionality to prevent access to attributes on ex. static bindings when loading a packed object until the object has been verified with receive_<object>.

## Done

+ ~~Make handling of GHID objects symmetric. AKA, convert loaded SmartyParseObjects into utils.Ghid objects.~~ That was unexpectedly straightforward.
+ ~~Move trashtest into _spec unit test file before substantial changes.~~ Might have broken since then though.