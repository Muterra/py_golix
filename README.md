py_golix
====

Golix: Python.

A python library for [Golix protocol](https://github.com/Muterra/doc-golix) objects. Not a full client implementation.

[![Code Climate](https://codeclimate.com/github/Muterra/py_golix/badges/gpa.svg)](https://codeclimate.com/github/Muterra/py_golix)

# Notes

### Why PyCryptoDome over cryptography.io?

I would much prefer to be using PyCA's cryptography.io project for my crypto backend, but currently I cannot.

These are reasons why the pycryptodome and cryptography.io projects are on more or less the same initial footing, with a slight advantage to cryptography.io:

+ Most of the complaints cryptography.io lists as their raison d'etre are also solved by PyCryptoDome:
    + PyPy, py3 support: **check**
    + Maintenance: **check**
    + Implementations vulnerable to side-channel attacks: based off pycrypto, so *maybe*, but I'm not qualified enough to comment here. However, our threat model is such that compromising the host machine is considered (basically) full compromise of the cryptosystem, so this is pushing outside the scope of py_golix, *at least for now*.
    + API improvements: Ehhhh, I have complaints, to be sure, but once I've started using it, it isn't that bad (for the most part).
    + Algorithm availability, ex GCM, HKDF: **check**
    + Introspectability / testability: somewhat unqualified to comment, largely because I haven't taken the time to verify, but pycryptodome does a lot of testing, so inclined to be optimistic here
    + Error-prone APIs: I haven't had an issue here
    + Bad defaults: conversations on the github repo with the primary dev behind pycryptodome indicate a reasonably intelligent amount of thought being put behind defaults.
+ That being said, cryptography.io *is* more mature, *is* more widely used, and *does* have a larger, and potentially-better-pedigreed list of maintainers
    + It's difficult for me to do due diligence on Legrandin, the maintainer of PyCryptoDome, because I have very little public info to go off of. I very much respect that, but I'm limited to then doing things like googling (his? I *think* Helder is a masculine name but I'm not sure) email address, username, and name. I've read a number of contributions and discussion threads from that, but beyond that I don't have a ton to go on.
    + The team behind cryptography.io is very well-respected.
+ Neither library supports 100% of the cryptographic primitives Golix needs to work
+ Both projects install easily from pip
+ Neither project has completed a third-party audit.

**However,** these problems *currently* tip the scales in support of PyCryptoDome:

+ **cryptography.io signing API doesn't appear to allow pre-generation of hashes to sign (critical).** This is "needed" for the GUID; even though we could appropriately slice the data and then pass it to be signed, we would have to repeat the hash generation process 
+ **cryptography.io doesn't support OAEP+MGF1+SHA512 (critical).** Yes, this is an extremely unusual construction, but the Golix standard has a STRONG desire to minimize the number of crypto primitives (including hash functions) necessary to support the standard. Maybe in the future that will change.
+ cryptography.io doesn't support SIV mode (note that SIV may be removed from Golix standard, though)
+ cryptography.io doesn't support scrypt
+ PyCryptoDome has fewer dependencies 
    + In particular, it doesn't rely upon openssl for cross-platform use
    + I believe cryptography.io is trying to move away from that, but it's causing me deployment issues already, just while experimenting with the two libraries.

And these metrics are unknown:

+ Less complexity = better maintainability, and especially given fewer dependencies, easier third-party audit if necessary
    + cryptography.io: 993229 SLOC as of 16 Feb 2016 (this is wholly inaccurate; it includes documentation)
    + PyCryptoDome: 300648 SLOC as of 16 Feb 2016 (this is wholly inaccurate; it includes documentation)
    + cryptography.io churn rate roughly 4x project SLOC
    + Pycryptodome churn rate roughly 2x project SLOC

# Todo

+ Create various bytes-like "plaintext" objects (in particular, a GEOC one) that have an attribute for the guid of the object
+ Change hash generation to use hash.update method, and then finally call a .finalize
+ Test vectors for all crypto operations

## Done

+ ~~Make handling of GUID objects symmetric. AKA, convert loaded SmartyParseObjects into utils.Guid objects.~~ That was unexpectedly straightforward.
+ ~~Move trashtest into _spec unit test file before substantial changes.~~ Might have broken since then though.