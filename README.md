TweetNaCl-Ristretto.js
============

[Ristretto255](https://ristretto.group/) group operations added to TweetNaCl Javascript library
for modern browsers and Node.js.

Documentation
=============

* [Overview](#overview)
* [Installation](#installation)
* [Usage](#usage)
* [System requirements](#system-requirements)
* [Development and testing](#development-and-testing)
* [Benchmarks](#benchmarks)

Overview
--------

This project gives a highlevel API to do operations in ristretto255 prime-order group.
Ristretto255 group enjoys the speed and safety of Curve25519 while also being prime-order, so that cryptographic protocols using it may not worry about the cofactor-related attacks.

There are multiple useful files in the repository:

* `ristretto.js` contains a well documented javascript code exporting function that provide operations over the prim-order group ristretto255 as well as operations over the scalars for that group,

* `ristretto.min.js` contains a minified variant of `ristretto.js` identical to it in functionality and can be served to clients,

* `ristretto.benchmarks.html` shows an example of usage for all the exported functions, this file from whitin the cloned repo can be opened in the browser to check the speed and support for the functions.

Installation
------------

Examples
--------
`ristretto.benchmarks.html` shows an example of usage for all the exported functions.

Usage
-----

The implementation provides the following set of arithmetic operations.

##### Operations over scalars - big integers modulo L
L = 2^252 + 27742317777372353535851937790883648493.

Each scalar (a big integer mod L) is of type Float64Array(32). Each of the 32 elements is at most 8 bits (auxiliary bits are needed to accommodate overflows during arithmetic operations).

Scalar operations implement simple school-book methods to achieve small javascript file size.

* **ristretto.scalar_random()**: returns a randomly generated scalar mod L
* **ristretto.scalar_invert(x)**: returns 1/x mod L
* **ristretto.scalar_negate(x)**: returns -x mod L
* **ristretto.scalar_add(x, y)**: returns x + y mod L
* **ristretto.scalar_sub(x, y)**: returns x - y mod L
* **ristretto.scalar_mul(x, y)**: returns x * y mod L

##### Operations over a prime order group (ristretto255) of order L

The inputs to all the functions should be valid ristretto255 elements (this can be checked with ristretto.is_valid_point() -> 0/1), otherwise the behavior is unpredicted and functions may throw exceptions.

All ristretto255 elements are stored in the serialized format as 32-elements byte arrays (of type Uint8Array(32)).

* **ristretto.scalarmult_base(x)**: return x * BASE
* **ristretto.scalarmult(x, P)**: return x * P
* **ristretto.is_valid(P)**: return 0 or 1
* **ristretto.add(P, Q)**: return P + Q
* **ristretto.sub(P, Q)**: return P - Q
* **ristretto.from_hash(h)**: return P instantiated from Uint8Array(64) such as the output of SHA512
* **ristretto.random()**: returns a random element of ristretto255


System requirements
-------------------

We inherit the limitations of TweetNaCl.js and support modern browsers that support
window.crypto API (which can be checked here ).

TweetNaCl.js supports modern browsers that have a cryptographically secure
pseudorandom number generator and typed arrays, including the latest versions
of:

* Chrome
* Firefox
* Safari (Mac, iOS)
* Internet Explorer 11

Other systems:

* Node.js

Development and testing
------------------------

Benchmarks
----------

Contributors
------------

### License
Ristretto255.js is [MIT licensed](./LICENSE).
