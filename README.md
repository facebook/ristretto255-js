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

This project gives a highlevel Javascript API for operations in [Ristretto255](https://ristretto.group/) prime-order group.
Ristretto255 group enjoys the speed and safety of Curve25519 while also being prime-order, so that cryptographic protocols using it not need to worry about the cofactor-related attacks.

There are multiple useful files in the repository:

* `ristretto.js` contains a well documented javascript code exporting function that provide operations over the prim-order group ristretto255 as well as operations over the scalars for that group,

* `ristretto.min.js` is a minified variant of `ristretto.js` identical to it in functionality, this file is ship-ready,

* `ristretto.benchmarks.html` shows an example of usage for all the exported functions, this file from whitin the cloned repo can be opened in the browser to check the speed and browser compatibility.

Installation
------------

Usage
-----

The implementation `ristretto.js` exports the following set of arithmetic operations.

##### Operations over scalars - big integers modulo L, where
`L = 2^252 + 27742317777372353535851937790883648493`.

Each scalar (a big integer mod L) is of type `Float64Array(32)`. Each of the 32 elements is at most 8 bits (auxiliary bits are needed to accommodate overflows during arithmetic operations).

Scalar operations implement simple school-book methods to achieve small javascript file size.

* **ristretto.scalar_random()**: returns a randomly generated scalar mod L
* **ristretto.scalar_add(x, y)**: returns x + y mod L
* **ristretto.scalar_sub(x, y)**: returns x - y mod L
* **ristretto.scalar_negate(x)**: returns -x mod L
* **ristretto.scalar_mul(x, y)**: returns x * y mod L
* **ristretto.scalar_invert(x)**: returns 1/x mod L

##### Operations over a prime order group (ristretto255) of order L

The inputs to all the functions should be valid ristretto255 elements (this can be checked with ristretto.is_valid_point() -> 0/1), otherwise the behavior is unpredicted and functions may throw exceptions.

All ristretto255 elements are stored in the serialized format as 32-elements byte arrays (of type Uint8Array(32)).

* **ristretto.is_valid(P)**: return 0 or 1
* **ristretto.from_hash(h)**: return P instantiated from Uint8Array(64) such as the output of SHA512
* **ristretto.random()**: returns a random element of ristretto255
* **ristretto.add(P, Q)**: return P + Q
* **ristretto.sub(P, Q)**: return P - Q
* **ristretto.scalarmult_base(x)**: return x * BASE
* **ristretto.scalarmult(x, P)**: return x * P

##### Unsafe operations over Edwards points

The ristretto group gives a way to map ristretto group elemenst to Edwards points (frombytes) and to convert a certain subset of Edwards points back to ristretto group elements (tobytes).

* **ristretto.unsafe.gf: creates a group element mod 2^255-19, stored as 'Float64Array(16)' with 16 least significant bits used
* **ristretto.unsafe.point_from_hash: instantiates a `[gf(), gf(), gf(), gf()]` point
* **ristretto.unsafe.tobytes: converts
* **nristretto.unsafe.frombytes = frombytes;
* **ristretto.unsafe.point_sub = lowlevel_sub;
* **ristretto.unsafe.point_add = lowlevel.add;
* **ristretto.unsafe.point_scalarmult_base = lowlevel.scalarbase;
* **ristretto.unsafe.point_scalarmult = lowlevel.scalarmult;
* **ristretto.unsafe.point_random = point_random;


System requirements
-------------------

We inherit the limitations of TweetNaCl.js and support modern browsers that support
window.crypto API and can generate cryptographically secure random numbers (which can be checked [here](https://caniuse.com/#feat=getrandomvalues)).

Our code can also be run with node.js

Development and testing
------------------------

Benchmarks
----------

Contributors
------------

### License
Ristretto255.js is [MIT licensed](./LICENSE).
