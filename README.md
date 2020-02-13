Ristretto255.js
============

Ristretto255.js is a pure-JS implementation of the
[Ristretto](https://ristretto.group/) group operations, built on top of the
popular [TweetNaCl.js](https://tweetnacl.js.org/#/) crypto library.

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

This project gives a high-level JavaScript API for operations in the
[ristretto255](https://ristretto.group/) prime-order group. The ristretto255
group enjoys the speed and safety of Curve25519 while also being prime-order, so
that cryptographic protocols using it not need to worry about  cofactor-related
attacks.

There are multiple useful files in the repository:

* [ristretto.js](./ristretto.js) contains a well documented javascript code
  exporting function that provide operations over the prime-order group
  ristretto255 as well as operations over the scalars for that group,

* [ristretto.min.js](./ristretto.min.js) is a minified variant of `ristretto.js`
  identical to it in functionality, this file is ship-ready,

* [ristretto.benchmarks.html](./ristretto.benchmarks.html) shows an example of
  usage for all the exported functions. This file can be opened in the browser
  to run the benchmarks and check for browser compatibility.

Installation
------------

`yarn add ristretto255`

Usage
-----

The implementation `ristretto.js` exports the following set of arithmetic
operations.

##### Operations over a prime order group (ristretto255) of order L

The inputs to all the functions should be valid ristretto255 elements (this can
be checked with ristretto.is_valid_point() -> 0/1), otherwise the behavior is
unpredicted and functions may throw exceptions.

All ristretto255 elements are stored in the serialized format as 32-elements
byte arrays (of type Uint8Array(32)).

* **is_valid(P)**: return 0 or 1
* **from_hash(h)**: return P instantiated from Uint8Array(64) such as the output
  of SHA512
* **random()**: returns a random element of ristretto255
* **add(P, Q)**: return P + Q
* **sub(P, Q)**: return P - Q
* **scalarmult_base(x)**: return x * BASE
* **scalarmult(x, P)**: return x * P

##### Operations over scalars - big integers modulo L, where
`L = 2^252 + 27742317777372353535851937790883648493`.

Each scalar (a big integer mod L) is of type `Float64Array(32)`. Each of the 32
elements is at most 8 bits (auxiliary bits are needed to accommodate overflows
during arithmetic operations).

Scalar operations implement simple school-book methods to achieve small
javascript file size.

* **scalar_random()**: returns a randomly generated scalar mod L
* **scalar_add(x, y)**: returns x + y mod L
* **scalar_sub(x, y)**: returns x - y mod L
* **scalar_negate(x)**: returns -x mod L
* **scalar_mul(x, y)**: returns x * y mod L
* **scalar_invert(x)**: returns 1/x mod L

##### Unsafe operations over Edwards EC points

Unsafe operations give a way to use the ristretto group more efficiently, but
these APIs should be used with great care. To guarantee security of
crypto-protocols the EC points stored on disk or transfered over the wire should
be serialized first with `tobytes`.

The format for the EC point (elliptic curve point) is four coordinates `[gf(),
gf(), gf(), gf()]`, where each coordinate `gf() = Float64Array(16)` is a 16
elements array, where each element has 16 least significant bits used.

The ristretto group gives a way to map ristretto group elemenst to Edwards
points (frombytes) and to convert a certain subset of Edwards points back to
ristretto group elements (tobytes).

* **unsafe.gf**: creates one zero coordinate, `[gf(), gf(), gf(), gf()]` will give an EC point type
* **unsafe.point_from_hash**: generates an EC point from a 64-elements byte array `Uint8Array(64)` such as an output of `SHA512`
* **unsafe.tobytes**: converts an EC point to a ristretto255 element (the conversion is well defined only for even EC points)
* **unsafe.frombytes**: converts a ristretto255 element to an EC point
* **unsafe.point_sub**: subtracts two EC points
* **unsafe.point_add**: adds two EC points
* **unsafe.point_scalarmult_base**: multiplies the base EC point by a scalar
* **unsafe.point_scalarmult**: multiplies a given EC point by a scaral
* **unsafe.point_random**: generates a random EC point


System requirements
-------------------

We inherit the limitations of [TweetNaCl.js](https://tweetnacl.js.org/#/) and
support modern browsers that support the [Window.crypto
API](https://developer.mozilla.org/en-US/docs/Web/API/Window/crypto) and can
generate cryptographically secure random numbers (which can be checked
[here](https://caniuse.com/#feat=getrandomvalues)).

This code can also be run with Node.js.

Development and testing
------------------------

Building this library requires node version >=6.9.0.

To install the necessary dependenices, run `yarn`.

To build `ristretto255.min.js`, run `yarn build`.

To test, run `yarn test`.


Benchmarks
----------

To run benchmarks in a browser open
[ristretto.benchmark.html](./ristretto.benchmark.html) in a browser.
Here are the benchmarks from MacBook Pro (15-inch, 2018) with 2.9 GHz Intel Core
i9:

| ristretto255 group        |              | scalar group              |              |
| ------------------------- |:------------:| ------------------------- |:------------:|
| random                    | 0.48 ms      | scalar_random             | 0.01 ms      |
| from_hash                 | 0.53 ms      | scalar_invert             | 2.60 ms      |
| add                       | 0.41 ms      | scalar_negate             | 0.01 ms      |
| sub                       | 0.41 ms      | scalar_add                | 0.02 ms      |
| scalarmult_base           | 3.47 ms      | scalar_sub                | 0.03 ms      |
| scalarmult                | 3.61 ms      | scalar_sub                | 0.03 ms      |
|                           |              | scalar_mul                | 0.01 ms      |

| UNSAFE - Edwards EC group |              |
| ------------------------- |:------------:|
| point_random              | 0.26 ms      |
| tobytes                   | 0.13 ms      |
| frombytes                 | 0.13 ms      |
| point_from_hash           | 0.27 ms      |
| point_add                 | 0.01 ms      |
| point_sub                 | 0.01 ms      |
| point_scalarmult_base     | 3.30 ms      |
| point_scalarmult          | 3.27 ms      |


Contributors
------------

The authors of this code are Valeria Nikolaenko
([valerini](https://github.com/valerini)) and Kevin Lewi
([kevinlewi](https://github.com/kevinlewi)).

### License
This project is [MIT licensed](./LICENSE).
