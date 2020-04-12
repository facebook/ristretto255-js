Ristretto255.js
============

Ristretto255.js is a pure-JS implementation of the
[Ristretto255](https://ristretto.group/) group operations, built on top of the
popular [TweetNaCl.js](https://tweetnacl.js.org/#/) crypto library.


* [Overview](#overview)
* [Installation](#installation)
* [Usage](#usage)
* [System requirements](#system-requirements)
* [Development and testing](#development-and-testing)
* [Benchmarks](#benchmarks)

Overview
--------

This project gives a high-level javascript API for operations in the
[ristretto255](https://ristretto.group/) prime-order group. The ristretto255
group enjoys the speed and safety of Curve25519 while also being prime-order, so
that cryptographic protocols built on top of it will be resistant to [cofactor-related
attacks](https://ristretto.group/why_ristretto.html#pitfalls-of-a-cofactor).

Installation
--------

To install with the yarn package manager, simply run:

`yarn add ristretto255`

Usage
-----

The main files of this repository include:

* [ristretto255.js](./ristretto255.js) contains a well documented javascript code
  exporting function that provide operations over the prime-order group
  ristretto255 as well as operations over the scalars for that group,

* [ristretto255.min.js](./ristretto255.min.js) is the minified version of `ristretto255.js`
  identical to it in functionality; this file is ship-ready,

* [ristretto255.benchmarks.html](./ristretto255.benchmarks.html) shows an example of
  usage for all the exported functions. This file can be opened in the browser
  to run the benchmarks and check for browser compatibility.


This library exports the following types of arithmetic operations:

##### Operations over a prime order group (ristretto255) of order L

The inputs to all of the functions below should be valid ristretto255 points (which can
be checked by calling `ristretto255.isValid()`); otherwise, the behavior is
undefined, and functions may throw exceptions.

All ristretto255 elements are stored in the serialized format as 32-element
byte arrays of type `Uint8Array(32)`.

* `getRandom()`: returns a random point on ristretto255
* `isValid(P)`: returns `true` or `false`
* `fromHash(h)`: returns `P` instantiated from a `Uint8Array(64)` (such as the output
  of SHA512)
* `add(P, Q)`: returns `P + Q`
* `sub(P, Q)`: returns `P - Q`
* `scalarMultBase(x)`: returns `x * BASE`
* `scalarMult(x, P)`: returns `x * P`

##### Operations over scalars - big integers modulo L, where
`L = 2^252 + 27742317777372353535851937790883648493`.

Each scalar (a big integer modulo `L`) is of type `Float64Array(32)`. Each of the 32
elements is at most 8 bits (auxiliary bits are needed to accommodate overflows
during arithmetic operations).

Scalar operations implement simple school-book methods to optimize for a minimal
javascript binary size.

* `scalar.getRandom()`: returns a randomly generated scalar `mod L`
* `scalar.invert(x)`: returns `1/x mod L`
* `scalar.negate(x)`: returns `-x mod L`
* `scalar.add(x, y)`: returns `x + y mod L`
* `scalar.sub(x, y)`: returns `x - y mod L`
* `scalar.mul(x, y)`: returns `x * y mod L`

##### Unsafe operations over Edwards EC points

Unsafe operations give a way to use the ristretto255 group more efficiently, but
these APIs should be used with great care. To minimize security risks of
cryptographic protocols which use these operations, these EC (elliptic curve) points should
be serialized first with `toBytes()` before being stored on disk or transferred over the wire.

The format for the EC point is four coordinates: `[gf(), gf(), gf(), gf()]`, where each coordinate
`gf() = Float64Array(16)` is a 16-element array, where each element has 16 least significant bits used.

The ristretto technique gives a way to map ristretto255 group elements to
Edwards points (`fromBytes()`) and to convert a certain subset of Edwards points
back to ristretto255 group elements (`toBytes()`).

* `unsafe.point.alloc()`: allocated a placeholder for an EC point
* `unsafe.point.toBytes(P)`: converts an EC point `P` to a ristretto255 element (the conversion is well defined only for even EC points)
* `unsafe.point.fromBytes(P, E)`: converts a ristretto255 element `E` to an EC point `P`
* `unsafe.point.getRandom()`: generates a random EC point
* `unsafe.point.fromHash(h)`: generates an EC point from `h`, a 64-element byte array `Uint8Array(64)` such as an output of `SHA512`
* `unsafe.point.add(P, Q)`: adds two EC points `P` and `Q`
* `unsafe.point.sub(P, Q)`: subtracts two EC points `P` and `Q`
* `unsafe.point.scalarMultBase(Q, x)`: multiplies the base EC point by a scalar `x` and stores the result in `Q`
* `unsafe.point.scalarMult(Q, P, x)`: multiplies a given EC point `P` by a scalar `x` and stores the result in `Q`

Development and testing
------------------------

1. Clone this repository with `git clone`.

2. cd `ristretto255-js/`

3. To install the necessary dependencies, run `yarn`. (Note: Building this library requires node version >=6.9.0)

4. To build `ristretto255.min.js`, run `yarn build`.

5. To lint and test, run `yarn lint` and `yarn test`.


Benchmarks
----------

To run the benchmarks in a browser, open
[ristretto255.benchmarks.html](./ristretto255.benchmarks.html).
Here are the benchmarks from a MacBook Pro (15-inch, 2018) with 2.9 GHz Intel Core
i9:

| ristretto255 group        |              | scalar group              |              |
| ------------------------- |:------------:| ------------------------- |:------------:|
| getRandom                 | 0.48 ms      | scalar.getRandom          | 0.01 ms      |
| fromHash                  | 0.53 ms      | scalar.invert             | 2.60 ms      |
| add                       | 0.41 ms      | scalar.negate             | 0.01 ms      |
| sub                       | 0.41 ms      | scalar.add                | 0.02 ms      |
| scalarMultBase            | 3.47 ms      | scalar.sub                | 0.03 ms      |
| scalarMult                | 3.61 ms      | scalar.mul                | 0.01 ms      |

| UNSAFE - Edwards EC group      |              |
| ------------------------------ |:------------:|
| unsafe.point.toBytes           | 0.13 ms      |
| unsafe.point.fromBytes         | 0.13 ms      |
| unsafe.point.getRandom         | 0.26 ms      |
| unsafe.point.fromHash          | 0.27 ms      |
| unsafe.point.add               | 0.01 ms      |
| unsafe.point.sub               | 0.01 ms      |
| unsafe.point.scalarMultBase    | 3.30 ms      |
| unsafe.point.scalarMult        | 3.27 ms      |

System requirements
-------------------

We inherit the limitations of [TweetNaCl.js](https://tweetnacl.js.org/#/) and
support modern browsers that support the [Window.crypto
API](https://developer.mozilla.org/en-US/docs/Web/API/Window/crypto) and can
generate cryptographically secure random numbers (which can be checked
[here](https://caniuse.com/#feat=getrandomvalues)).

This code can also be run with Node.js.

Contributors
------------

The authors of this code are Valeria Nikolaenko
([@valerini](https://github.com/valerini)) and Kevin Lewi
([@kevinlewi](https://github.com/kevinlewi)).

###### Acknowledgments

Special thanks go to Kostas Chalkias ([@kchalkias](https://github.com/kchalkias)) and
David Wong ([@mimoo](https://github.com/mimoo))
for reviewing and giving feedback, Henry de Valence ([@hdevalence](https://github.com/hdevalence)) for
answering questions about ristretto255, Dmitry Chestnykh ([@dchest](https://github.com/dchest)) for
extending TweetNaCl.js to support this library, and Kyle Summers
([@KyleJSummers](https://github.com/KyleJSummers)) for recommending javascript build tooling.

### License
This project is [MIT licensed](./LICENSE).
