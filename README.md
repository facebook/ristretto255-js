# tweetnacl-ristretto-js-private
(Private version of) TweetNacl Ristretto JS implementation.
The implementation provides the following set of arithmetic operations.

##### Operations over scalars - big integers modulo L
L = 2^252 + L_low, L is a prime, L_low is a 125 bits number, L_low = 27742317777372353535851937790883648493.

Each scalar (a big integer mod L) is of type Float64Array(32). Each of the 32 elements is at most 8 bits (auxiliary bits are needed to accommodate overflows during arithmetic operations).

Scalar operations implement simple school-book methods to achieve small javascript file size.

* **ristretto.crypto_core_ristretto255_scalar_random()**: returns a randomly generated scalar mod L
* **ristretto.crypto_core_ristretto255_scalar_invert(s)**: returns 1/s mod L
* **ristretto.crypto_core_ristretto255_scalar_negate(s)**: returns -s mod L
* **ristretto.crypto_core_ristretto255_scalar_add(x, y)**: returns x + y mod L
* **ristretto.crypto_core_ristretto255_scalar_sub(x, y)**: returns x - y mod L
* **ristretto.crypto_core_ristretto255_scalar_mul(x, y)**: returns x * y mod L

##### Operations over ristretto points

The inputs to all the functions should be valid ristretto points (this can be checked with crypto_core_ristretto255_is_valid_point() -> 0/1), otherwise the behavior is unpredicted and functions may throw exceptions.

All ristretto points are stored in the serialized format as 32-elements byte arrays (of type Uint8Array(32)).

* **ristretto.crypto_scalarmult_ristretto255_base(n)**: return n * BASE
* **ristretto.crypto_scalarmult_ristretto255(n, p)**: return n * p
* **ristretto.crypto_core_ristretto255_is_valid_point(p)**: return 0 or 1
* **ristretto.crypto_core_ristretto255_add(p, q)**: return p + q
* **ristretto.crypto_core_ristretto255_sub(p, q)**: return p - q
* **ristretto.crypto_core_ristretto255_from_hash(h)**: return p instantiated from Uint8Array(64) such as the output of SHA512
* **ristretto.crypto_core_ristretto255_random()**: returns a random ristretto point

#### Low-level functions for efficiency

For efficiency, the ristretto points should be kept as EC points for arithmetic operations and only be serialized for I/O. Each EC point is a 4-element array of gf elements, each gf element is of type Float64Array(16) with each element in range [0, 2^16), all operations on this number are done modulo 2^256 - 38 (when a gf number is transferred or written to disk, it gets moded 2^255-19 and packed to 32-elements byte array (w. pack25519)).

To create a placeholder for EC point:
`var P = [gf(), gf(), gf(), gf()];`

* **ristretto.ristretto255_random()**: generates an EC point corresponding to a random ristretto point
* **ristretto.ristretto255_from_hash(h)**: generates an EC point corresponding to a ristretto point instantiated from a Uint8Array(64) hash value (such as the output of SHA512)
* **ristretto.ristretto255_frombytes(h, s)**: returns -1 on failure, takes an s of type Uint8Array(32) and writes to h a corresponding EC point
* **ristretto.ristretto255_tobytes(h)**: takes an EC point h and outputs a serialized ristretto point of type Uint8Array(32)

The arithmetic operations on ristretto points in EC representation are as for usual EC points:

* **nacl.add(p, q)**: p := p + q
* **nacl.scalarmult(p, q, s)**: p := q * s (p, q - EC points, s - scalar)
* **nacl.scalarbase(p, s)**: p := BASE * s
* **ristretto.sub(P, Q)**: P := P - Q
