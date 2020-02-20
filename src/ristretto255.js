/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * @fileoverview ristretto255.js file exports arithmetic for scalars (mod L) and
 *     for ristretto255 group elements
 *
 * * Scalars are stored as Uint8Array(32)s, and the operations implement simple
 *   school-book arithmetic (mod L), where L is a prime and L = 2^252 + l,
 *   with l = 27742317777372353535851937790883648493 = 3 * 610042537739 *
 *   15158679415041928064055629. The order of the base point (X, Y) is L.
 *   The exported functions give a set of available arithmetic operations:
 *     ristretto255.scalar.{getRandom, invert, negate, add, sub, mul}
 *
 * * ristretto255 group elements are stored as Uint8Array(32)s.
 *   See https://ristretto.group/ for a reference on the ristretto255 group design.
 *   The exported functions give a set of available arithmetic operations:
 *     ristretto255.{getRandom, isValid, fromHash, add, sub, scalarMultBase, scalarMult}
 *
 * * Field elements are stored as Float64Array(16) they are used for coordinates of
 *   elliptic curve (EC) points. The EC points hold internal representation of ristretto group elements.
 *   Operations over the field elements are done modulo 2^255 - 19.
 *
 * * EC points are stored as an array of four field elements for extended projective coordinates.
 *
 * IMPORTANT NOTES
 *
 * * Little-endian encoding is used everywhere: the 0x0A0B0C0D 32-bit integer
 *   will be stored as a Uint8Array([0D, 0C, 0B, 0A]) byte array.
 *
 * * Double 64 bits IEEE 754 - default format for a number in javascript.
 *     An integer in the range -(2^53 - 1) and 2^53 - 1 can be stored precisely!
 *     Number.isSafeInteger() can be used to check for that.
 *
 * * For binary operations, the number is implicitly converted to a signed
 *   32-bits integer, and numbers with more than 32 bits get their most significant
 *   bits discarded. Bitshifts preserve the sign, for example: (-9) >> 2 gives -3.
 *
 * * A note on random number generation:
 *     For most of the cryptographic protocols it is crucial to have a
 *     good source of randomness. This code uses tweetnacl's nacl.randomBytes function
 *     for generating random bytes. See this note:
 *       https://github.com/dchest/tweetnacl-js#random-bytes-generation
 *     for more information on the limitations and browser support for obtaining
 *     these random values.
 */
import nacl from 'tweetnacl';

const ristretto255 = {};

const { lowlevel } = nacl;

const gf1 = lowlevel.gf([1]);

function fe() {
  return [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
}

const basePoint = new Uint8Array([
  0xe2,
  0xf2,
  0xae,
  0x0a,
  0x6a,
  0xbc,
  0x4e,
  0x71,
  0xa8,
  0x84,
  0xa9,
  0x61,
  0xc5,
  0x00,
  0x51,
  0x5f,
  0x58,
  0xe3,
  0x0b,
  0x6a,
  0xa5,
  0x82,
  0xdd,
  0x8d,
  0xb6,
  0xa6,
  0x59,
  0x45,
  0xe0,
  0x8d,
  0x2d,
  0x76
]);

/* L - 2, this constant is used to compute the inverse */
const LSub2 = new Float64Array([
  0xeb,
  0xd3,
  0xf5,
  0x5c,
  0x1a,
  0x63,
  0x12,
  0x58,
  0xd6,
  0x9c,
  0xf7,
  0xa2,
  0xde,
  0xf9,
  0xde,
  0x14,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x0,
  0x10
]);

/**
 * Multiplication of two scalars: school-book multiplication
 *
 * @param {Uint8Array(32)} o output scalar: o := a * b mod L
 * @param {Uint8Array(32)} a input scalar
 * @param {Uint8Array(32)} b input scalar
 */
function MmodL(o, a, b) {
  const t = new Float64Array(64);

  // Simple "operand scanning" schoolbook multiplication in two nested loops.
  // Elements of the resulting t have the max number of bits represented
  // by this 64-elements vector:
  // [16, 17, 18, 18, 19, 19, 19, 19, 20, 20,
  //  20, 20, 20, 20, 20, 20, 21, 21, 21, 21,
  //  21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
  //  21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
  //  21, 21, 21, 21, 21, 21, 21, 20, 20, 20,
  //  20, 20, 20, 20, 20, 19, 19, 19, 19, 18,
  //  18, 17, 16, 0]
  for (let i = 0; i < 32; i++) {
    for (let j = 0; j < 32; j++) {
      t[i + j] += a[i] * b[j];
    }
  }

  // Reduce t mod L and write to o
  lowlevel.modL(o, t);
}

/**
 * Squaring of a scalar
 *
 * @param {Uint8Array(32)} o output scalar: o := a^2 mod L
 * @param {Uint8Array(32)} a input scalar
 */
function SmodL(o, a) {
  MmodL(o, a, a);
}

/**
 * Computing the inverse of a scalar: 1/r mod L == r^(L-2) mod L.
 * Here we implement the simplest method: one-bit square-and-multiply
 * ladder that requires 251 squarings and 72 multiplications.
 * A more efficient approach for inversion (also implemented in
 * curve25519-dalek) requires only 250 squarings and 34 multiplications
 * (https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion),
 * but the code will be more lengthy.
 *
 * @param {Uint8Array(32)} invX output scalar: invX := 1/x mod L
 * @param {Uint8Array(32)} x input scalar
 */
function invmodL(invX, x) {
  for (let i = 0; i < 32; i++) invX[i] = x[i];
  for (let i = 251; i >= 0; i--) {
    // squaring
    SmodL(invX, invX);
    // parsing the bits of the modulus
    // i & 0x07 == i % 8
    // i >> 3 == i / 8 (integer division)
    if (((LSub2[i >> 3] >> (i & 0x07)) & 1) !== 0) {
      // multiply by x
      MmodL(invX, invX, x);
    }
  }
}

/* Here a and d are the parameters of the curve: a = -1, d = -121665 / 121666 */
/* sqrt(-1) */
const sqrtm1 = lowlevel.gf([
  0xa0b0,
  0x4a0e,
  0x1b27,
  0xc4ee,
  0xe478,
  0xad2f,
  0x1806,
  0x2f43,
  0xd7a7,
  0x3dfb,
  0x0099,
  0x2b4d,
  0xdf0b,
  0x4fc1,
  0x2480,
  0x2b83
]);
/* sqrt(a * d - 1) */
const sqrtadm1 = lowlevel.gf([
  0x2e1b,
  0x497b,
  0xf6a0,
  0x7e97,
  0x54bd,
  0x1b78,
  0x8e0c,
  0xaf9d,
  0xd1fd,
  0x31f5,
  0xfcc9,
  0x0f3c,
  0x48ac,
  0x2b83,
  0x31bf,
  0x3769
]);
/* 1 / sqrt(a - d) */
const invsqrtamd = lowlevel.gf([
  0x40ea,
  0x805d,
  0xfdaa,
  0x99c8,
  0x72be,
  0x5a41,
  0x1617,
  0x9d2f,
  0xd840,
  0xfe01,
  0x7b91,
  0x16c2,
  0xfca2,
  0xcfaf,
  0x8905,
  0x786c
]);
/* (1-d^2) */
const onemsqd = lowlevel.gf([
  0xc176,
  0x945f,
  0x09c1,
  0xe27c,
  0x350f,
  0xcd5e,
  0xa138,
  0x2c81,
  0xdfe4,
  0xbe70,
  0xabdd,
  0x9994,
  0xe0d7,
  0xb2b3,
  0x72a8,
  0x0290
]);
/* (d-1)^2 */
const sqdmone = lowlevel.gf([
  0x4d20,
  0x44ed,
  0x5aaa,
  0x31ad,
  0x1999,
  0xb01e,
  0x4a2c,
  0xd29e,
  0x4eeb,
  0x529b,
  0xd32f,
  0x4cdc,
  0x2241,
  0xf66c,
  0xb37a,
  0x5968
]);

/**
 * Returns 1 iff the input field element (mod 2^255 - 19) is zero
 *
 * @param {Float64Array(16)} p input field element
 * @return {int} 1 iff p == 0
 */
function iszero25519(p) {
  // first pack the element which does a final reduction mod 2^255-19,
  // otherwise the element is stored mod 2^256-38 for convenience by nacl.js
  const s = new Uint8Array(32);
  lowlevel.pack25519(s, p);
  // do byte-by-byte comparison
  let res = 1;
  for (let i = 0; i < 32; i++) {
    res &= s[i] === 0;
  }
  return res;
}

/**
 * Conditional move of field elements (mod 2^255 - 19) based on b:
 * replace (p,q) with (q,q) if b == 1;
 * replace (p,q) with (p,q) if b == 0.
 *
 * @param {Float64Array(16)} p input/output field element: p == (b&1) * q + (1 - (b&1)) * p
 * @param {Float64Array(16)} q input field element
 * @param {int} b The integer in {0, 1}
 */
function cmov25519(p, q, b) {
  // if b = 1, c = 0xFFFFFFFF (32 bits);
  // else if b = 0, c = 0;
  // otherwise the behaviour is undefined
  let t;
  const c = -b;
  for (let i = 0; i < 16; i++) {
    t = p[i] ^ q[i];
    t &= c;
    p[i] ^= t;
  }
}

/**
 * Returns true if the input field element (mod 2^255 - 19) is negative.
 * By convention the element is negative is its least significant bit is 1.
 *
 * @param {Float64Array(16)} f input field element
 * @return 1 if f is in {1,3,5,...,q-2}; 0 if f is in {0,2,4,...,q-1}
 */
function isneg25519(f) {
  const s = new Uint8Array(32);
  lowlevel.pack25519(s, f);
  return s[0] & 1;
}

/**
 * Computes a negation of the input field element (mod 2^255-19)
 *
 * @param {Float64Array(16)} h output field element: h := (-f)
 * @param {Float64Array(16)} f input field element
 */
function neg25519(h, f) {
  lowlevel.Z(h, lowlevel.gf(), f);
}

/**
 * Conditional negation of the field element (mod 2^255-19) f written into h based on b:
 * replace (h,f) with (-f,f) if b == 1;
 * replace (h,f) with (f,f) if b == 0.
 *
 * @param {Float64Array(16)} h output field element
 * @param {Float64Array(16)} f input field element
 * @param {int} b input integer in {0, 1}
 */
function cneg25519(h, f, b) {
  const negf = lowlevel.gf();

  neg25519(negf, f);
  lowlevel.set25519(h, f);
  cmov25519(h, negf, b);
}

/**
 * Computes an absolute value of f field element (mod 2^255-19) and writes it into h: replace (h,f) with (|f|,f)
 *
 * @param {Float64Array(16)} h output field element
 * @param {Float64Array(16)} f input field element
 */
function abs25519(h, f) {
  cneg25519(h, f, isneg25519(f));
}

/**
 * Computes a square root of (u/v) and writes it into x
 * See https://ristretto.group/formulas/invsqrt.html
 *
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} x output EC point: x will contain the sqrt(u/v) or sqrt(i * u/v) whichever exists
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} u input EC point
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} v input ECpoint
 *
 * @return {int} 1 iff u/v was square, 0 otherwise
 */
function sqrtRatioM1(x, u, v) {
  const v3 = lowlevel.gf();
  const vxx = lowlevel.gf();
  const mRootCheck = lowlevel.gf();
  const pRootCheck = lowlevel.gf();
  const fRootCheck = lowlevel.gf();
  const xSqrtM1 = lowlevel.gf(); // gf elements

  lowlevel.S(v3, v);
  lowlevel.M(v3, v3, v); /* v3 = v^3 */

  lowlevel.S(x, v3);
  lowlevel.M(x, x, v);
  lowlevel.M(x, x, u); /* x = uv^7 */

  lowlevel.pow2523(x, x); /* x = (uv^7)^((q-5)/8), ((q-5)/8) = 2^252 - 3 */
  lowlevel.M(x, x, v3);
  lowlevel.M(x, x, u); /* x = uv^3(uv^7)^((q-5)/8) */

  lowlevel.S(vxx, x);
  lowlevel.M(vxx, vxx, v); /* vx^2 */

  lowlevel.Z(mRootCheck, vxx, u); /* vx^2-u */
  lowlevel.A(pRootCheck, vxx, u); /* vx^2+u */
  lowlevel.M(fRootCheck, u, sqrtm1); /* u*sqrt(-1) */
  lowlevel.A(fRootCheck, vxx, fRootCheck); /* vx^2+u*sqrt(-1) */
  const hasMRoot = iszero25519(mRootCheck); /* hasMRoot = (vxx == u) */
  const hasPRoot = iszero25519(pRootCheck); /* hasPRoot = (vxx == -u) */
  const hasFRoot = iszero25519(fRootCheck); /* hasFRoot = (vxx = -u*sqrt(-1)) */
  lowlevel.M(xSqrtM1, x, sqrtm1); /* x*sqrt(-1) */

  cmov25519(x, xSqrtM1, hasPRoot | hasFRoot);
  abs25519(x, x);

  return hasMRoot | hasPRoot;
}

/**
 * Serializes elliptic-curve point into a ristretto string
 * See https://ristretto.group/formulas/encoding.html
 *
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} h input EC point
 *
 * @return {Uint8Array(32)} byte array - the result of the serialization
 */
function toBytes(h) {
  /* h.X = h[0], h.Y = h[1], h.Z = h[2], h.T = h[3] */
  const den1 = lowlevel.gf();
  const den2 = lowlevel.gf();
  let denInv = lowlevel.gf();
  const eden = lowlevel.gf();
  const invSqrt = lowlevel.gf();
  const ix = lowlevel.gf();
  const iy = lowlevel.gf();
  const sVar = lowlevel.gf();
  const tZInv = lowlevel.gf();
  const u1 = lowlevel.gf();
  const u2 = lowlevel.gf();
  const u1U2U2 = lowlevel.gf();
  let xVar = lowlevel.gf();
  let yVar = lowlevel.gf();
  const xZInv = lowlevel.gf();
  const zInv = lowlevel.gf();
  const zmy = lowlevel.gf();
  let rotate = 0;
  const s = new Uint8Array(32);

  lowlevel.A(u1, h[2], h[1]); /* u1 = Z+Y */
  lowlevel.Z(zmy, h[2], h[1]); /* zmy = Z-Y */
  lowlevel.M(u1, u1, zmy); /* u1 = (Z+Y)*(Z-Y) */

  lowlevel.M(u2, h[0], h[1]); /* u2 = X*Y */

  lowlevel.S(u1U2U2, u2); /* u1U2U2 = u2^2 */
  lowlevel.M(u1U2U2, u1, u1U2U2); /* u1U2U2 = u1*u2^2 */

  sqrtRatioM1(invSqrt, gf1, u1U2U2);

  lowlevel.M(den1, invSqrt, u1); /* den1 = invSqrt*u1 */
  lowlevel.M(den2, invSqrt, u2); /* den2 = invSqrt*u2 */
  lowlevel.M(zInv, den1, den2); /* z_inv = den1*den2 */
  lowlevel.M(zInv, zInv, h[3]); /* z_inv = den1*den2*T */

  lowlevel.M(ix, h[0], sqrtm1); /* ix = X*sqrt(-1) */
  lowlevel.M(iy, h[1], sqrtm1); /* iy = Y*sqrt(-1) */
  lowlevel.M(eden, den1, invsqrtamd); /* eden = den1*sqrt(a-d) */

  lowlevel.M(tZInv, h[3], zInv); /* tZInv = T*z_inv */
  rotate = isneg25519(tZInv);

  xVar = lowlevel.gf(h[0]);
  yVar = lowlevel.gf(h[1]);
  denInv = lowlevel.gf(den2);

  cmov25519(xVar, iy, rotate);
  cmov25519(yVar, ix, rotate);
  cmov25519(denInv, eden, rotate);

  lowlevel.M(xZInv, xVar, zInv);
  cneg25519(yVar, yVar, isneg25519(xZInv));

  lowlevel.Z(sVar, h[2], yVar);
  lowlevel.M(sVar, denInv, sVar);
  abs25519(sVar, sVar);

  lowlevel.pack25519(s, sVar);
  return s;
}

/**
 * Check is the input byte array is a canonical encoding of a field element
 * by checking that the following holds:
 * a) s must be 32 bytes
 * b) s < p, where p = 2^255-19
 * c) s is nonnegative <=> (s[0] & 1) == 0
 * NB: A canonical ristretto255 group element is not guaranted to be valid (i.e.
 * fromBytes may still fail). Valid points are those for which fromBytes
 * succeeds.
 *
 * @param {Uint8Array(32)} s input byte array
 *
 * @return {int} 1 iff s represents a valid ristretto255 group element
 */
function isCanonical(s) {
  let c = (s[31] & 0x7f) ^ 0x7f;
  /* here c == 0 iff s[31] == 0x7f */
  for (let i = 30; i > 0; i--) {
    c |= s[i] ^ 0xff;
  }
  /* here c == 0 iff s = 0x7f 0xff 0xff ... 0xff 0x** */
  c = ((c | (0 >>> 0)) - 1) >> 8;
  /* here c & 1 == 1 iff s = 0x7f 0xff 0xff ... 0xff 0x** */
  const d = (0xed - 1 - (s[0] | (0 >>> 0))) >> 8;
  /* here d & 1 == 1 iff s[0] >= 0xed */
  /* here (c & d) & 1 == 1 iff 2^255-1 >= s >= 2^255-19 */
  return 1 - ((((c & d) | s[0]) & 1) | ((s[31] & 0xff) >> 7));
}

/**
 * Deserializes the byte array into an elliptic curve point.
 * See https://ristretto.group/formulas/decoding.html
 *
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} h output EC point
 * @param {Uint8Array(32)} s input byte array
 * @return {int} -1 on failure
 */
function fromBytes(h, s) {
  const invSqrt = lowlevel.gf();
  const one = lowlevel.gf();
  const sVar = lowlevel.gf();
  const ss = lowlevel.gf();
  const u1 = lowlevel.gf();
  const u2 = lowlevel.gf();
  const u1u1 = lowlevel.gf();
  const u2u2 = lowlevel.gf();
  const v = lowlevel.gf();
  const vU2U2 = lowlevel.gf();

  if (isCanonical(s) === 0) {
    return -1;
  }
  lowlevel.unpack25519(sVar, s);
  lowlevel.S(ss, sVar); /* ss = s^2 */

  lowlevel.set25519(u1, gf1); /* u1 = 1 */
  lowlevel.Z(u1, u1, ss); /* u1 = 1-ss */
  lowlevel.S(u1u1, u1); /* u1u1 = u1^2 */

  lowlevel.set25519(u2, gf1); /* u2 = 1 */
  lowlevel.A(u2, u2, ss); /* u2 = 1+ss */
  lowlevel.S(u2u2, u2); /* u2u2 = u2^2 */

  lowlevel.M(v, lowlevel.D, u1u1); /* v = d*u1^2 */
  neg25519(v, v); /* v = -d*u1^2 */
  lowlevel.Z(v, v, u2u2); /* v = -(d*u1^2)-u2^2 */

  lowlevel.M(vU2U2, v, u2u2); /* v_u2u2 = v*u2^2 */

  lowlevel.set25519(one, gf1); /* one = 1 */
  const wasSquare = sqrtRatioM1(invSqrt, one, vU2U2);
  lowlevel.M(h[0], invSqrt, u2);
  lowlevel.M(h[1], invSqrt, h[0]);
  lowlevel.M(h[1], h[1], v);

  lowlevel.M(h[0], h[0], sVar);
  lowlevel.A(h[0], h[0], h[0]);
  abs25519(h[0], h[0]);
  lowlevel.M(h[1], u1, h[1]);
  lowlevel.set25519(h[2], gf1); /* h->Z = 1 */
  lowlevel.M(h[3], h[0], h[1]);

  return -((1 - wasSquare) | isneg25519(h[3]) | iszero25519(h[1]));
}

/**
 * Helper function for fromHash: implements Elligator 2 to map a
 * field element to a curve point.
 * See https://ristretto.group/formulas/elligator.html
 * Note that simpler methods based on rejection sampling are difficult to
 * implement in constant time.
 *
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} p output EC point
 * @param {Float64Array(16)} t input field element
 * @return none
 */
function elligator(p, t) {
  const c = lowlevel.gf();
  const n = lowlevel.gf();
  const one = lowlevel.gf();
  const r = lowlevel.gf();
  const rpd = lowlevel.gf();
  const s = lowlevel.gf();
  const sPrime = lowlevel.gf();
  const ss = lowlevel.gf();
  const u = lowlevel.gf();
  const v = lowlevel.gf();
  const w0 = lowlevel.gf();
  const w1 = lowlevel.gf();
  const w2 = lowlevel.gf();
  const w3 = lowlevel.gf();

  lowlevel.set25519(one, gf1); /* one = 1 */
  lowlevel.S(r, t); /* r = t^2 */
  lowlevel.M(r, sqrtm1, r); /* r = sqrt(-1)*t^2 */
  lowlevel.A(u, r, one); /* u = r+1 = sqrt(-1)*t^2 + 1 */
  lowlevel.M(
    u,
    u,
    onemsqd
  ); /* u = (r+1)*(1-d^2) =  (sqrt(-1)*t^2 + 1) * (1-d^2) */
  lowlevel.set25519(c, gf1); /* c = 1 */
  neg25519(c, c); /* c = -1 */
  lowlevel.A(rpd, r, lowlevel.D); /* rpd = r*d */
  lowlevel.M(v, r, lowlevel.D); /* v = r*d */
  lowlevel.Z(v, c, v); /* v = c-r*d */
  lowlevel.M(v, v, rpd); /* v = (c-r*d)*(r+d) */

  const wasntSquare = 1 - sqrtRatioM1(s, u, v);
  lowlevel.M(sPrime, s, t);
  abs25519(sPrime, sPrime);
  neg25519(sPrime, sPrime); /* s_prime = -|s*t| */
  cmov25519(s, sPrime, wasntSquare);
  cmov25519(c, r, wasntSquare);

  lowlevel.Z(n, r, one); /* n = r-1 */
  lowlevel.M(n, n, c); /* n = c*(r-1) */
  lowlevel.M(n, n, sqdmone); /* n = c*(r-1)*(d-1)^2 */
  lowlevel.Z(n, n, v); /* n =  c*(r-1)*(d-1)^2-v */

  lowlevel.A(w0, s, s); /* w0 = 2s */
  lowlevel.M(w0, w0, v); /* w0 = 2s*v */
  lowlevel.M(w1, n, sqrtadm1); /* w1 = n*sqrt(ad-1) */
  lowlevel.S(ss, s); /* ss = s^2 */
  lowlevel.Z(w2, one, ss); /* w2 = 1-s^2 */
  lowlevel.A(w3, one, ss); /* w3 = 1+s^2 */

  lowlevel.M(p[0], w0, w3);
  lowlevel.M(p[1], w2, w1);
  lowlevel.M(p[2], w1, w3);
  lowlevel.M(p[3], w0, w2);
}

/**
 * Hash to ristretto255 group with Elligator.
 * This function can be used anywhere where a random oracle is required by
 * calling it with a 512-bits random bit-string h
 * (can be a SHA-512 hash of a 256-bits randomness source or an HKDF if
 * instantiated from a low-entropy message).
 * See https://ristretto.group/formulas/elligator.html
 * Note: for h of length 256 bits and p = 2^255-19, the value "h mod p"
 * has a slightly larger probability of being in [0, 37],
 *       than a uniformly random element mod p.
 *       To get a bias of at most 1/2^128, h should have at
 *       least ceil(log2(p)) + 128 bits = ceil((255 + 128)/8)*8 = 384 bits.
 *       For a small-length message HKDF can be used to expand and
 *       extract the element h.
 *       (see https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-05.txt)
 * The reason two base field points are being produced, then hashed and
 * added is the line of work that shows that f(h(m)) is not a random oracle
 * (where f is map_to_curve and h is a secure hash function like SHA)
 * because f is not surjective necessarily, therefore it might be easy to
 * distinguish f(h(m)) from a truly random point.
 *
 * See [BCIMRT10] for rational behind hashing to two points and adding them up:
 *            Brier, E., Coron, J., Icart, T., Madore, D., Randriam, H.,
 *            and M. Tibouchi, "Efficient Indifferentiable Hashing into
 *            Ordinary Elliptic Curves", In Advances in Cryptology -
 *            CRYPTO 2010, pages 237-254,
 *            <https://doi.org/10.1007/978-3-642-14623-7_13>
 *
 * See [FFSTV13] and [TK17] for the improved analysis over the previous paper:
 * [FFSTV13]  Farashahi, R., Fouque, P., Shparlinski, I., Tibouch, M.,
 *            and J. Voloch, "Indifferentiable deterministic hashing to
 *            elliptic and hyperelliptic curves", In Math. Comp. vol 82,
 *            pages 491-512, 2013,
 *            <https://doi.org/10.1090/S0025-5718-2012-02606-8>.
 * [TK17]     Tibouchi, M. and T. Kim, "Improved elliptic curve hashing
 *            and point representation", In Designs, Codes, and
 *            Cryptography, vol 82, pages 161-177,
 *            <https://doi.org/10.1007/s10623-016-0288-2>.
 *
 * @param {Uint8Array(64)} h input 64 elements byte array such as the output of SHA512
 * @return {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} EC point
 */
function pointFromHash(h) {
  const r0 = lowlevel.gf();
  const r1 = lowlevel.gf();
  const p0 = fe();
  const p1 = fe();

  lowlevel.unpack25519(r0, h.slice(0, 32));
  lowlevel.unpack25519(r1, h.slice(32, 64));
  elligator(p0, r0);
  elligator(p1, r1);

  lowlevel.add(p0, p1);
  return p0;
}

/**
 * Multiply base point by scalar
 *
 * @param {Uint8Array(32)} n input scalar
 * @return {Uint8Array(32)} ristretto255 group element
 */
function scalarMultBase(n) {
  const Q = fe();
  lowlevel.scalarbase(Q, n); // Q = BASE * n
  return toBytes(Q);
}

/**
 * Multiply given point by scalar
 *
 * @param {Uint8Array(32)} n input scalar
 * @param {Uint8Array(32)} p input ristretto255 group element
 * @return {Uint8Array(32)} ristretto255 group element (p * n)
 */
function scalarMult(n, p) {
  const P = fe();
  const Q = fe();

  if (fromBytes(P, p) !== 0) {
    throw new Error('Invalid argument');
  }
  lowlevel.scalarmult(Q, P, n); // Q = P * n
  return toBytes(Q);
}

/**
 * Checking if the input array of bytes represents a serialization of a
 * valid ristretto255 group element
 *
 * @param {Uint8Array(32)} p input byte array
 * @return {Boolean} true on success, false on failure
 */
function isValid(p) {
  const P = fe();
  if (fromBytes(P, p) === -1) {
    return false;
  }
  return true;
}

/**
 * Helper private deserialization function reused in add(p, q) and sub(p, q)
 *
 * @param {Uint8Array(32)} p input ristretto255 group element
 * @param {Uint8Array(32)} q input ristretto255 group element
 * @return {[Uint8Array(32), Uint8Array(32)]} two ristretto255 group elements
 */
function deserializePandQ(p, q) {
  const P = fe();
  const Q = fe();

  if (fromBytes(P, p) === -1) {
    throw new Error('Invalid argument');
  }
  if (fromBytes(Q, q) === -1) {
    throw new Error('Invalid argument');
  }
  return [P, Q];
}

/**
 * Adding two ristretto255 group elements
 *
 * @param {Uint8Array(32)} p input ristretto255 group element
 * @param {Uint8Array(32)} q input ristretto255 group element
 * @return {Uint8Array(32)} ristretto255 group element (p+q)
 */
function add(p, q) {
  const [P, Q] = deserializePandQ(p, q);
  lowlevel.add(P, Q); // P = P + Q
  return toBytes(P);
}

/**
 * Subtracting two EC points - this function is symmetric to lowlevel.add
 *
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} P input/output EC point: P := P - Q
 * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} Q input EC point
 * @return {Uint8Array(32)} ristretto255 group element (p+q)
 */
function lowlevelSub(P, Q) {
  // negate Q: -(x,y,z,t) = (-x, y, z, -t)
  const negQ3 = lowlevel.gf();
  neg25519(negQ3, Q[3]);
  const negQ0 = lowlevel.gf();
  neg25519(negQ0, Q[0]);
  const negQ = [negQ0, Q[1], Q[2], negQ3];
  lowlevel.add(P, negQ);
}

/**
 * Subtracting two ristretto255 group elements
 *
 * @param {Uint8Array(32)} p input ristretto255 group element
 * @param {Uint8Array(32)} q input ristretto255 group element
 * @return {Uint8Array(32)} ristretto255 group element (p-q)
 */
function sub(p, q) {
  const [P, Q] = deserializePandQ(p, q);
  lowlevelSub(P, Q); // P = P - Q
  return toBytes(P);
}

/**
 * Generate a random EC point that will serialize to a valid ristretto255 group element
 *
 * @return {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} EC point
 */
function getRandomPoint() {
  // create a random hash string
  const h = nacl.randomBytes(64);
  // let h = new Uint8Array(64);
  // lowlevel.randombytes(h, 64);
  return pointFromHash(h);
}

/**
 * Create and serialize a ristretto255 group element from a hash byte array
 *
 * @param {Uint8Array(64)} h input 64 elements byte array such as the output of SHA512
 * @return {Uint8Array(32)} ristretto255 group element
 */
function fromHash(h) {
  return toBytes(pointFromHash(h));
}

/**
 * Generate a random ristretto255 group element
 *
 * @param none
 * @return {Uint8Array(32)} ristretto255 group element
 */
function getRandom() {
  return toBytes(getRandomPoint());
}

/**
 * Generating a random scalar via rejection sampling
 *
 * @return {Uint8Array(32)} scalar
 */
function getRandomScalar() {
  let r = new Uint8Array(32);
  let c = 0;
  // rejection sampling loop with constant-time body
  do {
    r = nacl.randomBytes(32);
    // lowlevel.randombytes(r, 32);
    r[31] &= 0x1f;

    // constant-time check for r < L, if so break and return r
    let i = 32;
    let n = 1;
    do {
      i--;
      c |= ((r[i] - lowlevel.L[i]) >> 8) & n;
      n &= ((r[i] ^ lowlevel.L[i]) - 1) >> 8;
    } while (i !== 0);
  } while (c === 0);

  return r;
}

/**
 * Inverting a scalar
 *
 * @param {Uint8Array(32)} s input scalar
 * @return {Uint8Array(32)} output inverted scalar 1/s
 */
function invertScalar(s) {
  const res = new Uint8Array(32);
  invmodL(res, s);
  return res;
}

/**
 * Negating a scalar
 *
 * @param {Uint8Array(32)} s input scalar
 * @return {Uint8Array(32)} output scalar: (-s)
 */
function negateScalar(s) {
  const negS = new Float64Array(64);
  // neg_s := L - s
  for (let i = 0; i < 32; i++) {
    negS[i] = -s[i];
  }
  const o = new Uint8Array(32);
  lowlevel.modL(o, negS);
  return o;
}

/**
 * Adding two scalars
 *
 * @param {Uint8Array(32)} x input scalar
 * @param {Uint8Array(32)} y input scalar
 * @return {Uint8Array(32)} output scalar: x + y
 */
function addScalar(x, y) {
  const z = new Float64Array(64);
  for (let i = 0; i < 32; i++) {
    z[i] = x[i] + y[i];
  }
  const o = new Uint8Array(32);
  lowlevel.modL(o, z);
  return o;
}

/**
 * Subtracting two scalars
 *
 * @param {Uint8Array(32)} x input scalar
 * @param {Uint8Array(32)} y input scalar
 * @return {Uint8Array(32)} output scalar: x - y
 */
function subScalar(x, y) {
  return addScalar(x, negateScalar(y));
}

/**
 * Multiplying two scalars
 *
 * @param {Uint8Array(32)} x input scalar
 * @param {Uint8Array(32)} y input scalar
 * @return {Uint8Array(32)} output scalar: x * y
 */
function mulScalar(x, y) {
  const res = new Uint8Array(32);
  MmodL(res, x, y);
  return res;
}

/**
 * EXPORTS
 * High-level ristretto255 functions operate on ristretto255 group elements stored in Uint8Array(32).
 * Scalar functions (invertScalar, addScalar, etc.) operate on scalars mod L stored in Uint8Array(32).
 */
ristretto255.scalarMultBase = scalarMultBase;
ristretto255.scalarMult = scalarMult;
ristretto255.isValid = isValid;
ristretto255.add = add;
ristretto255.sub = sub;
ristretto255.fromHash = fromHash;
ristretto255.getRandom = getRandom;
ristretto255.basePoint = basePoint;

ristretto255.scalar = {};
ristretto255.scalar.getRandom = getRandomScalar;
ristretto255.scalar.invert = invertScalar;
ristretto255.scalar.negate = negateScalar;
ristretto255.scalar.add = addScalar;
ristretto255.scalar.sub = subScalar;
ristretto255.scalar.mul = mulScalar;

/* Unsafe functions are exposed mainly for benchmarking and testing purposes */
/* Exercise care if using these in any production environments */
ristretto255.unsafe = {};
ristretto255.unsafe.point = {};
ristretto255.unsafe.point.toBytes = toBytes;
ristretto255.unsafe.point.fromBytes = fromBytes;
ristretto255.unsafe.point.fromHash = pointFromHash;
ristretto255.unsafe.point.sub = lowlevelSub;
ristretto255.unsafe.point.add = lowlevel.add;
ristretto255.unsafe.point.scalarMultBase = lowlevel.scalarbase;
ristretto255.unsafe.point.scalarMult = lowlevel.scalarmult;
ristretto255.unsafe.point.getRandom = getRandomPoint;
ristretto255.unsafe.point.alloc = fe;

ristretto255.unsafe.constants = {};
ristretto255.unsafe.constants.LSub2 = LSub2;
ristretto255.unsafe.constants.sqrtm1 = sqrtm1;
ristretto255.unsafe.constants.sqrtadm1 = sqrtadm1;
ristretto255.unsafe.constants.invsqrtamd = invsqrtamd;
ristretto255.unsafe.constants.onemsqd = onemsqd;
ristretto255.unsafe.constants.sqdmone = sqdmone;

export default ristretto255;
