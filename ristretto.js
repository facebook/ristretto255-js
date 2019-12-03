(function(ristretto) {
  'use strict';

  var nacl = require('./nacl');
  var lowlevel = nacl.lowlevel;

  var gf1 = lowlevel.gf([1]);

  /*** Important notes:
   *** All encodings are LITTLE-ENDIAN
   ***/

  /***
   *** Scalar arithmetic (mod L) for operations in the exponent of elliptic curve points.
   *** The order of the curve is a prime L = 2^252 + 27742317777372353535851937790883648493, the part being added is 125 bits long.
   *** Constant L is defined in nacl.js.
   *** The function modL() is defined in nacl.js and reduces an element mod L.
   ***/

  /* L - 2 = 2^252 + 27742317777372353535851937790883648491 required to compute the inverse */
  var L_sub_2 = new Float64Array([
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
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x10,
  ]);

  /**
   * Function scalarmodL creates an array of 32 element Float64Array(32) for representing points mod L
   */
  var scalarmodL = function(init) {
    var i,
      r = new Float64Array(32);
    if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };

  /**
   * Constant scalars of type Float64Array(32)
   */
  var scalarmodL1 = scalarmodL([1]);

  /**
   * Multiplication of two scalars: school-book multiplication.
   *
   * @param {Float64Array(32)} a scalar mod L, each element of a should be at most 8 bits.
   * @param {Float64Array(32)} b scalar mod L, each element of b should be at most 8 bits.
   * @param {Float64Array(32)} o scalar mod L for result, each element of o will be at most 8 bits.
   */
  function MmodL(o, a, b) {
    var i,
      j,
      t = new Float64Array(64);
    for (i = 0; i < 64; i++) t[i] = 0;

    // Simple "operand scanning" schoolbook multiplication in two nested loops.
    // Elements of the resulting t have the max number of bits represented by this 64-elements vector:
    // [16, 17, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 20, 20, 20, 20, 20, 20, 20, 20, 19, 19, 19, 19, 18, 18, 17, 16, 0]
    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) {
        t[i + j] += a[i] * b[j];
      }
    }

    // To reduce elements of t to be less than 8 bits, we propagate the carry above 8 bits to the most significant bits,
    // The following python simulation of the process shows that in result of this operation all the elements will be of less than 8 bits
    // with no overflows
    // #               [0,             1,                  ..., 31,         32,         ..., 62,     63]
    // # upperbounds = [255*255=65025, 255*255*2 = 130050, ..., 255*255*32, 255*255*31, ..., 255*255, 0]
    //
    // upperbounds = []
    // i = 0
    // while i <= 31:
    //   upperbounds.append(255*255*(i+1))
    //   i += 1
    // while i <= 62:
    //   upperbounds.append(255*255*(63 - i))
    //   i += 1
    // upperbounds.append(0)
    //
    // # simulating the reduction
    // i = 1
    // while i < 64:
    //     # check that addition does not overflows: the result will always be at most 22 bits
    //     assert upperbounds[i].bit_length() <= 21
    //     assert (upperbounds[i-1] >> 8).bit_length() <= 21
    //    upperbounds[i] += upperbounds[i-1] >> 8
    //    i += 1
    //
    // # the carry in the 63-rd element is at most 255, so exactly 8 bits:
    // print("the highest carry is {}".format(upperbounds[63]))      
    var carry = 0;
    for (j = 0; j < 64; j++) {
      t[j] += carry;
      carry = t[j] >> 8;
      t[j] &= 255;
    }

    // Reduce t mod L and write to o
    lowlevel.modL(o, t);
  }

  /**
   * Squaring of a scalar
   *
   * @param {Float64Array(32)} a scalar mod L, each element of a should be at most 8 bits.
   * @param {Float64Array(32)} 0 scalar mod L for result, each element of o will be at most 8 bits.
   */
  function SmodL(o, a) {
    MmodL(o, a, a);
  }

  /**
   * Computing the inverse of a scalar.
   * Due to Fermat's little theorem computing 1/r mod L  is equivalent to  r^(L-2) mod L.
   * Here we implement the simplest method: one-bit square-and-multiply ladder that requires 251 squarings and 72 multiplications.
   * A more efficient approach for inversion (also implemented in curve25519-dalek) requires only 250 squarings and 34 multiplications
   * (see https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion), but the code will be more lengthy.
   *
   * @param {Float64Array(32)} x scalar mod L, each element of x should be at most 8 bits.
   * @param {Float64Array(32)} inv_x scalar mod L for result, each element of inv_x should be at most 8 bits.
   */
  function invmodL(inv_x, x) {
    var tmp = new Float64Array(32);
    var i;
    for (i = 0; i < 32; i++) tmp[i] = x[i];
    for (i = 251; i >= 0; i--) {
      // parsing the bits of the modulus
      SmodL(tmp, tmp);
      if (((L_sub_2[i >> 3] >>> (i & 0x07)) & 1) !== 0) {
        // multiply by x
        MmodL(tmp, tmp, x);
      }
    }
    for (i = 0; i < 32; i++) inv_x[i] = tmp[i];
  }

  /***
   *** Ristretto functions
   *** See https://ristretto.group/ for a full specification and references.
   *** Ristretto group operates over elliptic curve Ed25519 points, where Ed25510 is a twisted Edwards curve: -x^2 + y^2 = 1 - 121665 / 121666 * x^2 * y^2
   *** The Ed25519 points are represented in extended twisted edwards projective coordinates (https://eprint.iacr.org/2008/522.pdf, page 6):
   ***   each point consists of four field elements (x, y, z, t), where t := xy/z
   *** To move to extended: (x, y, t) -> (x, y, 1, t)
   *** Scalar multiplication: a * (x,y,z,t) = (ax,ay,az,at)
   *** The identity element: (0, 1, 0, 1)
   *** Negation -(x,y,z,t) = (-x, y, z, -t)
   *** Conversion to/from projective: (x,y,z) -> (xz, yz, z^2, xy); (x,y,z,t) -> (x,y,z) simply ignores t
   *** NACL provides addition function (add) and scalar multiplication (scalarmult) for elliptic curve points.
   ***
   *** Each curve point P is represented with an array of four elements: P = [Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)], where P.X = P[0], P.Y = P[1], P.Z = P[2], P.T = P[3].
   ***/

  /* Here a and d are the parameters of the curve: a = -1, d = -121665 / 121666 */
  var sqrtm1 = lowlevel.gf([
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
      0x2b83,
    ]) /* sqrt(-1) */,
    sqrtadm1 = lowlevel.gf([
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
      0x3769,
    ]) /* sqrt(a * d - 1) */,
    invsqrtamd = lowlevel.gf([
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
      0x786c,
    ]) /* 1 / sqrt(a - d) */,
    onemsqd = lowlevel.gf([
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
      0x0290,
    ]) /* (1-d^2) */,
    sqdmone = lowlevel.gf([
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
      0x5968,
    ]); /* (d-1)^2 */

  /**
   * Returns 1 iff the input field element is zero
   *
   * @param {Float64Array(16)} p - the field element (mod 2^255 - 19).
   * @return {int} 1 iff p == 0.
   */
  function iszero25519(p) {
    // first pack the element which does a final reduction mod 2^255-19,
    // otherwise the element is stored mod 2^256-38 for convenience by nacl
    var s = new Uint8Array(32);
    lowlevel.pack25519(s, p);
    // do byte-by-byte comaprison
    var res = 1;
    for (var i = 0; i < 32; i++) {
      res &= s[i] == 0;
    }
    return res;
  }

  /**
   * Conditional move of q field element into p field element based on b:
   * replace (p,q) with (q,q) if b == 1;
   * replace (p,q) with (p,q) if b == 0.
   *
   * @param {Float64Array(16)} p - the field element (mod 2^255 - 19).
   * @param {Float64Array(16)} q - the input/output field element (mod 2^255 - 19).
   * @param {int} b The integer in {0, 1}.
   */
  function cmov25519(p, q, b) {
    // if b = 1, c = 0xFFFFFFFF (32 bits); else if b = 0, c = 0; otherwise the behavious is undefined
    var t,
      c = -b;
    for (var i = 0; i < 16; i++) {
      t = p[i] ^ q[i];
      t &= c;
      p[i] ^= t;
    }
  }

  /**
   * Returns true if the input field element is negative.
   * By convention the element is negative is its least significant bit is 1.
   *
   * @param {Float64Array(16)} f - the field element (mod 2^255 - 19).
   * @return 1 if f is in {1,3,5,...,q-2}; 0 if f is in {0,2,4,...,q-1}
   */
  function isneg25519(f) {
    var s = new Uint8Array(32);
    lowlevel.pack25519(s, f);
    return s[0] & 1;
  }

  /**
   * Computes a negation of the input field element.
   *
   * @param {Float64Array(16)} f - the field element (mod 2^255 - 19).
   * @param {Float64Array(16)} h = (-f) - the output field element (mod 2^255 - 19).
   */
  function neg25519(h, f) {
    lowlevel.Z(h, lowlevel.gf(), f);
  }

  /**
   * Conditional negation of the field element f written into h based on b:
   * replace (h,f) with (-f,f) if b == 1;
   * replace (h,f) with (f,f) if b == 0.
   *
   * @param {Float64Array(16)} f - the field element (mod 2^255 - 19).
   * @param {Float64Array(16)} h - the field element (mod 2^255 - 19).
   * @param {int} b The integer in {0, 1}.
   */
  function cneg25519(h, f, b) {
    var negf = lowlevel.gf();

    neg25519(negf, f);
    lowlevel.set25519(h, f);
    cmov25519(h, negf, b);
  }

  /**
   * Computes an absolute value of f and writes it into h: replace (h,f) with (|f|,f)
   *
   * @param {Float64Array(16)} f - the field element (mod 2^255 - 19).
   * @param {Float64Array(16)} h - the field element (mod 2^255 - 19).
   */
  function abs25519(h, f) {
    cneg25519(h, f, isneg25519(f));
  }

  /**
   * Computes an square root of (u/v) and writes it into x
   * See https://ristretto.group/formulas/invsqrt.html
   *
   * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} u - the Ed25519 elliptic-curve point.
   * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} v - the Ed25519 elliptic-curve point.
   * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} x - the Ed25519 elliptic-curve point, which will contain the sqrt(u/v) or sqrt(i * u/v) whichever exists.
   *
   * @return {int} 1 iff u/v was square, 0 otherwise
   */
  function ristretto255_sqrt_ratio_m1(x, u, v) {
    var v3 = lowlevel.gf(),
      vxx = lowlevel.gf(),
      m_root_check = lowlevel.gf(),
      p_root_check = lowlevel.gf(),
      f_root_check = lowlevel.gf(),
      x_sqrtm1 = lowlevel.gf(); // gf elements
    var has_m_root, has_p_root, has_f_root; // booleans

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

    lowlevel.Z(m_root_check, vxx, u); /* vx^2-u */
    lowlevel.A(p_root_check, vxx, u); /* vx^2+u */
    lowlevel.M(f_root_check, u, sqrtm1); /* u*sqrt(-1) */
    lowlevel.A(f_root_check, vxx, f_root_check); /* vx^2+u*sqrt(-1) */
    has_m_root = iszero25519(m_root_check); /* has_m_root = (vxx == u) */
    has_p_root = iszero25519(p_root_check); /* has_p_root = (vxx == -u) */
    has_f_root = iszero25519(f_root_check); /* has_f_root = (vxx = -u*sqrt(-1)) */
    lowlevel.M(x_sqrtm1, x, sqrtm1); /* x*sqrt(-1) */

    cmov25519(x, x_sqrtm1, has_p_root | has_f_root);
    abs25519(x, x);

    return has_m_root | has_p_root;
  }

  /**
   * Serializes elliptic-curve point in a ristretto string
   * See https://ristretto.group/formulas/encoding.html
   *
   * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} h - the Ed25519 elliptic-curve point.
   *
   * @return {Uint8Array(32)} byte array - the result of the serialization.
   */
  function ristretto255_tobytes(h) {
    /* h.X = h[0], h.Y = h[1], h.Z = h[2], h.T = h[3] */
    var den1 = lowlevel.gf(),
      den2 = lowlevel.gf();
    var den_inv = lowlevel.gf();
    var eden = lowlevel.gf();
    var inv_sqrt = lowlevel.gf();
    var ix = lowlevel.gf(),
      iy = lowlevel.gf();
    var one = lowlevel.gf();
    var s_ = lowlevel.gf();
    var t_z_inv = lowlevel.gf();
    var u1 = lowlevel.gf(),
      u2 = lowlevel.gf();
    var u1_u2u2 = lowlevel.gf();
    var x_ = lowlevel.gf(),
      y_ = lowlevel.gf();
    var x_z_inv = lowlevel.gf();
    var z_inv = lowlevel.gf();
    var zmy = lowlevel.gf();
    var res = 0;
    var rotate = 0;
    var s = new Uint8Array(32);

    lowlevel.A(u1, h[2], h[1]); /* u1 = Z+Y */
    lowlevel.Z(zmy, h[2], h[1]); /* zmy = Z-Y */
    lowlevel.M(u1, u1, zmy); /* u1 = (Z+Y)*(Z-Y) */

    lowlevel.M(u2, h[0], h[1]); /* u2 = X*Y */

    lowlevel.S(u1_u2u2, u2); /* u1_u2u2 = u2^2 */
    lowlevel.M(u1_u2u2, u1, u1_u2u2); /* u1_u2u2 = u1*u2^2 */

    ristretto255_sqrt_ratio_m1(inv_sqrt, gf1, u1_u2u2);

    lowlevel.M(den1, inv_sqrt, u1); /* den1 = inv_sqrt*u1 */
    lowlevel.M(den2, inv_sqrt, u2); /* den2 = inv_sqrt*u2 */
    lowlevel.M(z_inv, den1, den2); /* z_inv = den1*den2 */
    lowlevel.M(z_inv, z_inv, h[3]); /* z_inv = den1*den2*T */

    lowlevel.M(ix, h[0], sqrtm1); /* ix = X*sqrt(-1) */
    lowlevel.M(iy, h[1], sqrtm1); /* iy = Y*sqrt(-1) */
    lowlevel.M(eden, den1, invsqrtamd); /* eden = den1*sqrt(a-d) */

    lowlevel.M(t_z_inv, h[3], z_inv); /* t_z_inv = T*z_inv */
    rotate = isneg25519(t_z_inv);

    x_ = lowlevel.gf(h[0]);
    y_ = lowlevel.gf(h[1]);
    den_inv = lowlevel.gf(den2);

    cmov25519(x_, iy, rotate);
    cmov25519(y_, ix, rotate);
    cmov25519(den_inv, eden, rotate);

    lowlevel.M(x_z_inv, x_, z_inv);
    cneg25519(y_, y_, isneg25519(x_z_inv));

    lowlevel.Z(s_, h[2], y_);
    lowlevel.M(s_, den_inv, s_);
    abs25519(s_, s_);

    lowlevel.pack25519(s, s_);
    return s;
  }

  /**
   * Check is the input byte array is a canonical encoding of a field element by checking that the following holds:
   * a) s must be 32 bytes
   * b) s < p : either the most significant bit is 0 (s[31] & 0xc0 == 0)
   * c) s is nonnegative <=> (s[0] & 1) == 0
   * The field modulus is 2^255 - 19 which is in binary 0111 1111 ... all ones ... 1110 1101 = 0x7f 0xff ... 0xff ... 0xff 0xed
   *
   * @param {Uint8Array(32)} s byte array - the result of the serialization.
   *
   * @return {int} 1 iff s represents a valid ristretto point.
   */
  function ristretto255_is_canonical(s) {
    var c;
    var d;
    var i;

    c = (s[31] & 0x7f) ^ 0x7f;
    for (i = 30; i > 0; i--) {
      c |= s[i] ^ 0xff;
    }
    c =
      ((c | (0 >>> 0)) - 1) >>
      8; /* c & 1 == 1 iff s = 0x7f 0xff 0xff ... 0xff 0x** */
    d =
      (0xed - 1 - (s[0] | (0 >>> 0))) >>
      8; /* d & 1 == 1   iff   s[0] >= 0xed */

    return 1 - (((c & d) | s[0]) & 1); /* (c & d) & 1 == 1 iff s >= 2^255-19 */
  }

  /**
   * Deserializes the byte array into an elliptic curve point.
   * See https://ristretto.group/formulas/decoding.html
   *
   * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} h - the resulting Ed25519 elliptic-curve point.
   * @param {Uint8Array(32)} s byte array - the string for deserialization.
   * @return {int} -1 on failure.
   */
  function ristretto255_frombytes(h, s) {
    var inv_sqrt = lowlevel.gf(),
      one = lowlevel.gf(),
      s_ = lowlevel.gf(),
      ss = lowlevel.gf(),
      u1 = lowlevel.gf(),
      u2 = lowlevel.gf(),
      u1u1 = lowlevel.gf(),
      u2u2 = lowlevel.gf(),
      v = lowlevel.gf(),
      v_u2u2 = lowlevel.gf();
    var was_square;

    if (ristretto255_is_canonical(s) == 0) {
      return -1;
    }
    lowlevel.unpack25519(s_, s);
    lowlevel.S(ss, s_); /* ss = s^2 */

    lowlevel.set25519(u1, gf1); /* u1 = 1 */
    lowlevel.Z(u1, u1, ss); /* u1 = 1-ss */
    lowlevel.S(u1u1, u1); /* u1u1 = u1^2 */

    lowlevel.set25519(u2, gf1); /* u2 = 1 */
    lowlevel.A(u2, u2, ss); /* u2 = 1+ss */
    lowlevel.S(u2u2, u2); /* u2u2 = u2^2 */

    lowlevel.M(v, lowlevel.D, u1u1); /* v = d*u1^2 */
    neg25519(v, v); /* v = -d*u1^2 */
    lowlevel.Z(v, v, u2u2); /* v = -(d*u1^2)-u2^2 */

    lowlevel.M(v_u2u2, v, u2u2); /* v_u2u2 = v*u2^2 */

    lowlevel.set25519(one, gf1); /* one = 1 */
    was_square = ristretto255_sqrt_ratio_m1(inv_sqrt, one, v_u2u2);
    lowlevel.M(h[0], inv_sqrt, u2);
    lowlevel.M(h[1], inv_sqrt, h[0]);
    lowlevel.M(h[1], h[1], v);

    lowlevel.M(h[0], h[0], s_);
    lowlevel.A(h[0], h[0], h[0]);
    abs25519(h[0], h[0]);
    lowlevel.M(h[1], u1, h[1]);
    lowlevel.set25519(h[2], gf1); /* h->Z = 1 */
    lowlevel.M(h[3], h[0], h[1]);

    return -((1 - was_square) | isneg25519(h[3]) | iszero25519(h[1]));
  }

  /**
   * Helper function for ristretto255_from_hash: implements Elligator 2 to map a field element to a curve point.
   * See https://ristretto.group/formulas/elligator.html
   * Note that simpler methods based on rejection sampling are difficult to implement in constant time.
   *
   * @param {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} p - the resulting Ed25519 elliptic-curve point.
   * @param {Float64Array(16)} t - a field element.
   * @return {int} -1 on failure.
   */
  function ristretto255_elligator(p, t) {
    var c = lowlevel.gf(),
      n = lowlevel.gf(),
      one = lowlevel.gf(),
      r = lowlevel.gf(),
      rpd = lowlevel.gf(),
      s = lowlevel.gf(),
      s_prime = lowlevel.gf(),
      ss = lowlevel.gf(),
      u = lowlevel.gf(),
      v = lowlevel.gf(),
      w0 = lowlevel.gf(),
      w1 = lowlevel.gf(),
      w2 = lowlevel.gf(),
      w3 = lowlevel.gf();
    var wasnt_square;

    lowlevel.set25519(one, gf1); /* one = 1 */
    lowlevel.S(r, t); /* r = t^2 */
    lowlevel.M(r, sqrtm1, r); /* r = sqrt(-1)*t^2 */
    lowlevel.A(u, r, one); /* u = r+1 = sqrt(-1)*t^2 + 1 */
    lowlevel.M(
      u,
      u,
      onemsqd
    ); /* u = (r+1)*(1-d^2) =  (sqrt(-1)*t^2 + 1) * (1-d^2)*/
    lowlevel.set25519(c, gf1); /* c = 1 */
    neg25519(c, c); /* c = -1 */
    lowlevel.A(rpd, r, lowlevel.D); /* rpd = r*d */
    lowlevel.M(v, r, lowlevel.D); /* v = r*d */
    lowlevel.Z(v, c, v); /* v = c-r*d */
    lowlevel.M(v, v, rpd); /* v = (c-r*d)*(r+d) */

    wasnt_square = 1 - ristretto255_sqrt_ratio_m1(s, u, v);
    lowlevel.M(s_prime, s, t);
    abs25519(s_prime, s_prime);
    neg25519(s_prime, s_prime); /* s_prime = -|s*t| */
    cmov25519(s, s_prime, wasnt_square);
    cmov25519(c, r, wasnt_square);

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
   * Hash to ristretto group with Elligator.
   * This function can be used anywhere where a random oracle is required by calling is with a 512-bits random bit-string h
   * (can be a SHA-512 hash of a 256-bits randomness source or a HKDF is instantiated from a low-entropy message).
   * See https://ristretto.group/formulas/elligator.html
   * Note: for h of length 256 bits, then h mod p = 2^255-19 has a slighly larger probability of being in [0, 37], than a uniformly random element mod p.
   *       To get a bias of at most 1/2^128 h should have at least ceil(log2(p)) + 128 bits = ceil((255 + 128)/8)*8 = 384 bits.
   *       For a small-length message HKDF can be used to expand and extract the element h.
   *       (see https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-05.txt)
   * The reason two base field points are being produced, then hashed and added is the line of work that
   * shows that f(h(m)) is not a random oracle (where f is map_to_curve and h is a secure hash function like SHA)
   * because f is not surjective necessarily, therefore it might be easy to distinguish f(h(m)) from a truly random point.
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
   * @param {Uint8Array(64)} h 64 elements byte array such as the output of SHA512.
   * @return {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} The resulting Ed25519 elliptic-curve point.
   */
  function ristretto255_from_hash(h) {
    var r0 = lowlevel.gf(),
      r1 = lowlevel.gf();
    var p0 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var p1 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];

    lowlevel.unpack25519(r0, h.slice(0, 32));
    lowlevel.unpack25519(r1, h.slice(32, 64));
    ristretto255_elligator(p0, r0);
    ristretto255_elligator(p1, r1);

    lowlevel.add(p0, p1);
    return p0;
  }

  ristretto.ristretto255_from_hash = ristretto255_from_hash;
  ristretto.ristretto255_tobytes = ristretto255_tobytes;
  ristretto.scalarmodL = scalarmodL;
  ristretto.invmodL = invmodL;
  ristretto.MmodL = MmodL;
  ristretto.ristretto255_frombytes = ristretto255_frombytes;
  ristretto.scalarmodL1 = scalarmodL1;
})(
  typeof module !== 'undefined' && module.exports
    ? module.exports
    : (self.ristretto = self.ristretto || {})
);
