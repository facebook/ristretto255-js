var nacl_function = function(nacl) {
  'use strict';

  // Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
  // Public domain.
  //
  // Implementation derived from TweetNaCl version 20140427.
  // See for details: http://tweetnacl.cr.yp.to/

  var u64 = function(h, l) {
    this.hi = h | (0 >>> 0);
    this.lo = l | (0 >>> 0);
  };
  var gf = function(init) {
    var i,
      r = new Float64Array(16);
    if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };

  //  Pluggable, initialized in high-level API below.
  var randombytes = function(/* x, n */) {
    throw new Error('no PRNG');
  };

  var _0 = new Uint8Array(16);
  var _9 = new Uint8Array(32);
  _9[0] = 9;

  var gf0 = gf(),
    gf1 = gf([1]),
    _121665 = gf([0xdb41, 1]),
    D = gf([
      0x78a3,
      0x1359,
      0x4dca,
      0x75eb,
      0xd8ab,
      0x4141,
      0x0a4d,
      0x0070,
      0xe898,
      0x7779,
      0x4079,
      0x8cc7,
      0xfe73,
      0x2b6f,
      0x6cee,
      0x5203,
    ]),
    D2 = gf([
      0xf159,
      0x26b2,
      0x9b94,
      0xebd6,
      0xb156,
      0x8283,
      0x149a,
      0x00e0,
      0xd130,
      0xeef3,
      0x80f2,
      0x198e,
      0xfce7,
      0x56df,
      0xd9dc,
      0x2406,
    ]),
    X = gf([
      0xd51a,
      0x8f25,
      0x2d60,
      0xc956,
      0xa7b2,
      0x9525,
      0xc760,
      0x692c,
      0xdc5c,
      0xfdd6,
      0xe231,
      0xc0a4,
      0x53fe,
      0xcd6e,
      0x36d3,
      0x2169,
    ]),
    Y = gf([
      0x6658,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
      0x6666,
    ]),
    I = gf([
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
    ]);

  function L32(x, c) {
    return (x << c) | (x >>> (32 - c));
  }

  function ld32(x, i) {
    var u = x[i + 3] & 0xff;
    u = (u << 8) | (x[i + 2] & 0xff);
    u = (u << 8) | (x[i + 1] & 0xff);
    return (u << 8) | (x[i + 0] & 0xff);
  }

  function dl64(x, i) {
    var h = (x[i] << 24) | (x[i + 1] << 16) | (x[i + 2] << 8) | x[i + 3];
    var l = (x[i + 4] << 24) | (x[i + 5] << 16) | (x[i + 6] << 8) | x[i + 7];
    return new u64(h, l);
  }

  function st32(x, j, u) {
    var i;
    for (i = 0; i < 4; i++) {
      x[j + i] = u & 255;
      u >>>= 8;
    }
  }

  function ts64(x, i, u) {
    x[i] = (u.hi >> 24) & 0xff;
    x[i + 1] = (u.hi >> 16) & 0xff;
    x[i + 2] = (u.hi >> 8) & 0xff;
    x[i + 3] = u.hi & 0xff;
    x[i + 4] = (u.lo >> 24) & 0xff;
    x[i + 5] = (u.lo >> 16) & 0xff;
    x[i + 6] = (u.lo >> 8) & 0xff;
    x[i + 7] = u.lo & 0xff;
  }

  function vn(x, xi, y, yi, n) {
    var i,
      d = 0;
    for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
    return (1 & ((d - 1) >>> 8)) - 1;
  }

  function crypto_verify_16(x, xi, y, yi) {
    return vn(x, xi, y, yi, 16);
  }

  function crypto_verify_32(x, xi, y, yi) {
    return vn(x, xi, y, yi, 32);
  }

  function core(out, inp, k, c, h) {
    var w = new Uint32Array(16),
      x = new Uint32Array(16),
      y = new Uint32Array(16),
      t = new Uint32Array(4);
    var i, j, m;

    for (i = 0; i < 4; i++) {
      x[5 * i] = ld32(c, 4 * i);
      x[1 + i] = ld32(k, 4 * i);
      x[6 + i] = ld32(inp, 4 * i);
      x[11 + i] = ld32(k, 16 + 4 * i);
    }

    for (i = 0; i < 16; i++) y[i] = x[i];

    for (i = 0; i < 20; i++) {
      for (j = 0; j < 4; j++) {
        for (m = 0; m < 4; m++) t[m] = x[(5 * j + 4 * m) % 16];
        t[1] ^= L32((t[0] + t[3]) | 0, 7);
        t[2] ^= L32((t[1] + t[0]) | 0, 9);
        t[3] ^= L32((t[2] + t[1]) | 0, 13);
        t[0] ^= L32((t[3] + t[2]) | 0, 18);
        for (m = 0; m < 4; m++) w[4 * j + ((j + m) % 4)] = t[m];
      }
      for (m = 0; m < 16; m++) x[m] = w[m];
    }

    if (h) {
      for (i = 0; i < 16; i++) x[i] = (x[i] + y[i]) | 0;
      for (i = 0; i < 4; i++) {
        x[5 * i] = (x[5 * i] - ld32(c, 4 * i)) | 0;
        x[6 + i] = (x[6 + i] - ld32(inp, 4 * i)) | 0;
      }
      for (i = 0; i < 4; i++) {
        st32(out, 4 * i, x[5 * i]);
        st32(out, 16 + 4 * i, x[6 + i]);
      }
    } else {
      for (i = 0; i < 16; i++) st32(out, 4 * i, (x[i] + y[i]) | 0);
    }
  }

  function crypto_core_salsa20(out, inp, k, c) {
    core(out, inp, k, c, false);
    return 0;
  }

  function crypto_core_hsalsa20(out, inp, k, c) {
    core(out, inp, k, c, true);
    return 0;
  }

  var sigma = new Uint8Array([
    101,
    120,
    112,
    97,
    110,
    100,
    32,
    51,
    50,
    45,
    98,
    121,
    116,
    101,
    32,
    107,
  ]);
  // "expand 32-byte k"

  function crypto_stream_salsa20_xor(c, cpos, m, mpos, b, n, k) {
    var z = new Uint8Array(16),
      x = new Uint8Array(64);
    var u, i;
    if (!b) return 0;
    for (i = 0; i < 16; i++) z[i] = 0;
    for (i = 0; i < 8; i++) z[i] = n[i];
    while (b >= 64) {
      crypto_core_salsa20(x, z, k, sigma);
      for (i = 0; i < 64; i++) c[cpos + i] = (m ? m[mpos + i] : 0) ^ x[i];
      u = 1;
      for (i = 8; i < 16; i++) {
        u = (u + (z[i] & 0xff)) | 0;
        z[i] = u & 0xff;
        u >>>= 8;
      }
      b -= 64;
      cpos += 64;
      if (m) mpos += 64;
    }
    if (b > 0) {
      crypto_core_salsa20(x, z, k, sigma);
      for (i = 0; i < b; i++) c[cpos + i] = (m ? m[mpos + i] : 0) ^ x[i];
    }
    return 0;
  }

  function crypto_stream_salsa20(c, cpos, d, n, k) {
    return crypto_stream_salsa20_xor(c, cpos, null, 0, d, n, k);
  }

  function crypto_stream(c, cpos, d, n, k) {
    var s = new Uint8Array(32);
    crypto_core_hsalsa20(s, n, k, sigma);
    return crypto_stream_salsa20(c, cpos, d, n.subarray(16), s);
  }

  function crypto_stream_xor(c, cpos, m, mpos, d, n, k) {
    var s = new Uint8Array(32);
    crypto_core_hsalsa20(s, n, k, sigma);
    return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, n.subarray(16), s);
  }

  function add1305(h, c) {
    var j,
      u = 0;
    for (j = 0; j < 17; j++) {
      u = (u + ((h[j] + c[j]) | 0)) | 0;
      h[j] = u & 255;
      u >>>= 8;
    }
  }

  var minusp = new Uint32Array([
    5,
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
    252,
  ]);

  function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
    var s, i, j, u;
    var x = new Uint32Array(17),
      r = new Uint32Array(17),
      h = new Uint32Array(17),
      c = new Uint32Array(17),
      g = new Uint32Array(17);
    for (j = 0; j < 17; j++) r[j] = h[j] = 0;
    for (j = 0; j < 16; j++) r[j] = k[j];
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    while (n > 0) {
      for (j = 0; j < 17; j++) c[j] = 0;
      for (j = 0; j < 16 && j < n; ++j) c[j] = m[mpos + j];
      c[j] = 1;
      mpos += j;
      n -= j;
      add1305(h, c);
      for (i = 0; i < 17; i++) {
        x[i] = 0;
        for (j = 0; j < 17; j++)
          x[i] =
            (x[i] + h[j] * (j <= i ? r[i - j] : (320 * r[i + 17 - j]) | 0)) |
            0 |
            0;
      }
      for (i = 0; i < 17; i++) h[i] = x[i];
      u = 0;
      for (j = 0; j < 16; j++) {
        u = (u + h[j]) | 0;
        h[j] = u & 255;
        u >>>= 8;
      }
      u = (u + h[16]) | 0;
      h[16] = u & 3;
      u = (5 * (u >>> 2)) | 0;
      for (j = 0; j < 16; j++) {
        u = (u + h[j]) | 0;
        h[j] = u & 255;
        u >>>= 8;
      }
      u = (u + h[16]) | 0;
      h[16] = u;
    }

    for (j = 0; j < 17; j++) g[j] = h[j];
    add1305(h, minusp);
    s = -(h[16] >>> 7) | 0;
    for (j = 0; j < 17; j++) h[j] ^= s & (g[j] ^ h[j]);

    for (j = 0; j < 16; j++) c[j] = k[j + 16];
    c[16] = 0;
    add1305(h, c);
    for (j = 0; j < 16; j++) out[outpos + j] = h[j];
    return 0;
  }

  function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
    var x = new Uint8Array(16);
    crypto_onetimeauth(x, 0, m, mpos, n, k);
    return crypto_verify_16(h, hpos, x, 0);
  }

  function crypto_secretbox(c, m, d, n, k) {
    var i;
    if (d < 32) return -1;
    crypto_stream_xor(c, 0, m, 0, d, n, k);
    crypto_onetimeauth(c, 16, c, 32, d - 32, c);
    for (i = 0; i < 16; i++) c[i] = 0;
    return 0;
  }

  function crypto_secretbox_open(m, c, d, n, k) {
    var i;
    var x = new Uint8Array(32);
    if (d < 32) return -1;
    crypto_stream(x, 0, 32, n, k);
    if (crypto_onetimeauth_verify(c, 16, c, 32, d - 32, x) !== 0) return -1;
    crypto_stream_xor(m, 0, c, 0, d, n, k);
    for (i = 0; i < 32; i++) m[i] = 0;
    return 0;
  }

  function set25519(r, a) {
    var i;
    for (i = 0; i < 16; i++) r[i] = a[i] | 0;
  }

  function car25519(o) {
    var c;
    var i;
    for (i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i + 1) * (i < 15 ? 1 : 0)] +=
        c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
      o[i] -= c * 65536;
    }
  }

  function sel25519(p, q, b) {
    var t,
      c = ~(b - 1);
    for (var i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  function pack25519(o, n) {
    var i, j, b;
    var m = gf(),
      t = gf();
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;
      sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >> 8;
    }
  }

  function neq25519(a, b) {
    var c = new Uint8Array(32),
      d = new Uint8Array(32);
    pack25519(c, a);
    pack25519(d, b);
    return crypto_verify_32(c, 0, d, 0);
  }

  function par25519(a) {
    var d = new Uint8Array(32);
    pack25519(d, a);
    return d[0] & 1;
  }

  function unpack25519(o, n) {
    var i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
  }

  function A(o, a, b) {
    var i;
    for (i = 0; i < 16; i++) o[i] = (a[i] + b[i]) | 0;
  }

  function Z(o, a, b) {
    var i;
    for (i = 0; i < 16; i++) o[i] = (a[i] - b[i]) | 0;
  }

  function M(o, a, b) {
    var i,
      j,
      t = new Float64Array(31);
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) {
      for (j = 0; j < 16; j++) {
        t[i + j] += a[i] * b[j];
      }
    }
    for (i = 0; i < 15; i++) {
      t[i] += 38 * t[i + 16];
    }
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
  }

  function S(o, a) {
    M(o, a, a);
  }

  function inv25519(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
      S(c, c);
      if (a !== 2 && a !== 4) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
  }

  function pow2523(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
      S(c, c);
      if (a !== 1) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
  }

  function crypto_scalarmult(q, n, p) {
    var z = new Uint8Array(32);
    var x = new Float64Array(80),
      r,
      i;
    var a = gf(),
      b = gf(),
      c = gf(),
      d = gf(),
      e = gf(),
      f = gf();
    for (i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; i++) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
      r = (z[i >>> 3] >>> (i & 7)) & 1;
      sel25519(a, b, r);
      sel25519(c, d, r);
      A(e, a, c);
      Z(a, a, c);
      A(c, b, d);
      Z(b, b, d);
      S(d, e);
      S(f, a);
      M(a, c, a);
      M(c, b, e);
      A(e, a, c);
      Z(a, a, c);
      S(b, a);
      Z(c, d, f);
      M(a, c, _121665);
      A(a, a, d);
      M(c, c, a);
      M(a, d, f);
      M(d, b, x);
      S(b, e);
      sel25519(a, b, r);
      sel25519(c, d, r);
    }
    for (i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }
    var x32 = x.subarray(32);
    var x16 = x.subarray(16);
    inv25519(x32, x32);
    M(x16, x16, x32);
    pack25519(q, x16);
    return 0;
  }

  function crypto_scalarmult_base(q, n) {
    return crypto_scalarmult(q, n, _9);
  }

  function crypto_box_keypair(y, x) {
    randombytes(x, 32);
    return crypto_scalarmult_base(y, x);
  }

  function crypto_box_beforenm(k, y, x) {
    var s = new Uint8Array(32);
    crypto_scalarmult(s, x, y);
    return crypto_core_hsalsa20(k, _0, s, sigma);
  }

  var crypto_box_afternm = crypto_secretbox;
  var crypto_box_open_afternm = crypto_secretbox_open;

  function crypto_box(c, m, d, n, y, x) {
    var k = new Uint8Array(32);
    crypto_box_beforenm(k, y, x);
    return crypto_box_afternm(c, m, d, n, k);
  }

  function crypto_box_open(m, c, d, n, y, x) {
    var k = new Uint8Array(32);
    crypto_box_beforenm(k, y, x);
    return crypto_box_open_afternm(m, c, d, n, k);
  }

  function add64() {
    var a = 0,
      b = 0,
      c = 0,
      d = 0,
      m16 = 65535,
      l,
      h,
      i;
    for (i = 0; i < arguments.length; i++) {
      l = arguments[i].lo;
      h = arguments[i].hi;
      a += l & m16;
      b += l >>> 16;
      c += h & m16;
      d += h >>> 16;
    }

    b += a >>> 16;
    c += b >>> 16;
    d += c >>> 16;

    return new u64((c & m16) | (d << 16), (a & m16) | (b << 16));
  }

  function shr64(x, c) {
    return new u64(x.hi >>> c, (x.lo >>> c) | (x.hi << (32 - c)));
  }

  function xor64() {
    var l = 0,
      h = 0,
      i;
    for (i = 0; i < arguments.length; i++) {
      l ^= arguments[i].lo;
      h ^= arguments[i].hi;
    }
    return new u64(h, l);
  }

  function R(x, c) {
    var h,
      l,
      c1 = 32 - c;
    if (c < 32) {
      h = (x.hi >>> c) | (x.lo << c1);
      l = (x.lo >>> c) | (x.hi << c1);
    } else if (c < 64) {
      h = (x.lo >>> c) | (x.hi << c1);
      l = (x.hi >>> c) | (x.lo << c1);
    }
    return new u64(h, l);
  }

  function Ch(x, y, z) {
    var h = (x.hi & y.hi) ^ (~x.hi & z.hi),
      l = (x.lo & y.lo) ^ (~x.lo & z.lo);
    return new u64(h, l);
  }

  function Maj(x, y, z) {
    var h = (x.hi & y.hi) ^ (x.hi & z.hi) ^ (y.hi & z.hi),
      l = (x.lo & y.lo) ^ (x.lo & z.lo) ^ (y.lo & z.lo);
    return new u64(h, l);
  }

  function Sigma0(x) {
    return xor64(R(x, 28), R(x, 34), R(x, 39));
  }
  function Sigma1(x) {
    return xor64(R(x, 14), R(x, 18), R(x, 41));
  }
  function sigma0(x) {
    return xor64(R(x, 1), R(x, 8), shr64(x, 7));
  }
  function sigma1(x) {
    return xor64(R(x, 19), R(x, 61), shr64(x, 6));
  }

  var K = [
    new u64(0x428a2f98, 0xd728ae22),
    new u64(0x71374491, 0x23ef65cd),
    new u64(0xb5c0fbcf, 0xec4d3b2f),
    new u64(0xe9b5dba5, 0x8189dbbc),
    new u64(0x3956c25b, 0xf348b538),
    new u64(0x59f111f1, 0xb605d019),
    new u64(0x923f82a4, 0xaf194f9b),
    new u64(0xab1c5ed5, 0xda6d8118),
    new u64(0xd807aa98, 0xa3030242),
    new u64(0x12835b01, 0x45706fbe),
    new u64(0x243185be, 0x4ee4b28c),
    new u64(0x550c7dc3, 0xd5ffb4e2),
    new u64(0x72be5d74, 0xf27b896f),
    new u64(0x80deb1fe, 0x3b1696b1),
    new u64(0x9bdc06a7, 0x25c71235),
    new u64(0xc19bf174, 0xcf692694),
    new u64(0xe49b69c1, 0x9ef14ad2),
    new u64(0xefbe4786, 0x384f25e3),
    new u64(0x0fc19dc6, 0x8b8cd5b5),
    new u64(0x240ca1cc, 0x77ac9c65),
    new u64(0x2de92c6f, 0x592b0275),
    new u64(0x4a7484aa, 0x6ea6e483),
    new u64(0x5cb0a9dc, 0xbd41fbd4),
    new u64(0x76f988da, 0x831153b5),
    new u64(0x983e5152, 0xee66dfab),
    new u64(0xa831c66d, 0x2db43210),
    new u64(0xb00327c8, 0x98fb213f),
    new u64(0xbf597fc7, 0xbeef0ee4),
    new u64(0xc6e00bf3, 0x3da88fc2),
    new u64(0xd5a79147, 0x930aa725),
    new u64(0x06ca6351, 0xe003826f),
    new u64(0x14292967, 0x0a0e6e70),
    new u64(0x27b70a85, 0x46d22ffc),
    new u64(0x2e1b2138, 0x5c26c926),
    new u64(0x4d2c6dfc, 0x5ac42aed),
    new u64(0x53380d13, 0x9d95b3df),
    new u64(0x650a7354, 0x8baf63de),
    new u64(0x766a0abb, 0x3c77b2a8),
    new u64(0x81c2c92e, 0x47edaee6),
    new u64(0x92722c85, 0x1482353b),
    new u64(0xa2bfe8a1, 0x4cf10364),
    new u64(0xa81a664b, 0xbc423001),
    new u64(0xc24b8b70, 0xd0f89791),
    new u64(0xc76c51a3, 0x0654be30),
    new u64(0xd192e819, 0xd6ef5218),
    new u64(0xd6990624, 0x5565a910),
    new u64(0xf40e3585, 0x5771202a),
    new u64(0x106aa070, 0x32bbd1b8),
    new u64(0x19a4c116, 0xb8d2d0c8),
    new u64(0x1e376c08, 0x5141ab53),
    new u64(0x2748774c, 0xdf8eeb99),
    new u64(0x34b0bcb5, 0xe19b48a8),
    new u64(0x391c0cb3, 0xc5c95a63),
    new u64(0x4ed8aa4a, 0xe3418acb),
    new u64(0x5b9cca4f, 0x7763e373),
    new u64(0x682e6ff3, 0xd6b2b8a3),
    new u64(0x748f82ee, 0x5defb2fc),
    new u64(0x78a5636f, 0x43172f60),
    new u64(0x84c87814, 0xa1f0ab72),
    new u64(0x8cc70208, 0x1a6439ec),
    new u64(0x90befffa, 0x23631e28),
    new u64(0xa4506ceb, 0xde82bde9),
    new u64(0xbef9a3f7, 0xb2c67915),
    new u64(0xc67178f2, 0xe372532b),
    new u64(0xca273ece, 0xea26619c),
    new u64(0xd186b8c7, 0x21c0c207),
    new u64(0xeada7dd6, 0xcde0eb1e),
    new u64(0xf57d4f7f, 0xee6ed178),
    new u64(0x06f067aa, 0x72176fba),
    new u64(0x0a637dc5, 0xa2c898a6),
    new u64(0x113f9804, 0xbef90dae),
    new u64(0x1b710b35, 0x131c471b),
    new u64(0x28db77f5, 0x23047d84),
    new u64(0x32caab7b, 0x40c72493),
    new u64(0x3c9ebe0a, 0x15c9bebc),
    new u64(0x431d67c4, 0x9c100d4c),
    new u64(0x4cc5d4be, 0xcb3e42b6),
    new u64(0x597f299c, 0xfc657e2a),
    new u64(0x5fcb6fab, 0x3ad6faec),
    new u64(0x6c44198c, 0x4a475817),
  ];

  function crypto_hashblocks(x, m, n) {
    var z = [],
      b = [],
      a = [],
      w = [],
      t,
      i,
      j;

    for (i = 0; i < 8; i++) z[i] = a[i] = dl64(x, 8 * i);

    var pos = 0;
    while (n >= 128) {
      for (i = 0; i < 16; i++) w[i] = dl64(m, 8 * i + pos);
      for (i = 0; i < 80; i++) {
        for (j = 0; j < 8; j++) b[j] = a[j];
        t = add64(a[7], Sigma1(a[4]), Ch(a[4], a[5], a[6]), K[i], w[i % 16]);
        b[7] = add64(t, Sigma0(a[0]), Maj(a[0], a[1], a[2]));
        b[3] = add64(b[3], t);
        for (j = 0; j < 8; j++) a[(j + 1) % 8] = b[j];
        if (i % 16 === 15) {
          for (j = 0; j < 16; j++) {
            w[j] = add64(
              w[j],
              w[(j + 9) % 16],
              sigma0(w[(j + 1) % 16]),
              sigma1(w[(j + 14) % 16]),
            );
          }
        }
      }

      for (i = 0; i < 8; i++) {
        a[i] = add64(a[i], z[i]);
        z[i] = a[i];
      }

      pos += 128;
      n -= 128;
    }

    for (i = 0; i < 8; i++) ts64(x, 8 * i, z[i]);
    return n;
  }

  var iv = new Uint8Array([
    0x6a,
    0x09,
    0xe6,
    0x67,
    0xf3,
    0xbc,
    0xc9,
    0x08,
    0xbb,
    0x67,
    0xae,
    0x85,
    0x84,
    0xca,
    0xa7,
    0x3b,
    0x3c,
    0x6e,
    0xf3,
    0x72,
    0xfe,
    0x94,
    0xf8,
    0x2b,
    0xa5,
    0x4f,
    0xf5,
    0x3a,
    0x5f,
    0x1d,
    0x36,
    0xf1,
    0x51,
    0x0e,
    0x52,
    0x7f,
    0xad,
    0xe6,
    0x82,
    0xd1,
    0x9b,
    0x05,
    0x68,
    0x8c,
    0x2b,
    0x3e,
    0x6c,
    0x1f,
    0x1f,
    0x83,
    0xd9,
    0xab,
    0xfb,
    0x41,
    0xbd,
    0x6b,
    0x5b,
    0xe0,
    0xcd,
    0x19,
    0x13,
    0x7e,
    0x21,
    0x79,
  ]);

  function crypto_hash(out, m, n) {
    var h = new Uint8Array(64),
      x = new Uint8Array(256);
    var i,
      b = n;

    for (i = 0; i < 64; i++) h[i] = iv[i];

    crypto_hashblocks(h, m, n);
    n %= 128;

    for (i = 0; i < 256; i++) x[i] = 0;
    for (i = 0; i < n; i++) x[i] = m[b - n + i];
    x[n] = 128;

    n = 256 - 128 * (n < 112 ? 1 : 0);
    x[n - 9] = 0;
    ts64(x, n - 8, new u64((b / 0x20000000) | 0, b << 3));
    crypto_hashblocks(h, x, n);

    for (i = 0; i < 64; i++) out[i] = h[i];

    return 0;
  }

  function add(p, q) {
    var a = gf(),
      b = gf(),
      c = gf(),
      d = gf(),
      e = gf(),
      f = gf(),
      g = gf(),
      h = gf(),
      t = gf();

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
  }

  function cswap(p, q, b) {
    var i;
    for (i = 0; i < 4; i++) {
      sel25519(p[i], q[i], b);
    }
  }

  function pack(r, p) {
    var tx = gf(),
      ty = gf(),
      zi = gf();
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
  }

  function scalarmult(p, q, s) {
    var b, i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
      b = (s[(i / 8) | 0] >> (i & 7)) & 1;
      cswap(p, q, b);
      add(q, p);
      add(p, p);
      cswap(p, q, b);
    }
  }

  function scalarbase(p, s) {
    var q = [gf(), gf(), gf(), gf()];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
  }

  function crypto_sign_keypair(pk, sk, seeded) {
    var d = new Uint8Array(64);
    var p = [gf(), gf(), gf(), gf()];
    var i;

    if (!seeded) randombytes(sk, 32);
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d);
    pack(pk, p);

    for (i = 0; i < 32; i++) sk[i + 32] = pk[i];
    return 0;
  }

  var L = new Float64Array([
    0xed,
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

  function modL(r, x) {
    var carry, i, j, k;
    for (i = 63; i >= 32; --i) {
      carry = 0;
      for (j = i - 32, k = i - 12; j < k; ++j) {
        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;
        x[j] -= carry * 256;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * L[j];
      carry = x[j] >> 8;
      x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * L[j];
    for (i = 0; i < 32; i++) {
      x[i + 1] += x[i] >> 8;
      r[i] = x[i] & 255;
    }
  }

  function reduce(r) {
    var x = new Float64Array(64),
      i;
    for (i = 0; i < 64; i++) x[i] = r[i];
    for (i = 0; i < 64; i++) r[i] = 0;
    modL(r, x);
  }

  // Note: difference from C - smlen returned, not passed as argument.
  function crypto_sign(sm, m, n, sk) {
    var d = new Uint8Array(64),
      h = new Uint8Array(64),
      r = new Uint8Array(64);
    var i,
      j,
      x = new Float64Array(64);
    var p = [gf(), gf(), gf(), gf()];

    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    var smlen = n + 64;
    for (i = 0; i < n; i++) sm[64 + i] = m[i];
    for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

    crypto_hash(r, sm.subarray(32), n + 32);
    reduce(r);
    scalarbase(p, r);
    pack(sm, p);

    for (i = 32; i < 64; i++) sm[i] = sk[i];
    crypto_hash(h, sm, n + 64);
    reduce(h);

    for (i = 0; i < 64; i++) x[i] = 0;
    for (i = 0; i < 32; i++) x[i] = r[i];
    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) {
        x[i + j] += h[i] * d[j];
      }
    }

    modL(sm.subarray(32), x);
    return smlen;
  }

  function unpackneg(r, p) {
    var t = gf(),
      chk = gf(),
      num = gf(),
      den = gf(),
      den2 = gf(),
      den4 = gf(),
      den6 = gf();

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) === p[31] >> 7) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
  }

  function crypto_sign_open(m, sm, n, pk) {
    var i, mlen;
    var t = new Uint8Array(32),
      h = new Uint8Array(64);
    var p = [gf(), gf(), gf(), gf()],
      q = [gf(), gf(), gf(), gf()];

    mlen = -1;
    if (n < 64) return -1;

    if (unpackneg(q, pk)) return -1;

    for (i = 0; i < n; i++) m[i] = sm[i];
    for (i = 0; i < 32; i++) m[i + 32] = pk[i];
    crypto_hash(h, m, n);
    reduce(h);
    scalarmult(p, q, h);

    scalarbase(q, sm.subarray(32));
    add(p, q);
    pack(t, p);

    n -= 64;
    if (crypto_verify_32(sm, 0, t, 0)) {
      for (i = 0; i < n; i++) m[i] = 0;
      return -1;
    }

    for (i = 0; i < n; i++) m[i] = sm[i + 64];
    mlen = n;
    return mlen;
  }

  var crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16,
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32,
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
    crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
    crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64,
    crypto_sign_SEEDBYTES = 32,
    crypto_hash_BYTES = 64;

  nacl.lowlevel = {
    crypto_core_hsalsa20: crypto_core_hsalsa20,
    crypto_stream_xor: crypto_stream_xor,
    crypto_stream: crypto_stream,
    crypto_stream_salsa20_xor: crypto_stream_salsa20_xor,
    crypto_stream_salsa20: crypto_stream_salsa20,
    crypto_onetimeauth: crypto_onetimeauth,
    crypto_onetimeauth_verify: crypto_onetimeauth_verify,
    crypto_verify_16: crypto_verify_16,
    crypto_verify_32: crypto_verify_32,
    crypto_secretbox: crypto_secretbox,
    crypto_secretbox_open: crypto_secretbox_open,
    crypto_scalarmult: crypto_scalarmult,
    crypto_scalarmult_base: crypto_scalarmult_base,
    crypto_box_beforenm: crypto_box_beforenm,
    crypto_box_afternm: crypto_box_afternm,
    crypto_box: crypto_box,
    crypto_box_open: crypto_box_open,
    crypto_box_keypair: crypto_box_keypair,
    crypto_hash: crypto_hash,
    crypto_sign: crypto_sign,
    crypto_sign_keypair: crypto_sign_keypair,
    crypto_sign_open: crypto_sign_open,

    crypto_secretbox_KEYBYTES: crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES: crypto_secretbox_NONCEBYTES,
    crypto_secretbox_ZEROBYTES: crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES: crypto_secretbox_BOXZEROBYTES,
    crypto_scalarmult_BYTES: crypto_scalarmult_BYTES,
    crypto_scalarmult_SCALARBYTES: crypto_scalarmult_SCALARBYTES,
    crypto_box_PUBLICKEYBYTES: crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES: crypto_box_SECRETKEYBYTES,
    crypto_box_BEFORENMBYTES: crypto_box_BEFORENMBYTES,
    crypto_box_NONCEBYTES: crypto_box_NONCEBYTES,
    crypto_box_ZEROBYTES: crypto_box_ZEROBYTES,
    crypto_box_BOXZEROBYTES: crypto_box_BOXZEROBYTES,
    crypto_sign_BYTES: crypto_sign_BYTES,
    crypto_sign_PUBLICKEYBYTES: crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES: crypto_sign_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
    crypto_hash_BYTES: crypto_hash_BYTES,
  };

  /* High-level API */

  function checkLengths(k, n) {
    if (k.length !== crypto_secretbox_KEYBYTES) throw new Error('bad key size');
    if (n.length !== crypto_secretbox_NONCEBYTES)
      throw new Error('bad nonce size');
  }

  function checkBoxLengths(pk, sk) {
    if (pk.length !== crypto_box_PUBLICKEYBYTES)
      throw new Error('bad public key size');
    if (sk.length !== crypto_box_SECRETKEYBYTES)
      throw new Error('bad secret key size');
  }

  function checkArrayTypes() {
    for (var i = 0; i < arguments.length; i++) {
      if (!(arguments[i] instanceof Uint8Array))
        throw new TypeError('unexpected type, use Uint8Array');
    }
  }

  function cleanup(arr) {
    for (var i = 0; i < arr.length; i++) arr[i] = 0;
  }

  nacl.randomBytes = function(n) {
    var b = new Uint8Array(n);
    randombytes(b, n);
    return b;
  };

  nacl.secretbox = function(msg, nonce, key) {
    checkArrayTypes(msg, nonce, key);
    checkLengths(key, nonce);
    var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
    var c = new Uint8Array(m.length);
    for (var i = 0; i < msg.length; i++)
      m[i + crypto_secretbox_ZEROBYTES] = msg[i];
    crypto_secretbox(c, m, m.length, nonce, key);
    return c.subarray(crypto_secretbox_BOXZEROBYTES);
  };

  nacl.secretbox.open = function(box, nonce, key) {
    checkArrayTypes(box, nonce, key);
    checkLengths(key, nonce);
    var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
    var m = new Uint8Array(c.length);
    for (var i = 0; i < box.length; i++)
      c[i + crypto_secretbox_BOXZEROBYTES] = box[i];
    if (c.length < 32) return null;
    if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
    return m.subarray(crypto_secretbox_ZEROBYTES);
  };

  nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
  nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
  nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

  nacl.scalarMult = function(n, p) {
    checkArrayTypes(n, p);
    if (n.length !== crypto_scalarmult_SCALARBYTES)
      throw new Error('bad n size');
    if (p.length !== crypto_scalarmult_BYTES) throw new Error('bad p size');
    var q = new Uint8Array(crypto_scalarmult_BYTES);
    crypto_scalarmult(q, n, p);
    return q;
  };

  nacl.scalarMult.base = function(n) {
    checkArrayTypes(n);
    if (n.length !== crypto_scalarmult_SCALARBYTES)
      throw new Error('bad n size');
    var q = new Uint8Array(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(q, n);
    return q;
  };

  nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
  nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

  nacl.box = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox(msg, nonce, k);
  };

  nacl.box.before = function(publicKey, secretKey) {
    checkArrayTypes(publicKey, secretKey);
    checkBoxLengths(publicKey, secretKey);
    var k = new Uint8Array(crypto_box_BEFORENMBYTES);
    crypto_box_beforenm(k, publicKey, secretKey);
    return k;
  };

  nacl.box.after = nacl.secretbox;

  nacl.box.open = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox.open(msg, nonce, k);
  };

  nacl.box.open.after = nacl.secretbox.open;

  nacl.box.keyPair = function() {
    var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.box.keyPair.fromSecretKey = function(secretKey) {
    checkArrayTypes(secretKey);
    if (secretKey.length !== crypto_box_SECRETKEYBYTES)
      throw new Error('bad secret key size');
    var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
    crypto_scalarmult_base(pk, secretKey);
    return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
  };

  nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
  nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
  nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
  nacl.box.nonceLength = crypto_box_NONCEBYTES;
  nacl.box.overheadLength = nacl.secretbox.overheadLength;

  nacl.sign = function(msg, secretKey) {
    checkArrayTypes(msg, secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
      throw new Error('bad secret key size');
    var signedMsg = new Uint8Array(crypto_sign_BYTES + msg.length);
    crypto_sign(signedMsg, msg, msg.length, secretKey);
    return signedMsg;
  };

  nacl.sign.open = function(signedMsg, publicKey) {
    checkArrayTypes(signedMsg, publicKey);
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
      throw new Error('bad public key size');
    var tmp = new Uint8Array(signedMsg.length);
    var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
    if (mlen < 0) return null;
    var m = new Uint8Array(mlen);
    for (var i = 0; i < m.length; i++) m[i] = tmp[i];
    return m;
  };

  nacl.sign.detached = function(msg, secretKey) {
    var signedMsg = nacl.sign(msg, secretKey);
    var sig = new Uint8Array(crypto_sign_BYTES);
    for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
    return sig;
  };

  nacl.sign.detached.verify = function(msg, sig, publicKey) {
    checkArrayTypes(msg, sig, publicKey);
    if (sig.length !== crypto_sign_BYTES) throw new Error('bad signature size');
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
      throw new Error('bad public key size');
    var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
    var m = new Uint8Array(crypto_sign_BYTES + msg.length);
    var i;
    for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
    for (i = 0; i < msg.length; i++) sm[i + crypto_sign_BYTES] = msg[i];
    return crypto_sign_open(m, sm, sm.length, publicKey) >= 0;
  };

  nacl.sign.keyPair = function() {
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.sign.keyPair.fromSecretKey = function(secretKey) {
    checkArrayTypes(secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
      throw new Error('bad secret key size');
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32 + i];
    return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
  };

  nacl.sign.keyPair.fromSeed = function(seed) {
    checkArrayTypes(seed);
    if (seed.length !== crypto_sign_SEEDBYTES) throw new Error('bad seed size');
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
    for (var i = 0; i < 32; i++) sk[i] = seed[i];
    crypto_sign_keypair(pk, sk, true);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
  nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
  nacl.sign.seedLength = crypto_sign_SEEDBYTES;
  nacl.sign.signatureLength = crypto_sign_BYTES;

  nacl.hash = function(msg) {
    checkArrayTypes(msg);
    var h = new Uint8Array(crypto_hash_BYTES);
    crypto_hash(h, msg, msg.length);
    return h;
  };

  nacl.hash.hashLength = crypto_hash_BYTES;

  nacl.verify = function(x, y) {
    checkArrayTypes(x, y);
    // Zero length arguments are considered not equal.
    if (x.length === 0 || y.length === 0) return false;
    if (x.length !== y.length) return false;
    return vn(x, 0, y, 0, x.length) === 0 ? true : false;
  };

  nacl.setPRNG = function(fn) {
    randombytes = fn;
  };

  (function() {
    // Initialize PRNG if environment provides CSPRNG.
    // If not, methods calling randombytes will throw.
    var crypto =
      typeof self !== 'undefined' ? self.crypto || self.msCrypto : null;
    if (crypto && crypto.getRandomValues) {
      // Browsers.
      var QUOTA = 65536;
      nacl.setPRNG(function(x, n) {
        var i,
          v = new Uint8Array(n);
        for (i = 0; i < n; i += QUOTA) {
          crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
        }
        for (i = 0; i < n; i++) x[i] = v[i];
        cleanup(v);
      });
    } else if (typeof require !== 'undefined') {
      // Node.js.
      // crypto = require('crypto');
      // if (crypto && crypto.randomBytes) {
      //   nacl.setPRNG(function(x, n) {
      //     var i,
      //       v = crypto.randomBytes(n);
      //     for (i = 0; i < n; i++) x[i] = v[i];
      //     cleanup(v);
      //   });
      // }
    }
  })();

  /* Exposing low-level functions for PAKE */
  nacl.gf = gf;
  nacl.gf0 = gf0;
  nacl.gf1 = gf1;
  nacl._121665 = _121665;
  nacl.D = D;
  nacl.D2 = D2;
  nacl.X = X;
  nacl.Y = Y;
  nacl.I = I;
  nacl.car25519 = car25519;
  nacl.pack25519 = pack25519;
  nacl.unpack25519 = unpack25519;
  nacl.M = M;
  nacl.A = A;
  nacl.S = S;
  nacl.Z = Z;
  nacl.inv25519 = inv25519;
  nacl.pow2523 = pow2523;
  nacl.add = add;
  nacl.set25519 = set25519;
  nacl.sel25519 = sel25519;
  nacl.cswap = cswap;
  nacl.scalarmult = scalarmult;
  nacl.L = L;
  nacl.modL = modL;
  nacl.scalarbase = scalarbase;

  /*** Important notes:
   *** All encodings are LITTLE-ENDIAN
   ***/

  /***
   *** Scalar arithmetic (mod L) for operations in the exponent of elliptic curve points.
   *** The order of the curve is a prime L = 2^252 + 27742317777372353535851937790883648493, the part being added is 125 bits long.
   *** Constant L is defined in nacl.js.
   *** The function modL() is defined in nacl.js and reduces an element mod L.
   *** TODO: figure out the requirements on the input for the modL function to not have any overflows: it should just be that the elements are at most 16 bits...
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
    // Elements of t are 21 = (8 + 8 + log(32)) bits integers
    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) {
        t[i + j] += a[i] * b[j];
      }
    }

    // To reduce elements of t to be less than 16 bits each, we propagate the carry of 5 bits to the most significant bits,
    // resulting in at most 6 bits carry being added to t[63].
    // Note that t[63] is at most 1 (TODO: double check), so the addition of the 6-bits carry will not overflow.
    var carry = 0;
    for (j = 0; j < 64; j++) {
      t[j] += carry;
      carry = t[j] >> 8;
      t[j] &= 255;
    }

    // Reduce t mod L and write to o
    modL(o, t);
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
  var sqrtm1 = nacl.gf([
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
    sqrtadm1 = gf([
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
    invsqrtamd = gf([
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
    onemsqd = gf([
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
    sqdmone = gf([
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
    pack25519(s, p);
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
    pack25519(s, f);
    return s[0] & 1;
  }

  /**
   * Computes a negation of the input field element.
   *
   * @param {Float64Array(16)} f - the field element (mod 2^255 - 19).
   * @param {Float64Array(16)} h = (-f) - the output field element (mod 2^255 - 19).
   */
  function neg25519(h, f) {
    Z(h, gf0, f);
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
    var negf = gf();

    neg25519(negf, f);
    set25519(h, f);
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
    var v3 = gf(),
      vxx = gf(),
      m_root_check = gf(),
      p_root_check = gf(),
      f_root_check = gf(),
      x_sqrtm1 = gf(); // gf elements
    var has_m_root, has_p_root, has_f_root; // booleans

    S(v3, v);
    M(v3, v3, v); /* v3 = v^3 */

    S(x, v3);
    M(x, x, v);
    M(x, x, u); /* x = uv^7 */

    pow2523(x, x); /* x = (uv^7)^((q-5)/8), ((q-5)/8) = 2^252 - 3 */
    M(x, x, v3);
    M(x, x, u); /* x = uv^3(uv^7)^((q-5)/8) */

    S(vxx, x);
    M(vxx, vxx, v); /* vx^2 */

    Z(m_root_check, vxx, u); /* vx^2-u */
    A(p_root_check, vxx, u); /* vx^2+u */
    M(f_root_check, u, sqrtm1); /* u*sqrt(-1) */
    A(f_root_check, vxx, f_root_check); /* vx^2+u*sqrt(-1) */
    has_m_root = iszero25519(m_root_check); /* has_m_root = (vxx == u) */
    has_p_root = iszero25519(p_root_check); /* has_p_root = (vxx == -u) */
    has_f_root = iszero25519(
      f_root_check,
    ); /* has_f_root = (vxx = -u*sqrt(-1)) */
    M(x_sqrtm1, x, sqrtm1); /* x*sqrt(-1) */

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
    var den1 = gf(),
      den2 = gf();
    var den_inv = gf();
    var eden = gf();
    var inv_sqrt = gf();
    var ix = gf(),
      iy = gf();
    var one = gf();
    var s_ = gf();
    var t_z_inv = gf();
    var u1 = gf(),
      u2 = gf();
    var u1_u2u2 = gf();
    var x_ = gf(),
      y_ = gf();
    var x_z_inv = gf();
    var z_inv = gf();
    var zmy = gf();
    var res = 0;
    var rotate = 0;
    var s = new Uint8Array(32);

    A(u1, h[2], h[1]); /* u1 = Z+Y */
    Z(zmy, h[2], h[1]); /* zmy = Z-Y */
    M(u1, u1, zmy); /* u1 = (Z+Y)*(Z-Y) */

    M(u2, h[0], h[1]); /* u2 = X*Y */

    S(u1_u2u2, u2); /* u1_u2u2 = u2^2 */
    M(u1_u2u2, u1, u1_u2u2); /* u1_u2u2 = u1*u2^2 */

    one = gf1;
    ristretto255_sqrt_ratio_m1(inv_sqrt, one, u1_u2u2);

    M(den1, inv_sqrt, u1); /* den1 = inv_sqrt*u1 */
    M(den2, inv_sqrt, u2); /* den2 = inv_sqrt*u2 */
    M(z_inv, den1, den2); /* z_inv = den1*den2 */
    M(z_inv, z_inv, h[3]); /* z_inv = den1*den2*T */

    M(ix, h[0], sqrtm1); /* ix = X*sqrt(-1) */
    M(iy, h[1], sqrtm1); /* iy = Y*sqrt(-1) */
    M(eden, den1, invsqrtamd); /* eden = den1*sqrt(a-d) */

    M(t_z_inv, h[3], z_inv); /* t_z_inv = T*z_inv */
    rotate = isneg25519(t_z_inv);

    x_ = gf(h[0]);
    y_ = gf(h[1]);
    den_inv = gf(den2);

    cmov25519(x_, iy, rotate);
    cmov25519(y_, ix, rotate);
    cmov25519(den_inv, eden, rotate);

    M(x_z_inv, x_, z_inv);
    cneg25519(y_, y_, isneg25519(x_z_inv));

    Z(s_, h[2], y_);
    M(s_, den_inv, s_);
    abs25519(s_, s_);

    pack25519(s, s_);
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
    var inv_sqrt = gf(),
      one = gf(),
      s_ = gf(),
      ss = gf(),
      u1 = gf(),
      u2 = gf(),
      u1u1 = gf(),
      u2u2 = gf(),
      v = gf(),
      v_u2u2 = gf();
    var was_square;

    if (ristretto255_is_canonical(s) == 0) {
      return -1;
    }
    unpack25519(s_, s);
    S(ss, s_); /* ss = s^2 */

    set25519(u1, gf1); /* u1 = 1 */
    Z(u1, u1, ss); /* u1 = 1-ss */
    S(u1u1, u1); /* u1u1 = u1^2 */

    set25519(u2, gf1); /* u2 = 1 */
    A(u2, u2, ss); /* u2 = 1+ss */
    S(u2u2, u2); /* u2u2 = u2^2 */

    M(v, D, u1u1); /* v = d*u1^2 */
    neg25519(v, v); /* v = -d*u1^2 */
    Z(v, v, u2u2); /* v = -(d*u1^2)-u2^2 */

    M(v_u2u2, v, u2u2); /* v_u2u2 = v*u2^2 */

    set25519(one, gf1); /* one = 1 */
    was_square = ristretto255_sqrt_ratio_m1(inv_sqrt, one, v_u2u2);
    M(h[0], inv_sqrt, u2);
    M(h[1], inv_sqrt, h[0]);
    M(h[1], h[1], v);

    M(h[0], h[0], s_);
    A(h[0], h[0], h[0]);
    abs25519(h[0], h[0]);
    M(h[1], u1, h[1]);
    set25519(h[2], gf1); /* h->Z = 1 */
    M(h[3], h[0], h[1]);

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
    var c = gf(),
      n = gf(),
      one = gf(),
      r = gf(),
      rpd = gf(),
      s = gf(),
      s_prime = gf(),
      ss = gf(),
      u = gf(),
      v = gf(),
      w0 = gf(),
      w1 = gf(),
      w2 = gf(),
      w3 = gf();
    var wasnt_square;

    set25519(one, gf1); /* one = 1 */
    S(r, t); /* r = t^2 */
    M(r, sqrtm1, r); /* r = sqrt(-1)*t^2 */
    A(u, r, one); /* u = r+1 = sqrt(-1)*t^2 + 1 */
    M(u, u, onemsqd); /* u = (r+1)*(1-d^2) =  (sqrt(-1)*t^2 + 1) * (1-d^2)*/
    set25519(c, gf1); /* c = 1 */
    neg25519(c, c); /* c = -1 */
    A(rpd, r, D); /* rpd = r*d */
    M(v, r, D); /* v = r*d */
    Z(v, c, v); /* v = c-r*d */
    M(v, v, rpd); /* v = (c-r*d)*(r+d) */

    wasnt_square = 1 - ristretto255_sqrt_ratio_m1(s, u, v);
    M(s_prime, s, t);
    abs25519(s_prime, s_prime);
    neg25519(s_prime, s_prime); /* s_prime = -|s*t| */
    cmov25519(s, s_prime, wasnt_square);
    cmov25519(c, r, wasnt_square);

    Z(n, r, one); /* n = r-1 */
    M(n, n, c); /* n = c*(r-1) */
    M(n, n, sqdmone); /* n = c*(r-1)*(d-1)^2 */
    Z(n, n, v); /* n =  c*(r-1)*(d-1)^2-v */

    A(w0, s, s); /* w0 = 2s */
    M(w0, w0, v); /* w0 = 2s*v */
    M(w1, n, sqrtadm1); /* w1 = n*sqrt(ad-1) */
    S(ss, s); /* ss = s^2 */
    Z(w2, one, ss); /* w2 = 1-s^2 */
    A(w3, one, ss); /* w3 = 1+s^2 */

    M(p[0], w0, w3);
    M(p[1], w2, w1);
    M(p[2], w1, w3);
    M(p[3], w0, w2);
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
    var r0 = gf(),
      r1 = gf();
    var p0 = [gf(), gf(), gf(), gf()];
    var p1 = [gf(), gf(), gf(), gf()];

    unpack25519(r0, h.slice(0, 32));
    unpack25519(r1, h.slice(32, 64));
    ristretto255_elligator(p0, r0);
    ristretto255_elligator(p1, r1);

    add(p0, p1);
    return p0;
  }

  nacl.ristretto255_from_hash = ristretto255_from_hash;
  nacl.ristretto255_tobytes = ristretto255_tobytes;
  nacl.scalarmodL = scalarmodL;
  nacl.invmodL = invmodL;
  nacl.ristretto255_frombytes = ristretto255_frombytes;
};

let obj = {};
nacl_function(obj);
module.exports = obj;
