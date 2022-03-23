/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import nacl from 'tweetnacl';
import testDalekScalars from '../data/scalars.data';
import testDalek from '../data/ristretto.data';

const ristretto255 = require('./ristretto255').default;

const { lowlevel } = nacl;

/**
 * Helper functions for tests
 */

// eslint-disable-next-line no-restricted-globals
let crypto = typeof self !== 'undefined' ? self.crypto || self.msCrypto : null;
if ((!crypto || !crypto.getRandomValues) && typeof require !== 'undefined') {
  // eslint-disable-next-line global-require
  crypto = require('crypto');
}

/**
 * Function scalarmodL creates an array of 32 element Float64Array(32) for representing points mod L
 */
function scalarmodL(init) {
  let i;
  const r = new Float64Array(32);
  if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
  return r;
}

/**
 * Constant scalars of type Float64Array(32)
 */
const scalarmodL1 = scalarmodL([1]);
const scalarmodL0 = scalarmodL([0]);

/* Helper functions */
/* Padding the string s to size with leading zeroes, returns resulting string */
function pad(s, size) {
  let res = `${s}`;
  while (res.length < size) res = `0${res}`;
  return res;
}

/* Takes in a hex string and returns a parsed byte array */
function hexToByteArray(hexString) {
  const result = [];
  for (let i = 0; i < hexString.length; i += 2) {
    result.push(parseInt(hexString.substr(i, 2), 16));
  }
  return result;
}

/* Takes in a byte array and returns a hex string */
function byteArrayToHex(byteArray) {
  return Array.from(byteArray, function f(byte) {
    return pad((byte & 0xff).toString(16), 2);
  }).join('');
}

/**
 * Testing if the input byte array is all zeroes
 *
 * @param {Uint8Array} arr byte array
 * @return 1 iff arr is all zeroes
 */
function testIsZeroArray(arr) {
  let i;
  let d = 0;
  for (i = 0; i < arr.length; i++) {
    d |= arr[i];
  }
  return 1 & ((d - 1) >> 8);
}

/**
 * Testing if the two scalars are the same
 *
 * @param {Float64Array(32)} x
 * @param {Float64Array(32)} y
 * @return 1 iff x == y
 */
function testScalarEq(x, y) {
  let i;
  for (i = 0; i < 32; i++) {
    if (x[i] !== y[i]) {
      return 0;
    }
  }
  return 1;
}

/** *
 *** Tests
 ** */

// Testing scalar operations against test vectors
test('Scalars: add, sub, mul, invert, negate', () => {
  for (let i = 0; i < testDalekScalars.length; i++) {
    const a = testDalekScalars[i][0];
    const b = testDalekScalars[i][1];

    let resExp = testDalekScalars[i][2];
    let res = ristretto255.scalar.add(a, b);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalekScalars[i][3];
    res = ristretto255.scalar.sub(a, b);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalekScalars[i][4];
    res = ristretto255.scalar.mul(a, b);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalekScalars[i][5];
    res = ristretto255.scalar.invert(a);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalekScalars[i][6];
    res = ristretto255.scalar.invert(b);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalekScalars[i][7];
    res = ristretto255.scalar.negate(a);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalekScalars[i][8];
    res = ristretto255.scalar.negate(b);
    expect(resExp.toString()).toBe(res.toString());
  }
});

// Testing ristretto operations against test vectors
test('Ristretto: add, sub, scalarMultBase, scalarMult, fromHash, isValid', () => {
  for (let i = 0; i < testDalek.ristretto_ops.length; i++) {
    const a = testDalek.ristretto_ops[i][0];
    const b = testDalek.ristretto_ops[i][1];

    let resExp = testDalek.ristretto_ops[i][2];
    let res = ristretto255.add(a, b);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalek.ristretto_ops[i][3];
    res = ristretto255.sub(a, b);
    expect(resExp.toString()).toBe(res.toString());

    let s = testDalek.ristretto_ops[i][4];

    resExp = testDalek.ristretto_ops[i][5];
    res = ristretto255.scalarMultBase(s);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalek.ristretto_ops[i][6];
    res = ristretto255.scalarMult(s, a);
    expect(resExp.toString()).toBe(res.toString());

    resExp = testDalek.ristretto_ops[i][7];
    res = ristretto255.scalarMult(s, b);
    expect(resExp.toString()).toBe(res.toString());

    s = testDalek.ristretto_ops[i][8];
    resExp = testDalek.ristretto_ops[i][9];
    res = ristretto255.fromHash(s);
    expect(resExp.toString()).toBe(res.toString());
  }

  for (let i = 1; i < testDalek.ristretto_valid_or_not.length; i++) {
    const a = testDalek.ristretto_valid_or_not[i][0];
    const resExp = testDalek.ristretto_valid_or_not[i][1];
    const res = ristretto255.isValid(a);
    expect(resExp.toString()).toBe(res.toString());
  }
});

const FUZZY_TESTS_ITERATIONS_NUMBER = 5;

/* Checking for ristretto test vectors from https://ristretto.group/test_vectors/ristretto255.html */
const encodingsOfSmallMultiples = [
  // This is the identity point
  '0000000000000000000000000000000000000000000000000000000000000000',
  // This is the basepoint
  'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
  // These are small multiples of the basepoint
  '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
  '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
  'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57',
  'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e',
  'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403',
  '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d',
  '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c',
  '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031',
  '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f',
  'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42',
  'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460',
  'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f',
  '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e',
  'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e'
];

const P = ristretto255.unsafe.point.alloc();

test('Ristretto official: Checking encodings of small multiples', () => {
  for (let i = 0; i < 16; i++) {
    lowlevel.scalarbase(P, lowlevel.gf([i]));
    const res = byteArrayToHex(ristretto255.unsafe.point.toBytes(P));
    expect(res).toBe(encodingsOfSmallMultiples[i]);
  }
});

const badEncodings = [
  // These are all bad because they're non-canonical field encodings.
  '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  // These are all bad because they're negative field elements.
  '0100000000000000000000000000000000000000000000000000000000000000',
  '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
  'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
  'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
  '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
  'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
  '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',
  // These are all bad because they give a nonsquare x^2.
  '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
  '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
  'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
  'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
  '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
  'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
  '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
  '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
  // These are all bad because they give a negative xy value.
  '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
  'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
  'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
  '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
  '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
  '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
  '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
  '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
  // This is s = -1, which causes y = 0.
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
];

/* Testing for bad encodings */
test('Ristretto official: Checking bad encodings', () => {
  for (let i = 0; i < badEncodings.length; i++) {
    const res = ristretto255.unsafe.point.fromBytes(
      P,
      hexToByteArray(badEncodings[i])
    );
    expect(res).toBe(-1);
  }
});

/* Testing for good encodings: using the small multiples of the base point */
test('Ristretto official: Checking good encodings', () => {
  for (let i = 0; i < encodingsOfSmallMultiples.length; i++) {
    const res = ristretto255.unsafe.point.fromBytes(
      P,
      hexToByteArray(encodingsOfSmallMultiples[i])
    );
    expect(res).not.toBe(-1);
  }
});

const labels = [
  'Ristretto is traditionally a short shot of espresso coffee',
  'made with the normal amount of ground coffee but extracted with',
  'about half the amount of water in the same amount of time',
  'by using a finer grind.',
  'This produces a concentrated shot of coffee per volume.',
  'Just pulling a normal shot short will produce a weaker shot',
  'and is not a Ristretto as some believe.'
];

const intermediateHash = [
  '5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6',
  'f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38',
  '8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c',
  'ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf',
  '165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413',
  'a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c',
  '2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982'
];

const encodedHashToPoints = [
  '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
  'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
  '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
  'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
  'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
  'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
  '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065'
];

test('Ristretto official: Checking hash-to-point', () => {
  for (let i = 0; i < 7; i++) {
    const h = crypto
      .createHash('sha512')
      .update(labels[i])
      .digest();
    expect(byteArrayToHex(h)).toBe(intermediateHash[i]);
    const res = byteArrayToHex(
      ristretto255.unsafe.point.toBytes(ristretto255.unsafe.point.fromHash(h))
    );
    expect(res).toBe(encodedHashToPoints[i]);
  }
});

// Porting libsodium test tv3 https://github.com/jedisct1/libsodium/blob/master/test/default/core_ristretto255.c#L110
test('Fuzzy checking ristretto ops (libsodium tv3)', () => {
  for (let i = 0; i < FUZZY_TESTS_ITERATIONS_NUMBER; i++) {
    // s := random_scalar * BASE
    const r = ristretto255.scalar.getRandom();
    let s = ristretto255.scalarMultBase(r);
    // test s is valid
    expect(ristretto255.isValid(s)).toBe(true);

    // s := random
    s = ristretto255.getRandom();
    // test s is valid
    expect(ristretto255.isValid(s)).toBe(true);

    // s := s * L
    s = ristretto255.scalarMult(lowlevel.L, s);
    // test s == 0
    expect(testIsZeroArray(s)).toBe(1);

    // s := from hash h
    let h = new Uint8Array(64);
    // let h = crypto.randomBytes(64);
    h = nacl.randomBytes(64);
    s = ristretto255.fromHash(h);
    // test s is valid
    expect(ristretto255.isValid(s)).toBe(true);

    // s := s * L
    s = ristretto255.scalarMult(lowlevel.L, s);
    // test s == 0
    expect(testIsZeroArray(s)).toBe(1);

    // s2 := s * r
    let s2 = ristretto255.scalarMult(r, s);
    // test s2 is valid
    expect(ristretto255.isValid(s2)).toBe(true);

    // sVar := s2 * (1/r)
    const rInv = ristretto255.scalar.invert(r);
    let sVar = ristretto255.scalarMult(rInv, s2);
    // test sVar is valid
    expect(ristretto255.isValid(sVar)).toBe(true);

    // test sVar == s
    // both sVar and s are of type Uint8Array(32)
    for (let j = 0; j < 32; j++) {
      expect(sVar[j]).toBe(s[j]);
    }

    // s2 := s2 * L
    s2 = ristretto255.scalarMult(lowlevel.L, s2);
    // test s2 == 0
    expect(testIsZeroArray(s2)).toBe(1);

    // s2 := s + s
    s2 = ristretto255.add(s, sVar);
    // test s2 is valid
    expect(ristretto255.isValid(s2)).toBe(true);
    // s2 := s2 - s
    s2 = ristretto255.sub(s2, sVar);
    // test s2 is valid
    expect(ristretto255.isValid(s2)).toBe(true);
    // test s2 == s
    for (let j = 0; j < 32; j++) {
      expect(s2[j]).toBe(s[j]);
    }

    // s2 := s2 - s
    s2 = ristretto255.sub(s2, sVar);
    // test s2 is valid
    expect(ristretto255.isValid(s2)).toBe(true);
    // test s2 == 0
    expect(testIsZeroArray(s2)).toBe(1);

    s = ristretto255.getRandom();
    sVar = new Uint8Array(32);
    sVar.fill(0xfe);
    // test sVar is invalid
    expect(ristretto255.isValid(sVar)).toBe(false);

    // add should throw an exception on invalid inputs
    try {
      ristretto255.add(sVar, s);
      expect(0).toBe(1);
    } catch (err) {
      // empty
    }
    try {
      ristretto255.add(s, sVar);
      expect(0).toBe(1);
    } catch (err) {
      // empty
    }
    try {
      ristretto255.add(sVar, sVar);
      expect(0).toBe(1);
    } catch (err) {
      // empty
    }
    try {
      s2 = ristretto255.add(s, s);
    } catch (err) {
      expect(0).toBe(1);
    }

    // sub should throw an exception on invalid inputs
    try {
      ristretto255.sub(sVar, s);
      expect(0).toBe(1);
    } catch (err) {
      // empty
    }
    try {
      ristretto255.sub(s, sVar);
      expect(0).toBe(1);
    } catch (err) {
      // empty
    }
    try {
      ristretto255.sub(sVar, sVar);
      expect(0).toBe(1);
    } catch (err) {
      // empty
    }
    try {
      s2 = ristretto255.sub(s, s);
    } catch (err) {
      expect(0).toBe(1);
    }
  }
});

// Porting libsodium test tv4 https://github.com/jedisct1/libsodium/blob/master/test/default/core_ristretto255.c#L210
test('Fuzzy checking ristretto ops (libsodium tv4)', () => {
  for (let i = 0; i < FUZZY_TESTS_ITERATIONS_NUMBER; i++) {
    // s1 := random
    let s1 = ristretto255.scalar.getRandom();
    // s2 := random
    let s2 = ristretto255.scalar.getRandom();
    // s3 := s1 + s2
    const s3 = ristretto255.scalar.add(s1, s2);
    // s4 := s1 - s2
    let s4 = ristretto255.scalar.sub(s1, s2);
    // s2 := s3 + s4 == 2 * org_s1
    s2 = ristretto255.scalar.add(s3, s4);
    // s2 := s2 - s1 == org_s1
    s2 = ristretto255.scalar.sub(s2, s1);
    // s2 := s3 * s2 == (org_s1 + org_s2) * org_s1
    s2 = ristretto255.scalar.mul(s3, s2);
    // s4 = 1/s3 == 1 / (org_s1 + org_s2)
    s4 = ristretto255.scalar.invert(s3);
    // s2 := s2 * s4 == org_s1
    s2 = ristretto255.scalar.mul(s2, s4);
    // s1 := -s1 == -org_s1
    s1 = ristretto255.scalar.negate(s1);
    // s2 := s2 + s1 == 0
    s2 = ristretto255.scalar.add(s2, s1);
    // test s2 == 0
    expect(testIsZeroArray(s2)).toBe(1);
  }
});

// Test basepoint round trip: serialization/deserialization
test('Ristretto base point round trip', () => {
  const BASE = ristretto255.unsafe.point.alloc();
  lowlevel.scalarbase(BASE, scalarmodL1);
  const base = ristretto255.unsafe.point.toBytes(BASE);
  const BASE2 = ristretto255.unsafe.point.alloc();
  const res = ristretto255.unsafe.point.fromBytes(BASE2, base);
  expect(res).not.toBe(-1);
  const base2 = ristretto255.unsafe.point.toBytes(BASE2);
  // test base == base2
  for (let j = 0; j < 32; j++) {
    expect(base[j]).toBe(base2[j]);
  }
});

// Test random point round trip: serialization/deserialization
test('Ristretto random point round trip', () => {
  for (let i = 0; i < FUZZY_TESTS_ITERATIONS_NUMBER; i++) {
    const RANDOM = ristretto255.unsafe.point.getRandom();
    const random = ristretto255.unsafe.point.toBytes(RANDOM);
    const RANDOM2 = [
      lowlevel.gf(),
      lowlevel.gf(),
      lowlevel.gf(),
      lowlevel.gf()
    ];
    const res = ristretto255.unsafe.point.fromBytes(RANDOM2, random);
    expect(res).not.toBe(-1);
    const random2 = ristretto255.unsafe.point.toBytes(RANDOM2);
    // test random == random2
    for (let j = 0; j < 32; j++) {
      expect(random[j]).toBe(random2[j]);
    }
  }
});

// Test scalar mult and add
test('Ristretto random ops', () => {
  const BASE = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
  const P1 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
  const P2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
  lowlevel.scalarbase(BASE, scalarmodL1);
  // console.log("BASE = " + ristretto255.unsafe.point.toBytes(BASE));
  const s1 = new Float64Array(32);
  s1[0] = 33;
  const s2 = new Float64Array(32);
  s2[0] = 66;
  // P1 := BASE * s1
  lowlevel.scalarmult(P1, BASE, s1);
  // P1 := P1 + P1
  lowlevel.add(P1, P1);
  // P2 := BASE * s2
  lowlevel.scalarbase(BASE, scalarmodL1);
  lowlevel.scalarmult(P2, BASE, s2);

  expect(byteArrayToHex(ristretto255.unsafe.point.toBytes(P1))).toBe(
    byteArrayToHex(ristretto255.unsafe.point.toBytes(P2))
  );
});

// Test scalar mult and scalar inverse near the modulus
test('Ristretto ops corner cases', () => {
  const s = new Float64Array(32);
  for (let i = 0; i < 32; i++) {
    s[i] = lowlevel.L[i];
  }

  const BASE = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
  const P1 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
  const P2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
  lowlevel.scalarbase(BASE, scalarmodL1);
  const s1 = new Float64Array(32);
  s1[0] = 33;
  const s2 = new Float64Array(32);
  s2[0] = 66;
  // P1 := BASE * s1
  lowlevel.scalarmult(P1, BASE, s1);
  // P1 := P1 + P1
  lowlevel.add(P1, P1);
  // P2 := BASE * s2
  lowlevel.scalarbase(BASE, scalarmodL1);
  lowlevel.scalarmult(P2, BASE, s2);

  expect(byteArrayToHex(ristretto255.unsafe.point.toBytes(P1))).toBe(
    byteArrayToHex(ristretto255.unsafe.point.toBytes(P2))
  );
});

// Test border-scalars
test('Scalar operations, corner cases', () => {
  const x = new Uint8Array(32);
  for (let i = 0; i < 32; i++) x[i] = lowlevel.L[i];

  x[0] -= 1; // x = L - 1

  const xInv = ristretto255.scalar.invert(x);
  // one = x * (1/x)
  let one = ristretto255.scalar.mul(x, xInv);
  expect(testScalarEq(scalarmodL1, one)).toBe(1);
  one = ristretto255.scalar.mul(xInv, x);
  expect(testScalarEq(scalarmodL1, one)).toBe(1);

  const zero = ristretto255.scalar.add(x, scalarmodL1);
  expect(testScalarEq(scalarmodL0, zero)).toBe(1);

  const negS = new Float64Array(32);
  // negS := L - s
  for (let i = 0; i < 32; i++) {
    negS[i] = -scalarmodL1[i];
  }
  const o = new Float64Array(32);
  lowlevel.modL(o, negS);
  const x2 = ristretto255.scalar.sub(scalarmodL0, scalarmodL1);
  expect(testScalarEq(x, x2)).toBe(1);
});

// Test constants and arithmetic on field elemenst as a bonus
test('Constants', () => {
  // a = -1, d = -121665 / 121666
  const zeroGF = lowlevel.gf();
  const oneGF = lowlevel.gf([1]);

  // LSub2 = L - 2
  let x = ristretto255.unsafe.constants.LSub2;
  let y = new Uint8Array(32); // y == 0
  y[0] = 2; // y == 2
  y = ristretto255.scalar.sub(lowlevel.L, y); // y == L - 2
  expect(testScalarEq(y, x)).toBe(1);

  y = new Float64Array(32); // y == 0
  x = new Float64Array(32); // x == 0
  // sqrtm1 == sqrt(-1)
  lowlevel.S(x, ristretto255.unsafe.constants.sqrtm1);
  const xPacked = new Float64Array(32);
  lowlevel.pack25519(xPacked, x);
  lowlevel.Z(y, zeroGF, oneGF);
  const yPacked = new Float64Array(32);
  lowlevel.pack25519(yPacked, y);
  expect(testScalarEq(xPacked, yPacked)).toBe(1);

  // D == -121665 / 121666
  lowlevel.Z(x, zeroGF, lowlevel.D); // x = -D
  lowlevel.M(x, x, lowlevel.gf([0xdb42, 1])); // x *= 121666
  lowlevel.pack25519(xPacked, x);
  lowlevel.pack25519(yPacked, lowlevel.gf([0xdb41, 1])); // y = 121665
  expect(testScalarEq(xPacked, yPacked)).toBe(1);

  // sqrtadm1 == sqrt(-D-1)
  lowlevel.Z(x, zeroGF, lowlevel.D); // x = -D
  lowlevel.Z(x, x, oneGF); // x -= 1
  lowlevel.S(y, ristretto255.unsafe.constants.sqrtadm1); // y = sqrtadm1^2
  lowlevel.pack25519(xPacked, x);
  lowlevel.pack25519(yPacked, y);
  expect(testScalarEq(xPacked, yPacked)).toBe(1);

  // invsqrtamd == 1 / sqrt(-D-1)
  lowlevel.Z(x, zeroGF, lowlevel.D); // x = -D
  lowlevel.Z(x, x, oneGF); // x -= 1
  lowlevel.S(y, ristretto255.unsafe.constants.invsqrtamd); // y = invsqrtamd^2
  lowlevel.M(x, y, x);
  lowlevel.pack25519(xPacked, x);
  lowlevel.pack25519(yPacked, oneGF);
  expect(testScalarEq(xPacked, yPacked)).toBe(1);

  // onemsqd == (1-d^2)
  lowlevel.S(x, lowlevel.D);
  lowlevel.Z(x, oneGF, x);
  lowlevel.pack25519(xPacked, x);
  lowlevel.pack25519(yPacked, ristretto255.unsafe.constants.onemsqd);
  expect(testScalarEq(xPacked, yPacked)).toBe(1);

  // sqdmone == (d-1)^2
  lowlevel.Z(x, lowlevel.D, oneGF);
  lowlevel.S(x, x);
  lowlevel.pack25519(xPacked, x);
  lowlevel.pack25519(yPacked, ristretto255.unsafe.constants.sqdmone);
  expect(testScalarEq(xPacked, yPacked)).toBe(1);

  // base point
  const one = new Uint8Array(32);
  one[0] = 1;
  const b = ristretto255.scalarMultBase(one);
  const b2 = [
    lowlevel.gf([
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
      0x2169
    ]),
    lowlevel.gf([
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
      0x6666
    ]),
    lowlevel.gf([1]),
    lowlevel.gf()
  ];
  lowlevel.M(b2[3], b2[0], b2[1]);

  const b3 = ristretto255.unsafe.point.toBytes(b2);
  expect(testScalarEq(b3, b)).toBe(1);
  expect(testScalarEq(ristretto255.basePoint, b)).toBe(1);
});
