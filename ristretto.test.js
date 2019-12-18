var nacl = require('./nacl.min');
var ristretto = require('./ristretto.min');
var lowlevel = nacl.lowlevel;

/***
 *** Tests
 ***/

// Copied here not to expose L from lowlevel solely for the testing purposes
var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

/* Helper functions */
/* Padding the string s to size with leading zeroes, returns resulting string */
function pad(s, size) {
  var res = s + '';
  while (res.length < size) res = '0' + res;
  return res;
}

/* Takes in a hex string and returns a parsed byte array */
function hexToByteArray(hexString) {
  var result = [];
  for (var i = 0; i < hexString.length; i += 2) {
    result.push(parseInt(hexString.substr(i, 2), 16));
  }
  return result;
}

/* Takes in a byte array and returns a hex string */
function byteArrayToHex(byteArray) {
  return Array.from(byteArray, function(byte) {
    return pad((byte & 0xff).toString(16), 2);
  }).join('');
}

/* Takes a field element, which is of type Float64Array(16), and returns a corresponding hex string */
function gfToHex(byteArray) {
  var s = new Uint8Array(32);
  lowlevel.pack25519(s, byteArray);
  return Array.from(s, function(byte) {
    return pad((byte & 0xff).toString(16), 2);
  }).join('');
}

/* Checking for ristretto test vectors from https://ristretto.group/test_vectors/ristretto255.html */
var encodings_of_small_multiples = [
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
  'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e',
];

var P = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
var p = new Uint8Array(32); // for ristretto encoding
var Q = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
var q = new Uint8Array(32); // for ristretto encoding

test('Ristretto official: Checking encodings of small multiples', () => {
  for (i = 0; i < 16; i++) {
    lowlevel.scalarbase(P, lowlevel.gf([i]));
    var res = byteArrayToHex(ristretto.ristretto255_tobytes(P));
    expect(res).toBe(encodings_of_small_multiples[i]);
  }
});

var bad_encodings = [
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
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

/* Testing for bad encodings */
test('Ristretto official: Checking bad encodings', () => {
  for (i = 0; i < bad_encodings.length; i++) {
    var res = ristretto.ristretto255_frombytes(
      P,
      hexToByteArray(bad_encodings[i]),
    );
    expect(res).toBe(-1);
  }
});

/* Testing for good encodings: using the small multiples of the base point */
test('Ristretto official: Checking good encodings', () => {
  for (i = 0; i < encodings_of_small_multiples.length; i++) {
    var res = ristretto.ristretto255_frombytes(
      P,
      hexToByteArray(encodings_of_small_multiples[i]),
    );
    expect(res).not.toBe(-1);
  }
});

var labels = [
  'Ristretto is traditionally a short shot of espresso coffee',
  'made with the normal amount of ground coffee but extracted with',
  'about half the amount of water in the same amount of time',
  'by using a finer grind.',
  'This produces a concentrated shot of coffee per volume.',
  'Just pulling a normal shot short will produce a weaker shot',
  'and is not a Ristretto as some believe.',
];

var intermediate_hash = [
    "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
    "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
    "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
    "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
    "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
    "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
    "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
];

var encoded_hash_to_points = [
  '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
  'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
  '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
  'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
  'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
  'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
  '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065',
];

const crypto = require('crypto');

test('Ristretto official: Checking hash-to-point', () => {
  for (i = 0; i < 7; i++) {
    var h = crypto
      .createHash('sha512')
      .update(labels[i])
	.digest();
    expect(byteArrayToHex(h)).toBe(intermediate_hash[i]);
    var res = byteArrayToHex(
      ristretto.ristretto255_tobytes(ristretto.ristretto255_from_hash(h)),
    );
    expect(res).toBe(encoded_hash_to_points[i]);
  }
});

var pw = ['cGFzc3dvcmQ='];
var blindingFactor = ['54hgABn0JeElU/fiOjjhO8jdiYcKJqJAdSlWoY1+iQY=']; // r
var randomizedPassword = ['iNdgMEUV99xJaPkniZHZmaZXO2LaHxGhfWwfcNPWE2w=']; // H(pw)^r
var salt = ['n2ehSWUoDHyAY+AcuqywpgCGTTY7Jt60/nqzqOTMPg4='];
var randomizedSaltedPassword = ['/nQlZdwWLNW4lVKh7iwRcZEO2A85ocf7HGwPe1w3ui8=']; // H(pw)^{r * salt}
var blindingFactorInverse = ['OELnLADQnysgl00DEV6DHg3Hkkt1+lQNMDaNyuWuTwk=']; // 1/r
var Hmsalt = ['nFFEP+9sKmEnnOKnu4rXV0z16VHDaus8irP224XYBVA=']; // H(pw)^salt
var HmHmsalt = [
  'spdNB+lRije70KwqbDI8+9hBpDStqdU30n4sEPByRzi2ZFUs2xqLom1h95AznvrD9u3vzrD+QDKcX7QPsHd5zQ==',
]; // H(pw, H(pw)^salt)

test('Checking PAKE', () => {
  for (i = 0; i < pw.length; i++) {
    var pwd = new Buffer(pw[i], 'base64');
    var r = new Buffer(blindingFactor[i], 'base64');
    var s = new Buffer(salt[i], 'base64');
    var inv_r_exp = new Buffer(blindingFactorInverse[i], 'base64');
    var Hmsalt_exp = new Buffer(Hmsalt[i], 'base64');

    /* h1 = H(pw) */
    var h1 = ristretto.ristretto255_from_hash(
      crypto
        .createHash('sha512')
        .update(pwd)
        .digest(),
    );

    /* h2 = H(pw)^r */
    var h2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarmult(h2, h1, r);
    expect(
      new Buffer(ristretto.ristretto255_tobytes(h2)).toString('base64'),
    ).toBe(randomizedPassword[i]);

    /* h3 = (H(pw)^r)^salt */
    var h3 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarmult(h3, h2, s);
    expect(
      new Buffer(ristretto.ristretto255_tobytes(h3)).toString('base64'),
    ).toBe(randomizedSaltedPassword[i]);

    /* h6 = H(pw)^salt */
    h1 = ristretto.ristretto255_from_hash(
      crypto
        .createHash('sha512')
        .update(pwd)
        .digest(),
    );
    var h6 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarmult(h6, h1, s);
    expect(
      new Buffer(ristretto.ristretto255_tobytes(h6)).toString('base64'),
    ).toBe(Hmsalt[i]);

    /* inv_r = 1/r */
    var inv_r = ristretto.scalarmodL();
    ristretto.invmodL(inv_r, r);
    var one = ristretto.scalarmodL();
    ristretto.MmodL(one, r, inv_r);
    expect(ristretto.scalarmodL1.toString()).toBe(one.toString());
    ristretto.MmodL(one, r, inv_r_exp);
    expect(byteArrayToHex(inv_r_exp)).toBe(byteArrayToHex(inv_r));

    /* h4 = h3^inv_r */
    var h4 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarmult(h4, h3, inv_r);
    expect(byteArrayToHex(ristretto.ristretto255_tobytes(h6))).toBe(
      byteArrayToHex(ristretto.ristretto255_tobytes(h4)),
    );

    var h5 = crypto
      .createHash('sha512')
      .update(pwd)
      .update(ristretto.ristretto255_tobytes(h4))
      .digest();
    expect(h5.toString('base64')).toBe(HmHmsalt[i]);
  }
});

/***
 *** High-level ristretto functions that only operate on serialized ristretto points
 *** Note: if the inputs to the functions are not valid (as per spec), the function's behaviour is undefined, it can crash or throw an error.
 ***/

/**
 * Multiply base point by scalar
 *
 * @param {Float64Array(32)} n - scalar mod L
 * @return {Uint8Array(32)} serialized ristretto point
 */
function crypto_scalarmult_ristretto255_base(n) {    
    var Q = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    // TODO: do we need to erase the most significant bit as below?
    /*
    var t = new Uint8Array(32);
    var i;
    for (i = 0; i < 32; i++) {
	t[i] = n[i];
    }
    t[31] &= 127;
    */

    lowlevel.scalarbase(Q, n); // Q = BASE * n
    return ristretto.ristretto255_tobytes(Q);
}

/**
 * Multiply given point by scalar
 *
 * @param {Float64Array(32)} n - scalar mod L
 * @param {Uint8Array(32)} p - serialized ristretto point
 * @return {Uint8Array(32)} serialized ristretto point (p * n)
 */
function crypto_scalarmult_ristretto255(n, p) {
    var Q = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var P = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    
    if (ristretto.ristretto255_frombytes(P, p) != 0) {
	throw "Invalid argument";
    }
    // TODO: do we need to crop the scalar n[31] &= 127 ?
    lowlevel.scalarmult(Q, P, n); // Q = P * n
    return ristretto.ristretto255_tobytes(Q);
}

/**
 * Checking if the input array of bytes represents a serialization of a ristretto point
 *
 * @param {Uint8Array(32)} p byte array
 * @return {int} 1 on success, 0 on failure.
 */
function crypto_core_ristretto255_is_valid_point(p) {    
    var P = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    if (ristretto.ristretto255_frombytes(P, p) == -1) {
	return 0;
    }
    return 1;
}

/**
 * Adding two ristretto points
 *
 * @param {Uint8Array(32)} p byte array - serialized ristretto point
 * @param {Uint8Array(32)} q byte array - serialized ristretto point
 * @return {Uint8Array(32)} serialized ristretto point (p+q)
 */
function crypto_core_ristretto255_add(p, q) {
    var P = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var Q = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];

    if (ristretto.ristretto255_frombytes(P, p) == -1) {
	throw "Invalid argument";
    }
    if (ristretto.ristretto255_frombytes(Q, q) == -1) {
	throw "Invalid argument";
    }

    var R = [P[0], P[1], P[2], P[3]];
    lowlevel.add(R, Q); // R = P + Q
    return ristretto.ristretto255_tobytes(R);
}

// Subtracting two ed25519 points - this function is symmetrical to lowlevel.add
// P := P - Q
function sub(P, Q) {
    // negate Q: -(x,y,z,t) = (-x, y, z, -t)
    var negQ3 = lowlevel.gf();
    ristretto.neg25519(negQ3, Q[3]);
    var negQ0 = lowlevel.gf();
    ristretto.neg25519(negQ0, Q[0]);
    var negQ = [negQ0, Q[1], Q[2], negQ3];
    lowlevel.add(P, negQ);    
}

/**
 * Subtracting two ristretto points
 *
 * @param {Uint8Array(32)} p byte array - serialized ristretto point
 * @param {Uint8Array(32)} q byte array - serialized ristretto point
 * @return {Uint8Array(32)} serialized ristretto point (p-q)
 */
function crypto_core_ristretto255_sub(p, q) {
    var P = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var Q = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];

    if (ristretto.ristretto255_frombytes(P, p) == -1) {
	throw "Invalid argument";
    }
    if (ristretto.ristretto255_frombytes(Q, q) == -1) {
	throw "Invalid argument";
    }

    var R = [P[0], P[1], P[2], P[3]];
    sub(R, Q); // R = P - Q
    return ristretto.ristretto255_tobytes(R);
}

/**
 * Generating a random ristretto point
 * NB: Defining for convenience though the function can make it upstream
 *
 * @param none
 * @return {[Float64Array(16), Float64Array(16), Float64Array(16), Float64Array(16)]} The resulting Ed25519 elliptic-curve point.
 */
function ristretto255_random() {
    // create a random hash string
    var h = crypto.randomBytes(64);
    return ristretto.ristretto255_from_hash(h);
}

/**
 * Creating and serializing a ristretto point from a hash
 *
 * @param {Uint8Array(64)} h 64 elements byte array such as the output of SHA512.
 * @return {Uint8Array(32)} serialized ristretto point
 */
function crypto_core_ristretto255_from_hash(h) {
    return ristretto.ristretto255_tobytes(ristretto.ristretto255_from_hash(h));
}

/**
 * Generating a random serialized ristretto point
 *
 * @param none
 * @return {Uint8Array(32)} serialized random ristretto point
 */
function crypto_core_ristretto255_random() {
    return ristretto.ristretto255_tobytes(ristretto255_random())
}

/**
 * Generating a random scalar: a random number in the interval [0, L) via rejection sampling
 *
 * @return {Uint8Array(32)} serialized ed25519 scalar
 */
function random_scalar_modL() {
    var r;
    // rejection sampling loop with constant-time body
    do {
	r = crypto.randomBytes(32);
        r[31] &= 0x1f;

	// constant-time check for r < L, if so break and return r
	var i = 32;
	var n = 1;
	var c = 0;
	do {
            i--;
            c |= ((r[i] - L[i]) >> 8) & n;
            n &= ((r[i] ^ L[i]) - 1) >> 8;
	} while (i != 0);

    } while (c == 0);

    var res = new Float64Array(32);
    // converting from Buffer to the correct type to avoid confusion
    for (i = 0; i < 32; i++) res[i] = r[i];
    return res;
}

/**
 * Generating a random scalar mod L
 *
 * @return {Float64Array(32)} scalar mod L
 */
function crypto_core_ristretto255_scalar_random() {
    return random_scalar_modL();
}

/**
 * Inverting scalar modL
 *
 * @param {Float64Array(32)} s - scalar mod L to invert
 * @return {Float64Array(32)} inverted scalar 1/s
 */
function crypto_core_ristretto255_scalar_invert(s) {
    var res = new Float64Array(32);
    ristretto.invmodL(res, s);
    return res;
}

function crypto_core_ristretto255_scalar_negate(neg, s) {
    throw "Undefined";
    // ed25519_scalar_negate(neg, s);
}

function crypto_core_ristretto255_scalar_complement(comp, s) {    
    // ed25519_scalar_complement(comp, s);
    throw "Undefined";
}

function crypto_core_ristretto255_scalar_add(z, x, y) {    
    // ed25519_scalar_add(z, x, y);
    throw "Undefined";
}

function crypto_core_ristretto255_scalar_sub(z, x, y) {
    // ed25519_scalar_sub(z, x, y);
    throw "Undefined";
}

/**
 * Multiplying two scalar modL.
 *
 * @param {Float64Array(32)} x - scalar mod L
 * @param {Float64Array(32)} y - scalar mod L
 * @return {Float64Array(32)} (x * y) mod L
 */
function crypto_core_ristretto255_scalar_mul(x, y) {
    var res = new Float64Array(64);
    ristretto.MmodL(res, x, y);
    return res;
}

function crypto_core_ristretto255_scalar_reduce(r, s) {
    // ed25519_scalar_reduce(r, s);
    throw "Undefined";
}

/**
 * Testing if the input byte array is all zeroes
 *
 * @param {Uint8Array} arr byte array
 * @return 1 iff arr is all zeroes
 */
function test_is_zero_array(arr) {
    var i;
    var d = 0;
    for (i = 0; i < arr.length; i++) {
        d |= arr[i];
    }
    return 1 & ((d - 1) >> 8);
}

// Porting libsodium test tv3 https://github.com/jedisct1/libsodium/blob/master/test/default/core_ristretto255.c#L110
test('Fuzzy checking ristretto ops', () => {
    for (i = 0; i < 100; i++) {
	// s := random_scalar * BASE
        var r = crypto_core_ristretto255_scalar_random();
	var s = crypto_scalarmult_ristretto255_base(r);
	// test s is valid
	expect(crypto_core_ristretto255_is_valid_point(s)).toBe(1);
	
	// s := random
        s = crypto_core_ristretto255_random();
	// test s is valid
	expect(crypto_core_ristretto255_is_valid_point(s)).toBe(1);

	// s := s * L
        s = crypto_scalarmult_ristretto255(L, s);
	// test s == 0
	expect(test_is_zero_array(s)).toBe(1);

	// crypto_core_ristretto255_HASHBYTES = 64
	// crypto_core_ristretto255_BYTES = 32
	// crypto_core_ristretto255_SCALARBYTES = 32
	// crypto_core_ristretto255_NONREDUCEDSCALARBYTES = 64 - why we even need non-reduced scalars?

	// s := from hash h
	var h = crypto.randomBytes(64);
	s = crypto_core_ristretto255_from_hash(h);
	// test s is valid
	expect(crypto_core_ristretto255_is_valid_point(s)).toBe(1);

	// s := s * L
        s = crypto_scalarmult_ristretto255(L, s);
	// test s == 0
	expect(test_is_zero_array(s)).toBe(1);

	// s2 := s * r
	var s2 = crypto_scalarmult_ristretto255(r, s);
	// test s2 is valid
	expect(crypto_core_ristretto255_is_valid_point(s2)).toBe(1);

	// s_ := s2 * (1/r)
        var r_inv = crypto_core_ristretto255_scalar_invert(r);
	var s_ = crypto_scalarmult_ristretto255(r_inv, s2);
	// test s_ is valid
	expect(crypto_core_ristretto255_is_valid_point(s_)).toBe(1);

	// test s_ == s
	// both s_ and s are of type Uint8Array(32)
	var j;
	for (j = 0; j < 32; j++) {
	    expect(s_[j]).toBe(s[j]);
	}

	// s2 := s2 * L
        s2 = crypto_scalarmult_ristretto255(L, s2);
	// test s2 == 0
	expect(test_is_zero_array(s2)).toBe(1);

	// s2 := s + s
	s2 = crypto_core_ristretto255_add(s, s_);
	// test s2 is valid
	expect(crypto_core_ristretto255_is_valid_point(s2)).toBe(1);	
	// s2 := s2 - s
        s2 = crypto_core_ristretto255_sub(s2, s_);
	// test s2 is valid
	expect(crypto_core_ristretto255_is_valid_point(s2)).toBe(1);	
	// test s2 == s
	for (j = 0; j < 32; j++) {
	    expect(s2[j]).toBe(s[j]);
	}

	// s2 := s2 - s
        s2 = crypto_core_ristretto255_sub(s2, s_);
	// test s2 is valid
	expect(crypto_core_ristretto255_is_valid_point(s2)).toBe(1);	
	// test s2 == 0
	expect(test_is_zero_array(s2)).toBe(1);

	s = crypto_core_ristretto255_random();
	s_ = new Uint8Array([
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe
	]);
	// test s_ is invalid
	expect(crypto_core_ristretto255_is_valid_point(s_)).toBe(0);

	// add should throw an exception on invalid inputs
	try {
	    crypto_core_ristretto255_add(s_, s);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    crypto_core_ristretto255_add(s, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    crypto_core_ristretto255_add(s_, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    s2 = crypto_core_ristretto255_add(s, s);
	} catch (err) {
	    expect(0).toBe(1);
	}
	
	// sub should throw an exception on invalid inputs
	try {
	    crypto_core_ristretto255_sub(s_, s);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    crypto_core_ristretto255_sub(s, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    crypto_core_ristretto255_sub(s_, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    s2 = crypto_core_ristretto255_sub(s, s);
	} catch (err) {
	    expect(0).toBe(1);
	}
    }
});
