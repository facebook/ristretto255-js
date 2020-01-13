var nacl = require('./nacl.js').default;
var ristretto = require('./ristretto.min.js');
var lowlevel = nacl.lowlevel;

/***
 *** Helper functions for Tests
 ***/

// const crypto = require('crypto');
var crypto = typeof self !== 'undefined' ? (self.crypto || self.msCrypto) : null;
if ((!crypto || !crypto.getRandomValues) && typeof require !== 'undefined') {
    crypto = require('crypto');
}

// Copied here not to expose L from lowlevel solely for the testing purposes
// TODO: remove? Use the one from nacl.lowlevel?
var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

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
var scalarmodL0 = scalarmodL([0]);


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

/**
 * Testing if the two scalars are the same
 *
 * @param {Float64Array(32)} x
 * @param {Float64Array(32)} y
 * @return 1 iff x == y
 */
function test_scalar_eq(x, y) {
    var i;
    for (i = 0; i < 32; i++) {
	if (x[i] != y[i]) {
	    return 0;
	}
    }
    return 1;
}

/***
 *** Tests
 ***/
// suggested value: 100
var FUZZY_TESTS_ITERATIONS_NUMBER = 1;

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
  for (let i = 0; i < 16; i++) {
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
  for (let i = 0; i < bad_encodings.length; i++) {
    var res = ristretto.ristretto255_frombytes(
      P,
      hexToByteArray(bad_encodings[i]),
    );
    expect(res).toBe(-1);
  }
});

/* Testing for good encodings: using the small multiples of the base point */
test('Ristretto official: Checking good encodings', () => {
  for (let i = 0; i < encodings_of_small_multiples.length; i++) {
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

test('Ristretto official: Checking hash-to-point', () => {
  for (let i = 0; i < 7; i++) {
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
  for (let i = 0; i < pw.length; i++) {
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
    var inv_r = ristretto.crypto_core_ristretto255_scalar_invert(r);
    // var inv_r = scalarmodL();
    // ristretto.invmodL(inv_r, r);
    var one = ristretto.crypto_core_ristretto255_scalar_mul(inv_r, r);
    // var one = scalarmodL();
    // ristretto.MmodL(one, r, inv_r);
    expect(scalarmodL1.toString()).toBe(one.toString());
    var one = ristretto.crypto_core_ristretto255_scalar_mul(r, inv_r_exp);
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

// Porting libsodium test tv3 https://github.com/jedisct1/libsodium/blob/master/test/default/core_ristretto255.c#L110
test('Fuzzy checking ristretto ops: libsodium tv3', () => {
    for (let i = 0; i < FUZZY_TESTS_ITERATIONS_NUMBER; i++) {
	// s := random_scalar * BASE
        var r = ristretto.crypto_core_ristretto255_scalar_random();
	var s = ristretto.crypto_scalarmult_ristretto255_base(r);
	// test s is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s)).toBe(1);

	// s := random
        s = ristretto.crypto_core_ristretto255_random();
	// test s is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s)).toBe(1);

	// s := s * L
        s = ristretto.crypto_scalarmult_ristretto255(L, s);
	// test s == 0
	expect(test_is_zero_array(s)).toBe(1);

	// s := from hash h
	var h = new Uint8Array(64);
	// var h = crypto.randomBytes(64);
	h = nacl.randomBytes(64);
	s = ristretto.crypto_core_ristretto255_from_hash(h);
	// test s is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s)).toBe(1);

	// s := s * L
        s = ristretto.crypto_scalarmult_ristretto255(L, s);
	// test s == 0
	expect(test_is_zero_array(s)).toBe(1);

	// s2 := s * r
	var s2 = ristretto.crypto_scalarmult_ristretto255(r, s);
	// test s2 is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s2)).toBe(1);

	// s_ := s2 * (1/r)
        var r_inv = ristretto.crypto_core_ristretto255_scalar_invert(r);
	var s_ = ristretto.crypto_scalarmult_ristretto255(r_inv, s2);
	// test s_ is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s_)).toBe(1);

	// test s_ == s
	// both s_ and s are of type Uint8Array(32)
	var j;
	for (let j = 0; j < 32; j++) {
	    expect(s_[j]).toBe(s[j]);
	}

	// s2 := s2 * L
        s2 = ristretto.crypto_scalarmult_ristretto255(L, s2);
	// test s2 == 0
	expect(test_is_zero_array(s2)).toBe(1);

	// s2 := s + s
	s2 = ristretto.crypto_core_ristretto255_add(s, s_);
	// test s2 is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s2)).toBe(1);
	// s2 := s2 - s
        s2 = ristretto.crypto_core_ristretto255_sub(s2, s_);
	// test s2 is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s2)).toBe(1);
	// test s2 == s
	for (let j = 0; j < 32; j++) {
	    expect(s2[j]).toBe(s[j]);
	}

	// s2 := s2 - s
        s2 = ristretto.crypto_core_ristretto255_sub(s2, s_);
	// test s2 is valid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s2)).toBe(1);
	// test s2 == 0
	expect(test_is_zero_array(s2)).toBe(1);

	s = ristretto.crypto_core_ristretto255_random();
	s_ = new Uint8Array([
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
	    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe
	]);
	// test s_ is invalid
	expect(ristretto.crypto_core_ristretto255_is_valid_point(s_)).toBe(0);

	// add should throw an exception on invalid inputs
	try {
	    ristretto.crypto_core_ristretto255_add(s_, s);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    ristretto.crypto_core_ristretto255_add(s, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    ristretto.crypto_core_ristretto255_add(s_, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    s2 = ristretto.crypto_core_ristretto255_add(s, s);
	} catch (err) {
	    expect(0).toBe(1);
	}

	// sub should throw an exception on invalid inputs
	try {
	    ristretto.crypto_core_ristretto255_sub(s_, s);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    ristretto.crypto_core_ristretto255_sub(s, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    ristretto.crypto_core_ristretto255_sub(s_, s_);
	    expect(0).toBe(1);
	} catch (err) {}
	try {
	    s2 = ristretto.crypto_core_ristretto255_sub(s, s);
	} catch (err) {
	    expect(0).toBe(1);
	}
    }
});

// Porting libsodium test tv4 https://github.com/jedisct1/libsodium/blob/master/test/default/core_ristretto255.c#L210
test('Fuzzy checking ristretto ops: libsodium tv4', () => {
    for (let i = 0; i < FUZZY_TESTS_ITERATIONS_NUMBER; i++) {
	// s1 := random
	var s1 = ristretto.crypto_core_ristretto255_scalar_random();
	// s2 := random
	var s2 = ristretto.crypto_core_ristretto255_scalar_random();
	// s3 := s1 + s2
	var s3 = ristretto.crypto_core_ristretto255_scalar_add(s1, s2);
	// s4 := s1 - s2
	var s4 = ristretto.crypto_core_ristretto255_scalar_sub(s1, s2);
	// s2 := s3 + s4 == 2 * org_s1
	s2 = ristretto.crypto_core_ristretto255_scalar_add(s3, s4);
	// s2 := s2 - s1 == org_s1
	s2 = ristretto.crypto_core_ristretto255_scalar_sub(s2, s1);
	// s2 := s3 * s2 == (org_s1 + org_s2) * org_s1
	s2 = ristretto.crypto_core_ristretto255_scalar_mul(s3, s2);
	// s4 = 1/s3 == 1 / (org_s1 + org_s2)
	s4 = ristretto.crypto_core_ristretto255_scalar_invert(s3);
	// s2 := s2 * s4 == org_s1
	s2 = ristretto.crypto_core_ristretto255_scalar_mul(s2, s4);
	// s1 := -s1 == -org_s1
	s1 = ristretto.crypto_core_ristretto255_scalar_negate(s1);
	// s2 := s2 + s1 == 0
	s2 = ristretto.crypto_core_ristretto255_scalar_add(s2, s1);
	// test s2 == 0
	expect(test_is_zero_array(s2)).toBe(1);
    }
});

// TODO: create some massive test file with vectors obtained from libsodium to cross-check compatibility

// Test basepoint round trip: serialization/deserialization
test('Ristretto base point round trip', () => {
    var BASE = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarbase(BASE, scalarmodL1);
    var base = ristretto.ristretto255_tobytes(BASE);
    var BASE2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var res = ristretto.ristretto255_frombytes(BASE2, base);
    expect(res).not.toBe(-1);
    var base2 = ristretto.ristretto255_tobytes(BASE2);
    // test base == base2
    for (let j = 0; j < 32; j++) {
	expect(base[j]).toBe(base2[j]);
    }
});

// Test random point round trip: serialization/deserialization
test('Ristretto random point round trip', () => {
    for (let i = 0; i < FUZZY_TESTS_ITERATIONS_NUMBER; i++) {
	var RANDOM = ristretto.ristretto255_random();
	var random = ristretto.ristretto255_tobytes(RANDOM);
	var RANDOM2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
	var res = ristretto.ristretto255_frombytes(RANDOM2, random);
	expect(res).not.toBe(-1);
	var random2 = ristretto.ristretto255_tobytes(RANDOM2);
	// test random == random2
	for (let j = 0; j < 32; j++) {
	    expect(random[j]).toBe(random2[j]);
	}
    }
});

// Test scalar mult and add
test('Ristretto ops', () => {
    var BASE = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var P1 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var P2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarbase(BASE, scalarmodL1);
    // console.log("BASE = " + ristretto.ristretto255_tobytes(BASE));
    var s1 = new Float64Array(32);
    s1[0] = 33;
    var s2 = new Float64Array(32);
    s2[0] = 66;
    // P1 := BASE * s1
    lowlevel.scalarmult(P1, BASE, s1);
    // P1 := P1 + P1
    lowlevel.add(P1, P1);
    // P2 := BASE * s2
    lowlevel.scalarbase(BASE, scalarmodL1);
    lowlevel.scalarmult(P2, BASE, s2);

    expect(byteArrayToHex(ristretto.ristretto255_tobytes(P1))).toBe(byteArrayToHex(ristretto.ristretto255_tobytes(P2)));
});

// Test scalar mult and scalar inverse near the modulus
test('Ristretto ops', () => {
    var s = new Float64Array(32);
    for (let i = 0; i < 32; i++) {
	s[i] = L[i];
    }

    var BASE = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var P1 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    var P2 = [lowlevel.gf(), lowlevel.gf(), lowlevel.gf(), lowlevel.gf()];
    lowlevel.scalarbase(BASE, scalarmodL1);
    // console.log("BASE = " + ristretto.ristretto255_tobytes(BASE));
    var s1 = new Float64Array(32);
    s1[0] = 33;
    var s2 = new Float64Array(32);
    s2[0] = 66;
    // P1 := BASE * s1
    lowlevel.scalarmult(P1, BASE, s1);
    // P1 := P1 + P1
    lowlevel.add(P1, P1);
    // P2 := BASE * s2
    lowlevel.scalarbase(BASE, scalarmodL1);
    lowlevel.scalarmult(P2, BASE, s2);

    expect(byteArrayToHex(ristretto.ristretto255_tobytes(P1))).toBe(byteArrayToHex(ristretto.ristretto255_tobytes(P2)));
});

// Test border-scalars
test('Scalar ops', () => {
    var x = new Float64Array(32);
    for (let i = 0; i < 32; i++) x[i] = L[i];

    x[0] -= 1; // x = L - 1

    var x_inv = ristretto.crypto_core_ristretto255_scalar_invert(x);
    // one = x * (1/x)
    var one = ristretto.crypto_core_ristretto255_scalar_mul(x, x_inv);
    expect(test_scalar_eq(scalarmodL1, one)).toBe(1);
    one = ristretto.crypto_core_ristretto255_scalar_mul(x_inv, x);
    expect(test_scalar_eq(scalarmodL1, one)).toBe(1);

    var zero = ristretto.crypto_core_ristretto255_scalar_add(x, scalarmodL1);
    expect(test_scalar_eq(scalarmodL0, zero)).toBe(1);

    var x2 = ristretto.crypto_core_ristretto255_scalar_sub(scalarmodL0, scalarmodL1);
    expect(test_scalar_eq(x, x2)).toBe(1);
});
