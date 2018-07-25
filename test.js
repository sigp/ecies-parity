var expect = require("chai").expect;
var createHash = require("crypto").createHash;
var bufferEqual = require("buffer-equal");
var ecies = require("./");
var crypto = require("crypto");

// TODO: Add more ECIES tests

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

var msg = createHash("sha256").update("test").digest();
var otherMsg = createHash("sha256").update("test2").digest();
var shortMsg = createHash("sha1").update("test").digest();

var privateKey = Buffer(32);
privateKey.fill(1);
var publicKey = ecies.getPublic(privateKey);

var privateKeyA = Buffer(32);
privateKeyA.fill(2);
var publicKeyA = ecies.getPublic(privateKeyA);

var privateKeyB = Buffer(32);
privateKeyB.fill(3);

// parity-specifc vars
var publicKeyB = ecies.getPublic(privateKeyB);
var testPrivateKey=Buffer.from('677d558860e2a5b735952b1133e6c613018fc0ad3e81d04bbf8975dd63a28258','hex');
var testReceiverPrivateKey=Buffer.from('dbd770b0ec84c57a5c2920558e1e28aac808a126822ff74401f26fdaef49c861', 'hex');
var testPubKey=ecies.getPublic(testPrivateKey);
var testReceiverPubKey= ecies.getPublic(testReceiverPrivateKey);
var testIV = Buffer.from('d0198031fcd63151667eadf3537f6a6b','hex');

// tests
describe("Key convertion", function() {
  it("should allow to convert private key to public", function() {
    expect(Buffer.isBuffer(publicKey)).to.be.true;
    expect(publicKey.toString("hex")).to.equal("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1");
  });

  it("should throw on invalid private key", function() {
    expect(ecies.getPublic.bind(null, Buffer("00", "hex"))).to.throw(Error);
    expect(ecies.getPublic.bind(null, Buffer("test"))).to.throw(Error);
  });
});

describe("ECDSA", function() {
  it("should allow to sign and verify message", function() {
    return ecies.sign(privateKey, msg).then(function(sig) {
      expect(Buffer.isBuffer(sig)).to.be.true;
      expect(sig.toString("hex")).to.equal("3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c");
      return ecies.verify(publicKey, msg, sig);
    });
  });

  it("shouldn't verify incorrect signature", function(done) {
    ecies.sign(privateKey, msg).then(function(sig) {
      expect(Buffer.isBuffer(sig)).to.be.true;
      ecies.verify(publicKey, otherMsg, sig).catch(function() {
        done();
      });
    });
  });

  it("should reject promise on invalid key when signing", function(done) {
    var k4 = Buffer("test");
    var k192 = Buffer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hex");
    var k384 = Buffer("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "hex");
    ecies.sign(k4, msg).catch(function() {
      ecies.sign(k192, msg).catch(function() {
        ecies.sign(k384, msg).catch(function() {
          done();
        });
      });
    });
  });

  it("should reject promise on invalid key when verifying", function(done) {
    ecies.sign(privateKey, msg).then(function(sig) {
      expect(Buffer.isBuffer(sig)).to.be.true;
      ecies.verify(Buffer("test"), msg, sig).catch(function() {
        var badKey = new Buffer(65);
        publicKey.copy(badKey);
        badKey[0] ^= 1;
        ecies.verify(badKey, msg, sig).catch(function() {
          done();
        });
      });
    });
  });

  it("should reject promise on invalid sig when verifying", function(done) {
    ecies.sign(privateKey, msg).then(function(sig) {
      expect(Buffer.isBuffer(sig)).to.be.true;
      sig[0] ^= 1;
      ecies.verify(publicKey, msg, sig).catch(function() {
        done();
      });
    });
  });

  it("should allow to sign and verify messages less than 32 bytes", function() {
    return ecies.sign(privateKey, shortMsg).then(function(sig) {
      expect(Buffer.isBuffer(sig)).to.be.true;
      expect(sig.toString("hex")).to.equal("304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa");
      return ecies.verify(publicKey, shortMsg, sig);
    });
  });

  it("shouldn't sign and verify messages longer than 32 bytes", function(done) {
    var longMsg = Buffer(40);
    var someSig = Buffer("304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa", "hex");
    ecies.sign(privateKey, longMsg).catch(function() {
      ecies.verify(privateKey, longMsg, someSig).catch(function(e) {
        expect(e.message).to.not.match(/bad signature/i);
        done();
      });
    });
  });

  it("shouldn't sign and verify empty messages", function(done) {
    var emptyMsg = Buffer(0);
    var someSig = Buffer("304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa", "hex");
    ecies.sign(privateKey, emptyMsg).catch(function() {
      ecies.verify(publicKey, emptyMsg, someSig).catch(function(e) {
        expect(e.message).to.not.match(/bad signature/i);
        done();
      });
    });
  });
});

describe("ECDH", function() {
  it("should derive shared secret from privkey A and pubkey B", function() {
    return ecies.derive(privateKeyA, publicKeyB).then(function(Px) {
      expect(Buffer.isBuffer(Px)).to.be.true;
      expect(Px.length).to.equal(32);
      expect(Px.toString("hex")).to.equal("aca78f27d5f23b2e7254a0bb8df128e7c0f922d47ccac72814501e07b7291886");
      return ecies.derive(privateKeyB, publicKeyA).then(function(Px2) {
        expect(Buffer.isBuffer(Px2)).to.be.true;
        expect(Px2.length).to.equal(32);
        expect(bufferEqual(Px, Px2)).to.be.true;
      });
    });
  });

  it("should reject promise on bad keys", function(done) {
    ecies.derive(Buffer("test"), publicKeyB).catch(function() {
      ecies.derive(publicKeyB, publicKeyB).catch(function() {
        ecies.derive(privateKeyA, privateKeyA).catch(function() {
          ecies.derive(privateKeyB, Buffer("test")).catch(function() {
            done();
          });
        });
      });
    });
  });

  it("should reject promise on bad arguments", function(done) {
    ecies.derive({}, {}).catch(function(e) {
      expect(e.message).to.match(/bad input/i);
      done();
    });
  });
});
describe("Cryptographic Primitives", function() { 
  it("should calculate the correct public from private keys", async function() { 
    let expectedTestPub =Buffer.from('044267ec8951b0bad54847c7d1bf913687b1db9cc4ca2817eca651a092fe073028ec0d41e0593c95d7a60bf0c39e5cdeb6e27206ec8998ba9e464e78d865b44423','hex');
    assert(Buffer.compare(expectedTestPub,testPubKey)===0, "Public key calculated from private key is incorrect");
  });

  it("should generate the correct shared key through ecdh", async function() { 
    let expectedEphemKey =Buffer.from('8bfd2daaa0c40fb835eb21a963f4bb80c757e0d6eb92ac2f84c2e133119b4fa8','hex');

    let ephemPrivKey = await ecies.derive(testPrivateKey, testReceiverPubKey);
    assert(Buffer.compare(ephemPrivKey,expectedEphemKey) === 0, "Ephemeral Key creation failed");
  });

  it("the kdf should generate the correct shared key", async function() { 
    let expectedKey =Buffer.from('9f3d21492e94e13bcb034d4e88c3b5f72f8107acf349e98a79223077c25c8710','hex');
    let ephemPrivKey = await ecies.derive(testPrivateKey, testReceiverPubKey);
    let key = await ecies.kdf(ephemPrivKey, 32);
    assert(Buffer.compare(key, expectedKey) === 0, "Key derivation function is incorrect");
  });

  it("the HMAC should be generated correctly", async function() { 
    let expectedHMAC =Buffer.from('1511c779a66cfe87f13d54edfee151292b7b7af2145cc50f2d5a29676630409d','hex');
    let ephemPrivKey = await ecies.derive(testPrivateKey, testReceiverPubKey);
    let key = await ecies.kdf(ephemPrivKey, 32);
    let cipher = await ecies.encrypt(testReceiverPubKey, Buffer.from('test'), {ephemPrivateKey: testPrivateKey, iv: testIV });
    let metaLength = 1 + 64 + 16 + 32; 
    let cipherTextLength = cipher.length - metaLength; 
    let HMAC = cipher.slice(65+16+ cipherTextLength);
    assert(Buffer.compare(HMAC, expectedHMAC) === 0, "HMAC generation incorrect.");
  });

});

describe("Encryption tests", function() {
  it("should produce the correct ciphertext",  async function() {
    let plaintext = Buffer.from('test')
    let expectedCipherText = Buffer.from('d0198031', 'hex');
    let serialisedOutput = await ecies.encrypt(testReceiverPubKey, plaintext, {ephemPrivateKey: testPrivateKey, iv: testIV });
    let metaLength = 1 + 64 + 16 + 32; 
    let cipherTextLength = serialisedOutput.length - metaLength; 
    let cipherText = serialisedOutput.slice(65, 65 + cipherTextLength);
    assert(Buffer.compare(cipherText, expectedCipherText) === 0, "Generated ciphertext is incorrect.");
  });

  it("encryption should provide correct serialised output",  async function() {
    let plaintext = Buffer.from('test')
    let expectedSerialisedOutput = Buffer.from('044267ec8951b0bad54847c7d1bf913687b1db9cc4ca2817eca651a092fe073028ec0d41e0593c95d7a60bf0c39e5cdeb6e27206ec8998ba9e464e78d865b44423d0198031fcd63151667eadf3537f6a6b2a2a6fa41511c779a66cfe87f13d54edfee151292b7b7af2145cc50f2d5a29676630409d', 'hex');
    let serialisedOutput = await ecies.encrypt(testReceiverPubKey, Buffer.from('test'), {ephemPrivateKey: testPrivateKey, iv: testIV });
    assert(Buffer.compare(serialisedOutput, expectedSerialisedOutput) === 0, "Encrypted serialised output is incorrect.");
  });

})

describe("Decryption tests", function() {
  it("should produce the correct plaintext",  async function() {
    let expectedPlaintext = Buffer.from('test')
    let serialisedCipher =Buffer.from('044267ec8951b0bad54847c7d1bf913687b1db9cc4ca2817eca651a092fe073028ec0d41e0593c95d7a60bf0c39e5cdeb6e27206ec8998ba9e464e78d865b44423d0198031fcd63151667eadf3537f6a6b2a2a6fa41511c779a66cfe87f13d54edfee151292b7b7af2145cc50f2d5a29676630409d', 'hex');
    let plaintext = await ecies.decrypt(testReceiverPrivateKey, serialisedCipher)
    assert(Buffer.compare(plaintext, expectedPlaintext) === 0, "Decrypted plaintext is incorrect.");
  });

});



