/**
 * Browser ecies-parity implementation.
 *
 * This is based of the eccrypto js module
 *
 */

"use strict";

var EC = require("elliptic").ec;
var ec = new EC("secp256k1");
var cryptoObj = global.crypto || global.msCrypto || {};
var subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

// Implemented in parity
var PARITY_DEFAULT_HMAC = Buffer.from([0,0]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

// Use the browser RNG
function randomBytes(size) {
  var arr = new Uint8Array(size);
  global.crypto.getRandomValues(arr);
  return new Buffer(arr);
}

// Get the browser SHA256 implementation
var sha256 = exports.sha256 = function sha256(msg) {
  return subtle.digest({name: "SHA-256"}, msg).then(function(hash) {
    return new Buffer(new Uint8Array(hash));
  });
}

// The KDF as implemented in Parity
var kdf = exports.kdf = async function(secret, outputLength) { 
  let ctr = 1;
  let written = 0; 
  let result = Buffer.from('');
  while (written < outputLength) { 
    let ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr]);
    let hashResult = await sha256(Buffer.concat([ctrs,secret]));
    result = Buffer.concat([result, hashResult])
    written += 32; 
    ctr +=1;
  }
  return result;
}

// AES-128-CTR is used in the Parity implementation
// Get the AES-128-CTR browser implementation
function getAes(op) {
  return function(counter, key, data) {
    var importAlgorithm = {
      name: "AES-CTR",
    };
    var keyp = subtle.importKey("raw", key, importAlgorithm, false, [op]);

    return keyp.then(function(cryptoKey) {
      var encAlgorithm = {
        name: "AES-CTR",
        counter: counter,
        length: 128,
        };
      return subtle[op](encAlgorithm, cryptoKey, data);
    }).then(function(result) {
      return Buffer.from(new Uint8Array(result));
    });
  };
}

var aesCtrEncrypt = getAes("encrypt");
var aesCtrDecrypt = getAes("decrypt");

function hmacSha256Sign(key, msg) {
  var algorithm = {name: "HMAC", hash: {name: "SHA-256"}};
  var keyp = subtle.importKey("raw", key, algorithm, false, ["sign"]);
  return keyp.then(function(cryptoKey) {
    return subtle.sign(algorithm, cryptoKey, msg);
  }).then(function(sig) {
    return Buffer.from(new Uint8Array(sig));
  });
}

function hmacSha256Verify(key, msg, sig) {
  var algorithm = {name: "HMAC", hash: {name: "SHA-256"}};
  var keyp = subtle.importKey("raw", key, algorithm, false, ["verify"]);
  return keyp.then(function(cryptoKey) {
    return subtle.verify(algorithm, cryptoKey, sig, msg);
  });
}

// Obtain the public elliptic curve key from a private
var getPublic = exports.getPublic = function(privateKey) {
  assert(privateKey.length === 32, "Bad private key");
  return new Buffer(ec.keyFromPrivate(privateKey).getPublic("arr"));
};

// ECDSA
exports.sign = function(privateKey, msg) {
  return new Promise(function(resolve) {
    assert(privateKey.length === 32, "Bad private key");
    assert(msg.length > 0, "Message should not be empty");
    assert(msg.length <= 32, "Message is too long");
    resolve(new Buffer(ec.sign(msg, privateKey, {canonical: true}).toDER()));
  });
};

// Verify ECDSA signatures
exports.verify = function(publicKey, msg, sig) {
  return new Promise(function(resolve, reject) {
    assert(publicKey.length === 65, "Bad public key");
    assert(publicKey[0] === 4, "Bad public key");
    assert(msg.length > 0, "Message should not be empty");
    assert(msg.length <= 32, "Message is too long");
    if (ec.verify(msg, sig, publicKey)) {
      resolve(null);
    } else {
      reject(new Error("Bad signature"));
    }
  });
};

//ECDH 
var derive = exports.derive = function(privateKeyA, publicKeyB) {
  return new Promise(function(resolve) {
    assert(Buffer.isBuffer(privateKeyA), "Bad input");
    assert(Buffer.isBuffer(publicKeyB), "Bad input");
    assert(privateKeyA.length === 32, "Bad private key");
    assert(publicKeyB.length === 65, "Bad public key");
    assert(publicKeyB[0] === 4, "Bad public key");
    let keyA = ec.keyFromPrivate(privateKeyA);
    let keyB = ec.keyFromPublic(publicKeyB);
    let Px = keyA.derive(keyB.getPublic());  // BN instance
    resolve(new Buffer(Px.toArray()));
  });
};


// Encrypt AES-128-CTR and serialise as in Parity
// Serialisation: <ephemPubKey><IV><CipherText><HMAC>
exports.encrypt = async function(publicKeyTo, msg, opts) {
  assert(subtle, "WebCryptoAPI is not available");
  opts = opts || {};
  let ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  let ephemPublicKey = getPublic(ephemPrivateKey);
  let sharedPx = await derive(ephemPrivateKey, publicKeyTo);
  let hash = await kdf(sharedPx, 32);
  let iv = opts.iv || randomBytes(16);
  let encryptionKey = hash.slice(0, 16);
  let macKey = await sha256(hash.slice(16));
  let ciphertext = await aesCtrEncrypt(iv, encryptionKey, msg);
  let dataToMac = Buffer.concat([iv, ciphertext, PARITY_DEFAULT_HMAC]);
  let HMAC = await hmacSha256Sign(macKey, dataToMac);
  return Buffer.concat([ephemPublicKey,iv,ciphertext,HMAC]);
};

// Decrypt serialised AES-128-CTR
exports.decrypt = async function(privateKey, encrypted) {
  assert(subtle, "WebCryptoAPI is not available");
  let metaLength = 1 + 64 + 16 + 32; 
  assert(encrypted.length > metaLength, "Invalid Ciphertext. Data is too small")
  assert(encrypted[0] >= 2 && encrypted[0] <= 4, "Not valid ciphertext.")
  // deserialise
  let ephemPublicKey = encrypted.slice(0,65);
  let cipherTextLength = encrypted.length - metaLength; 
  let iv = encrypted.slice(65,65 + 16);
  let cipherAndIv = encrypted.slice(65, 65+16+ cipherTextLength);
  let ciphertext = cipherAndIv.slice(16);
  let msgMac = encrypted.slice(65+16+ cipherTextLength);

  // check HMAC
  var px = await derive(privateKey, ephemPublicKey);
  var hash = await kdf(px,32);
  var encryptionKey = hash.slice(0, 16);
  var macKey = await sha256(hash.slice(16));
  var dataToMac = Buffer.concat([cipherAndIv, PARITY_DEFAULT_HMAC]);
  var hmacGood = await hmacSha256Verify(macKey, dataToMac,msgMac);
  assert(hmacGood, "Incorrect MAC");
  // decrypt message
  var plainText = await aesCtrDecrypt(iv, encryptionKey, ciphertext);
  return new Buffer(new Uint8Array(plainText));
};
