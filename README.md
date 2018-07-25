# ecies-parity

This is a javaScript Elliptic curve Integrated Encryption Scheme (ECIES) library for both `browserify` and `node.js`. This implementation mimics [parity](https://www.parity.io/)'s rust implementation to allow dapps to encrypt/decrypt messages from parity's extended [JSON RPC API](https://wiki.parity.io/JSONRPC-parity-module.html). 

This module is a modified version of the [eccrypto](https://github.com/bitchan/eccrypto) javascript library. 

## Motivation

[Parity](https://www.parity.io/) has implemented ECIES encryption and
decryption for arbitrary messages through its extended [JSON RPC API](https://wiki.parity.io/JSONRPC-parity-module.html). Other
Ethereum clients, (i.e. Metamask, go-ethereum) have not implemented such
encryption. Dapps wishing to utilise Parity's features but also facilitate
other Ethereum clients may require encrypting and decrypting Parity's
messages in the browser. This package is designed to facilitate such tasks.  

## Implementation details

As with `eccrypto`, this library provides two implementations for Browser and Node.js with the same API. 

The ECIES implementation details mimic those introduced by Parity, which are

* Implements a SHA256 Key Derivation Function (KDF). 
* Uses ECDH based only on the secp256k1 curve (To match common blockchain transaction
    signing).
* AES-128-CTR based symmetric encryption (uses a 128 bit shared key derived
    from ECDH). 

#### Cryptography Warning

The ECIES implementation given here is solely based off Parity's
implementation. This module offers no guarantees as to the
security or validity of the implementation. Furthermore, this project is being actively
developed and as such should not be used for highly sensitive information.   

## Usage

Although this module is primarily developed for ECIES encryption/decryption
extra elliptic curve functionality is given.


### ECIES (Parity Encryption/Decryption)

```js
const crypto = require("crypto");
const ecies = require("ecies-parity");

var privateKeyA = crypto.randomBytes(32);
var publicKeyA = ecies.getPublic(privateKeyA);
var privateKeyB = crypto.randomBytes(32);
var publicKeyB = ecies.getPublic(privateKeyB);

// Encrypting the message for B.
ecies.encrypt(publicKeyB, Buffer.from("msg to b")).then(function(encrypted) {
  // B decrypting the message.
  ecies.decrypt(privateKeyB, encrypted).then(function(plaintext) {
    console.log("Message to part B:", plaintext.toString());
  });
});

// Encrypting the message for A.
ecies.encrypt(publicKeyA, Buffer.from("msg to a")).then(function(encrypted) {
  // A decrypting the message.
  ecies.decrypt(privateKeyA, encrypted).then(function(plaintext) {
    console.log("Message to part A:", plaintext.toString());
  });
});
```

### Signing 

```js
const crypto = require("crypto");
const ecies = require("ecies-parity");

// A new random 32-byte private key.
var privateKey = crypto.randomBytes(32);
// Corresponding uncompressed (65-byte) public key.
var publicKey = ecies.getPublic(privateKey);

var str = "message to sign";
// Always hash you message to sign!
var msg = crypto.createHash("sha256").update(str).digest();

ecies.sign(privateKey, msg).then(function(sig) {
  console.log("Signature in DER format:", sig);
  ecies.verify(publicKey, msg, sig).then(function() {
    console.log("Signature is OK");
  }).catch(function() {
    console.log("Signature is BAD");
  });
});
```

### ECDH

```js
const crypto = require("crypto");
const ecies = require("ecies-parity");

var privateKeyA = crypto.randomBytes(32);
var publicKeyA = ecies.getPublic(privateKeyA);
var privateKeyB = crypto.randomBytes(32);
var publicKeyB = ecies.getPublic(privateKeyB);

ecies.derive(privateKeyA, publicKeyB).then(function(sharedKey1) {
  ecies.derive(privateKeyB, publicKeyA).then(function(sharedKey2) {
    console.log("Both shared keys are equal:", sharedKey1, sharedKey2);
  });
});
```
