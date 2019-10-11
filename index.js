var sodium = require('sodium').api;
var secp256k1 = require("secp256k1/elliptic");
var crypto = require('crypto');
var createKeccakHash = require("keccak/js");

const constants = {
  // Symmetric cipher for private key encryption
  cipher: "aes-256-ctr",

  // Initialization vector size in bytes
  ivBytes: 16,

  // ECDSA private key size in bytes
  keyBytes: 32,

  // Key derivation function parameters
  pbkdf2: {
    c: 262144,
      dklen: 32,
      hash: "sha256",
      prf: "hmac-sha256"
  },
  scrypt: {
    memory: 280000000,
      dklen: 32,
      n: 262144,
      r: 8,
      p: 1
  }
};

// create alice
const alice = create();
//const alicePub = publicKey(alice.privateKey);
const alicePub = sodium.crypto_scalarmult_base(alice.privateKey)

// create bob
const bob = create();
//const bobPub = publicKey(bob.privateKey);
const bobPub = sodium.crypto_scalarmult_base(bob.privateKey)

console.log(alicePub, `\n has a length of ${alicePub.length}`);

// create shared secret
const bobSharedSecret = sodium.crypto_scalarmult(bob.privateKey, alicePub);
const aliceSharedSecret = sodium.crypto_scalarmult(alice.privateKey, bobPub);

console.log(bobSharedSecret, aliceSharedSecret, bobSharedSecret == aliceSharedSecret, bobSharedSecret.length);

const iv1 = Buffer.alloc(constants.ivBytes, 0);
const iv2 = Buffer.alloc(constants.ivBytes, 0);
const cipher = crypto.createCipheriv(constants.cipher, bobSharedSecret, iv1);
const decipher = crypto.createDecipheriv(constants.cipher, aliceSharedSecret, iv2);

let encrypted = '';
cipher.on('readable', () => {
  let chunk;
  while (null !== (chunk = cipher.read())) {
    encrypted += chunk.toString('hex');
  }
});

cipher.on('end', () => {
  console.log(`cb: ${encrypted}`);
  decipher.write(encrypted, 'hex');
  decipher.end();
  // Prints: e5f79c5915c02171eec6b212d5520d44480993d7d622a7c4c2da32f6efda0ffa
});

cipher.write('some clear text data');
cipher.end();
console.log(`end: ${encrypted}`);

let decrypted = '';
decipher.on('readable', () => {
  while (null !== (chunk = decipher.read())) {
    decrypted += chunk.toString('utf8');
  }
});
decipher.on('end', () => {
  console.log(`decrypted: ${decrypted}`);
});

function create() {
  return checkBoundsAndCreateObject(crypto.randomBytes(constants.keyBytes + constants.ivBytes + constants.keyBytes));
}

function checkBoundsAndCreateObject(randomBytes) {
  let privateKey = randomBytes.slice(0, constants.keyBytes);
  if (!secp256k1.privateKeyVerify(privateKey)) return create();
  return {
    privateKey: privateKey,
    iv: randomBytes.slice(constants.keyBytes, constants.keyBytes + constants.ivBytes),
    salt: randomBytes.slice(constants.keyBytes + constants.ivBytes)
  };
}

function publicKey(privateKey) {
  let privateKeyBuffer = str2buf(privateKey);
  if (privateKeyBuffer.length < 32) {
    privateKeyBuffer = Buffer.concat([
      Buffer.alloc(32 - privateKeyBuffer.length, 0),
      privateKeyBuffer
    ]);
  }

  return secp256k1.publicKeyCreate(privateKeyBuffer, false).slice(1);
}

function address(publicKey) {
  return "0x" + keccak256(publicKey).slice(-20).toString("hex");
}

function keccak256(buffer) {
  return createKeccakHash("keccak256").update(buffer).digest();
}

function str2buf(str, enc) {
  if (!str || str.constructor !== String) return str;
  if (!enc && this.isHex(str)) enc = "hex";
  if (!enc && this.isBase64(str)) enc = "base64";
  return Buffer.from(str, enc);
}
