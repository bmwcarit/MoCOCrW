# Symmetric Crypto API

## Encrypting messages in one-shot mode

The code below demonstrates encryption and then further decryption of a simple message. The example also shows how to generate random encryption key and IV.

```cpp

using namespace mococrw;

std::string message{"This is a message we going to encrypt and then, hopefully, decrypt."};
std::vector<uint8_t> plaintext{message.begin(), message.end()};

// Generate random encryption key.
// NOTE: Always prefer library built-in cryptographically secure random number generator to
// other sources of random number generation.
auto secretKey = utility::cryptoRandomBytes(256/8);

//
// Encryption
//

// Create symmetric cipher for encryption.
// NOTE: we do not specify IV and AESCipherBuilder will generate a random one.
auto encryptor = AESCipherBuilder{SymmetricCipherMode::CBC, SymmetricCipherKeySize::S_256, secretKey}.buildEncryptor();

// This example demonstrates one-shot operation mode which means plaintext message is first
// encrypted and later decrypted in one piece.
encryptor->update(plaintext);
auto ciphertext = encryptor->finish();

// Get the Initialization Vector. We will need it, together with the key, for decryption
auto iv = encryptor->getIV();

//
// Decryption
//

// Use the same parameters as for encryption but explicitly specify the IV.
auto decryptor = AESCipherBuilder{SymmetricCipherMode::CBC, SymmetricCipherKeySize::S_256, secretKey}.setIV(iv).buildDecryptor();
decryptor->update(ciphertext);

std::vector<uint8_t> decryptedtext;
try {
    decryptedtext = decryptor->finish();
}
catch (const MoCOCrWException& e) {
    std::cerr << "Decryption failed : " << e.what() << std::endl;
}

// Ensure that decrypted text matches the original message
assert(std::equal(plaintext.begin(), plaintext.end(), decryptedtext.begin()));

```

## Using authenticated encryption

Authenticated ciphers not only encrypt data but also compute authentication tag over it. It allows to detect if data was modified after it was encrypted.

It is also possible to associate additional unencrypted data with the message. The authentication tag will ensure the integrity of both encrypted and unencrypted data in that case. This is, e.g., used to protect the integrity of header fields that contain metadata that need to be visible on transport.

Example below is similar to the previous one but uses authenticated cipher mode GCM. After encryption we take computed authentication tag and carry it along with the message for further authentication.

```cpp

std::string message{"This is a message we going to encrypt and then, hopefully, decrypt."};
std::vector<uint8_t> plaintext{message.begin(), message.end()};

// Optional: Associated data
std::string data{"This is a message we are not going to encrypt but want to make sure arrived unchanged."};
std::vector<uint8_t> associatedData{data.begin(), data.end()};


auto secretKey = utility::cryptoRandomBytes(256/8);

//
// Encryption
//

// Create cipher similarly to the previous example with two differences:
// * use mode which supports authenticated encryption such as GCM
// * explicitly build authenticated encryptor with 'buildAuthenticatedEncryptor'.
//
// If you try to build authenticated cipher with mode which does not support it, 'build'
// function will throw.
auto encryptor = AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, secretKey}.buildAuthenticatedEncryptor();

// Optional step: Associating additional unencrypted data with the message
encryptor->addAssociatedData(associatedData);

encryptor->update(plaintext);
auto ciphertext = encryptor->finish();

auto iv = encryptor->getIV();
// In addition to getting IV of the encrypted block of data we also get authentication tag.
auto authTag = encryptor->getAuthTag();

//
// Decryption
//

auto decryptor = AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, secretKey}.setIV(iv).buildAuthenticatedDecryptor();

// Optional step: If associated data was set during encryption, add it here for the integrity check
decryptor->addAssociatedData(associatedData);

decryptor->update(ciphertext);

// Set authentication tag **before** calling `finish()`.
decryptor->setAuthTag(authTag);

std::vector<uint8_t> decryptedtext;
try {
    decryptedtext = decryptor->finish();
}
catch (const MoCOCrWException& e) {
    std::cerr << "Decryption failed. It is possible that the message was modified after"
    " encryption. " << e.what() << std::endl;
}

// Ensure that decrypted text matches the original message
assert(std::equal(plaintext.begin(), plaintext.end(), decryptedtext.begin()));

```

## Steaming-mode

Symmetric encryption interface also supports streaming use-case. It allows encryption of big chunks of data without loading them into memory. The implementation is optimized to avoid unnecessary copies of the input and output buffers when used with fixed block sizes in streaming en-/decryption.

The following example demonstrates how to use stream mode with authenticated cipher.

```cpp

std::string message;
for (size_t i = 0; i < 1024; i++) {
    message += "a string which will be concatenated multiple times-";
}
std::vector<uint8_t> plaintext{message.begin(), message.end()};

auto secretKey = utility::cryptoRandomBytes(256/8);

//
// Encryption
//

auto encryptor = AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, secretKey}.buildAuthenticatedEncryptor();

std::vector<uint8_t> ciphertext;

// Encrypt plaintext messages in 1K blocks.
// NOTE: Note about performance: default memory model for streaming-mode is optimized for the
// following use-cases:
// - `update()` followed by `readAll()`. `readAll` will return one chunk of encrypted/decrypted
// data with zero-copy.
// - `update()` followed by `read()` with the same chunk size (only if the cipher is a stream
// cipher, or a block cipher and the input size produces an equivalent output size)
// Therefore we recommend "`update()` followed by `readAll()`" pattern.
const size_t packetSize = 1024;
auto packetIterator = plaintext.begin();
while (packetIterator < plaintext.end() - packetSize) {
    std::vector<uint8_t> plaintextPacket{packetIterator, packetIterator + packetSize};
    packetIterator += packetSize;
    encryptor->update(plaintextPacket);
    auto encryptedPacket = encryptor->readAll();
    std::copy(std::begin(encryptedPacket), std::end(encryptedPacket), std::back_inserter(ciphertext));
}

// AES GCM does not use padding and `finalEncryptedChunk` would be empty but you still
// have to call `finish()` to indicate to the cipher that encryption is complete and
// authentication tag can be computed.
// Please also note that if you use other cipher in stream mode, `finish()` might actually
// return some encrypted data.
auto finalEncryptedChunk = encryptor->finish();
std::copy(std::begin(finalEncryptedChunk), std::end(finalEncryptedChunk), std::back_inserter(ciphertext));

auto iv = encryptor->getIV();
auto authTag = encryptor->getAuthTag();

//
// Decryption
//

auto decryptor = AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, secretKey}.setIV(iv).buildAuthenticatedDecryptor();


// You can mix `update()`, `read()` and `readAll()`. For example, in the code below we first
// read and decrypt several packets, then accumulate some decrypted blocks in the cipher
// internal memory and finally read all the remaining plaintext from the cipher.
//
// NOTE: `update()` and sequential `readAll()` (or `read()` of the same chunk size) is still
// the most efficient approach.

std::vector<uint8_t> decryptedtext;

// Decrypt in packets and read plaintext right away
packetIterator = ciphertext.begin();
while (packetIterator < ciphertext.end() - packetSize * 14) {
    decryptor->update({packetIterator, packetIterator + packetSize});
    packetIterator += packetSize;
    auto decryptedPacket = decryptor->read(packetSize);
    std::copy(std::begin(decryptedPacket), std::end(decryptedPacket), std::back_inserter(decryptedtext));
}

//...decrypt, but not read-out the plaintext.
while (packetIterator < ciphertext.end()) {
    decryptor->update({packetIterator, packetIterator + packetSize});
    packetIterator += packetSize;
}
//... read all remaining decrypted data in one chunk.
auto decryptedPacket = decryptor->readAll();
std::copy(std::begin(decryptedPacket), std::end(decryptedPacket), std::back_inserter(decryptedtext));

decryptor->setAuthTag(authTag);
try {
    decryptor->finish();
}
catch (const MoCOCrWException& e) {
    std::cerr << "Decryption failed. It is possible that the message was modified after"
    " encryption. " << e.what() << std::endl;
}

// Ensure that decrypted text matches the original message
assert(std::equal(decryptedtext.begin(), decryptedtext.end(), plaintext.begin()));

```
