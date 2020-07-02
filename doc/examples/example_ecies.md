# Elliptic Curve Integrated Encryption Scheme (ECIES)

# Basic ECIES

ECIES utilizes well-known symmetric encryption, key derivation functions and message authentication codes
to achieve encryption based on elliptic curves. However, ECIES is not limited to specific algorithms. That is,
the algorithms used for symmetric encryption, key derivation and message authentication can be configured
in our implementation. For the sake of easy usage, we have decided to use the following defaults:
 - Symmetric Encryption: AES-CBC with PKCS7 padding, IV=0x0, keysize 256 bit
 - Key Derivation Function: X9.63 without salt
 - Message Authentication Code: HMAC-SHA512 without salt

The following examples show how to en- and decrypt using ECIES with these default settings. Afterwards, the
different options to change the default values will be shown.

## Encryption

```cpp
// 1. Read public key from PEM
mococrw::AsymmetricPublicKey pubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(secp384PubKeyPEM);

std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

mococrw::ECIESCtxBuilder encBuilder;
std::unique_ptr<mococrw::ECIESEncryptionCtx> encCtx = encBuilder.buildEncryptionCtx(pubKey);
encCtx->update(testString);

// 2. Finish encryption and extract parameters for decryption
std::vector<uint8_t> ciphertext = encCtx->finish();
std::vector<uint8_t> mac = encCtx->getMAC();
std::vector<uint8_t> point = encCtx->getEphemeralKey().toECPoint(...); // See section "Ephemeral Key Encodig Format" for details
```

## Decryption

```cpp
// Ciphertext, mac and the point need to be available
std::vector<uint8_t> ciphertext = { ... };
std::vector<uint8_t> mac = { ... };
std::vector<uint8_t> point = { ... };

// 1. Read private key from PEM
mococrw::AsymmetricKeypair privKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(secp384KeyPEM, "password");

// 2. Get type of curve from private key
std::shared_ptr<mococrw::ECCSpec> spec;
{
    // Convert returned unique_ptr into shared_ptr
    std::shared_ptr<mococrw::AsymmetricKey::Spec> spec_tmp = privKey.getKeySpec();

    // Cast shared_ptr<mococrw::AsymmetricKey::Spec> into std::shared_ptr<mococrw::ECCSpec>
    spec = std::dynamic_pointer_cast<mococrw::ECCSpec>(spec_tmp);
}

if (!spec) {
    // Error handling
    ...
}

// 3. Re-create ephemeral key
mococrw::AsymmetricPublicKey ephKey = mococrw::AsymmetricPublicKey::fromECPoint(spec, point);

mococrw::ECIESCtxBuilder decBuilder;

// 4. Set parameters for decryption
std::unique_ptr<mococrw::ECIESDecryptionCtx> decCtx = decBuilder.buildDecryptionCtx(privKey, ephKey);
decCtx->update(ciphertext);
decCtx->setMAC(mac);

// 5. Decrypt
try {
    std::vector<uint8_t> result = decCtx->finish();
}
catch (const mococrw::MoCOCrWException &e)  {
    std::cerr << "MAC verification failed" << std::endl;
    ...
}
```

## Serialization of Artifacts

The encryption of the plaintext creates several artifacts (ciphertext, mac and ephemeral key) that need to be transferred to the client in order to
decrypt the ciphertext. MoCOCrW offers no serialization functionality because we don't want to make any assumptions of the format. That is,
the user of the library is responsible for the serialization.

### Ephemeral Key Encodig Format

The methods `mococrw::AsymmetricPublicKey::toECPoint()` and `mococrw::AsymmetricPublicKey::toECPoint()` expect that the serialization format
is specified by the programmer. The library currently offers three different formats:

* `mococrw::openssl::EllipticCurvePointConversionForm::compressed`:
   Format *z||x*, where *z* specifies which of the possible two solutions to *x* has been used
* `mococrw::openssl::EllipticCurvePointConversionForm::uncompressed`:
   Format *0x04||x||y*, where *y* is the solution to *x* that has been used
* `mococrw::openssl::EllipticCurvePointConversionForm::hybrid`
   Format *z||x||y*, where *z* specifies which of the possible two solutions to *x* has been used and *y* contains this solution

It is also possible to encode the ephemeral key as PEM, but this seems rather unsusal.


# Change Default Parameters

## Symmetric Cipher
The `mococrw::ECIESCtxBuilder` offers methods to modify the symmetric cipher that will be used for encryption.
The following code shows how to use these methods to change the symmetric cipher to AES-CBC with a key size of 128 bit:

### Encryption

```cpp
// 1. Read public key from PEM
mococrw::AsymmetricPublicKey pubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(secp384PubKeyPEM);

std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

mococrw::ECIESCtxBuilder encBuilder;

// 2. Create IV vector (default value for the IV is 0x0 in ECIES)
// Default size of the IV can be obtianed with mococrw::AESCipherBuilder::getDefaultIVLength(mococrw::SymmetricCipherMode::CBC)
std::vector<uint8_t> IV = ...

// 3. Set new Symmetric Cipher Factory Function
auto cipherEncFunc = [&IV](const std::vector<uint8_t> &key) -> std::unique_ptr<mococrw::AESCipher> {
    return mococrw::AESCipherBuilder(mococrw::SymmetricCipherMode::CBC, mococrw::SymmetricCipherKeySize::S_128, key)
            .setIV(std::vector<uint8_t>(IV))
            .setPadding(mococrw::SymmetricCipherPadding::PKCS)
            .buildEncryptor();
};
encBuilder.setSymmetricCipherFactoryFunction(cipherEncFunc);

// 4. Set new key size
encBuilder.setSymmetricCipherKeySize(mococrw::getSymmetricCipherKeySize(mococrw::SymmetricCipherKeySize::S_128));

std::unique_ptr<mococrw::ECIESEncryptionCtx> encCtx = encBuilder.buildEncryptionCtx(pubKey);
encCtx->update(testString);

// 5. Finish encryption and extract parameters for decryption
std::vector<uint8_t> ciphertext = encCtx->finish();
std::vector<uint8_t> mac = encCtx->getMAC();
std::vector<uint8_t> point = encCtx->getEphemeralKey().toECPoint(...); // See section "Ephemeral Key Encodig Format" for details
```

### Decryption

```cpp
// Ciphertext, mac, point and IV need to be available
std::vector<uint8_t> ciphertext = { ... };
std::vector<uint8_t> mac = { ... };
std::vector<uint8_t> point = { ... };
std::vector<uint8_t> IV = { ... };

// 1. Read private key from PEM
mococrw::AsymmetricKeypair privKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(secp384KeyPEM, "");

// 2. Get type of curve from private key
std::shared_ptr<mococrw::ECCSpec> spec;
{
    // Convert returned unique_ptr into shared_ptr
    std::shared_ptr<mococrw::AsymmetricKey::Spec> spec_tmp = privKey.getKeySpec();

    // Cast shared_ptr<mococrw::AsymmetricKey::Spec> into std::shared_ptr<mococrw::ECCSpec>
    spec = std::dynamic_pointer_cast<mococrw::ECCSpec>(spec_tmp);
}

if (!spec) {
    // Error handling
    ...
}

// 3. Re-create ephemeral key
mococrw::AsymmetricPublicKey ephKey = mococrw::AsymmetricPublicKey::fromECPoint(spec, point);

mococrw::ECIESCtxBuilder decBuilder;

// 4. Set new Symmetric Cipher Factory Function
auto cipherDecFunc = [&IV](const std::vector<uint8_t> &key) -> std::unique_ptr<mococrw::AESCipher> {
    return mococrw::AESCipherBuilder(mococrw::SymmetricCipherMode::CBC, mococrw::SymmetricCipherKeySize::S_128, key)
            .setIV(IV)
            .setPadding(mococrw::SymmetricCipherPadding::PKCS)
            .buildDecryptor();
};
decBuilder.setSymmetricCipherFactoryFunction(cipherDecFunc);

// 5. Set new key size
decBuilder.setSymmetricCipherKeySize(mococrw::getSymmetricCipherKeySize(mococrw::SymmetricCipherKeySize::S_128));

// 6. Set parameters for decryption
std::unique_ptr<mococrw::ECIESDecryptionCtx> decCtx = decBuilder.buildDecryptionCtx(privKey, ephKey);
decCtx->update(ciphertext);
decCtx->setMAC(mac);

// 7. Decrypt
try {
    std::vector<uint8_t> result = decCtx->finish();
}
catch (const MoCOCrWException &e)  {
    std::cerr << "MAC verification failed" << std::endl;
    ...
}
```

## Key Derivation Function (KDF)

MoCOCrW offers different key derivation functions. The following example shows how to change the KDF used by ECIES. In addition, the example shows
how to set the optional salt for the key derivation.

### Encryption

```cpp
// 1. Read public key from PEM
mococrw::AsymmetricPublicKey pubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(secp384PubKeyPEM);

std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

mococrw::ECIESCtxBuilder encBuilder;

// 2. Set KDF to PBKDF2
encBuilder.setKDF(std::make_shared<mococrw::PBKDF2>(mococrw::openssl::DigestTypes::SHA256, 100));

// (optionally) Set salt for KDF
std::vector<uint8_t> randomSalt= { ... };
encBuilder.setKDFSalt(randomSalt);

std::unique_ptr<mococrw::ECIESEncryptionCtx> encCtx = encBuilder.buildEncryptionCtx(pubKey);
encCtx->update(testString);

// 3. Finish encryption and extract parameters for decryption
std::vector<uint8_t> ciphertext = encCtx->finish();
std::vector<uint8_t> mac = encCtx->getMAC();
std::vector<uint8_t> point = encCtx->getEphemeralKey().toECPoint(...); // See section "Ephemeral Key Encodig Format" for details
```

### Decryption

```cpp
// Ciphertext, mac and point need to be available
std::vector<uint8_t> ciphertext = { ... };
std::vector<uint8_t> mac = { ... };
std::vector<uint8_t> point = { ... };

// 1. Read private key from PEM
mococrw::AsymmetricKeypair privKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(secp384KeyPEM, "password");

// 2. Get type of curve from private key
std::shared_ptr<mococrw::ECCSpec> spec;
{
    // Convert returned unique_ptr into shared_ptr
    std::shared_ptr<mococrw::AsymmetricKey::Spec> spec_tmp = privKey.getKeySpec();

    // Cast shared_ptr<mococrw::AsymmetricKey::Spec> into std::shared_ptr<mococrw::ECCSpec>
    spec = std::dynamic_pointer_cast<mococrw::ECCSpec>(spec_tmp);
}

if (!spec) {
    // Error handling
    ...
}

// 3. Re-create ephemeral key
mococrw::AsymmetricPublicKey ephKey = mococrw::AsymmetricPublicKey::fromECPoint(spec, point);

mococrw::ECIESCtxBuilder decBuilder;

// 4. Set KDF to PBKDF2
decBuilder.setKDF(std::make_shared<mococrw::PBKDF2>(mococrw::openssl::DigestTypes::SHA256, 100));

// (optionally) Set salt for KDF
std::vector<uint8_t> encryptionSalt= { ... };
encBuilder.setKDFSalt(encryptionSalt);

// 5. Set parameters for decryption
std::unique_ptr<mococrw::ECIESDecryptionCtx> decCtx = decBuilder.buildDecryptionCtx(privKey, ephKey);
decCtx->update(ciphertext);
decCtx->setMAC(mac);

// 6. Decrypt
try {
    std::vector<uint8_t> result = decCtx->finish();
}
catch (const MoCOCrWException &e)  {
    std::cerr << "MAC verification failed" << std::endl;
    ...
}
```

## Message Authentication Code (MAC)

The following example shows how to configure (and specify if there ever shall be more than one supported MAC) the MAC to be used by the ECIES scheme

### Encryption

```cpp
// 1. Read public key from PEM
mococrw::AsymmetricPublicKey pubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(secp384PubKeyPEM);

std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

mococrw::ECIESCtxBuilder encBuilder;

// 2. Set new MAC function
auto macFunc = [](const std::vector<uint8_t> &key) -> std::unique_ptr<mococrw::MessageAuthenticationCode> {
    return std::make_unique<mococrw::HMAC>(mococrw::openssl::DigestTypes::SHA256, key);
};
encBuilder.setMacFactoryFunction(macFunc);

// 3. Set keysize of new MAC function
encBuilder.setMacKeySize(mococrw::Hash::getDigestSize(mococrw::openssl::DigestTypes::SHA256));

// (optionally) Set salt for MAC
std::vector<uint8_t> randomSalt= { ... };
encBuilder.setMACSalt(randomSalt);

std::unique_ptr<mococrw::ECIESEncryptionCtx> encCtx = encBuilder.buildEncryptionCtx(pubKey);
encCtx->update(testString);

// 4. Finish encryption and extract parameters for decryption
std::vector<uint8_t> ciphertext = encCtx->finish();
std::vector<uint8_t> mac = encCtx->getMAC();
std::vector<uint8_t> point = encCtx->getEphemeralKey().toECPoint(...); // See section "Ephemeral Key Encodig Format" for details
```

### Decryption

```cpp
// Ciphertext, mac and point need to be available
std::vector<uint8_t> ciphertext = { ... };
std::vector<uint8_t> mac = { ... };
std::vector<uint8_t> point = { ... };

// 1. Read private key from PEM
mococrw::AsymmetricKeypair privKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(secp384KeyPEM, "password");

// 2. Get type of curve from private key
std::shared_ptr<mococrw::ECCSpec> spec;
{
    // Convert returned unique_ptr into shared_ptr
    std::shared_ptr<mococrw::AsymmetricKey::Spec> spec_tmp = privKey.getKeySpec();

    // Cast shared_ptr<mococrw::AsymmetricKey::Spec> into std::shared_ptr<mococrw::ECCSpec>
    spec = std::dynamic_pointer_cast<mococrw::ECCSpec>(spec_tmp);
}

if (!spec) {
    // Error handling
    ...
}

// 3. Re-create ephemeral key
mococrw::AsymmetricPublicKey ephKey = mococrw::AsymmetricPublicKey::fromECPoint(spec, point);

mococrw::ECIESCtxBuilder decBuilder;

// 4. Set new MAC function
auto macFunc = [](const std::vector<uint8_t> &key) -> std::unique_ptr<mococrw::MessageAuthenticationCode> {
    return std::make_unique<mococrw::HMAC>(mococrw::openssl::DigestTypes::SHA256, key);
};
decBuilder.setMacFactoryFunction(macFunc);

// 5. Set keysize of new MAC function
decBuilder.setMacKeySize(mococrw::Hash::getDigestSize(mococrw::openssl::DigestTypes::SHA256));

// (optionally) Set salt for KDF
std::vector<uint8_t> encryptionSalt= { ... };
encBuilder.setKDFSalt(encryptionSalt);

// 6. Set parameters for decryption
std::unique_ptr<mococrw::ECIESDecryptionCtx> decCtx = decBuilder.buildDecryptionCtx(privKey, ephKey);
decCtx->update(ciphertext);
decCtx->setMAC(mac);

// 7. Decrypt
try {
    std::vector<uint8_t> result = decCtx->finish();
}
catch (const MoCOCrWException &e)  {
    std::cerr << "MAC verification failed" << std::endl;
    ...
}
```
