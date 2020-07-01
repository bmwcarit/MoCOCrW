# Asymmetric Crypto API

# Common Interface

## Encryption Interface

All contexts that support en- / decryption are implementing an `encrypt()` or `decrypt()` method resprectively. The classes `mococrw::EncryptionCtx` and `mococrw::DecryptionCtx` provide a pure virtual interface to these methods:
<!-- TODO for when refactoring Examples: Generate such code snippets from code-->
```cpp
class EncryptionCtx {
    ...
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& message) = 0;
};

class DecryptionCtx {
    ...
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& message) = 0;
}
```
That is, these classes can be used to access an en-/decryption context in a generic manner.

## Signature Interface

All contexts that support signing implement a method to sign pre-hashed message digests (`signDigest()`) or unhashed messages (`signMessage()`) or both. Please note that if a message digest shall be signed (or verified) it is expected that the client provides the digest of the message to be signed (i.e. performs the hashing on his own). On the contrary, signing a message means that the message digest will be calculated and signed then. The classes `mococrw::DigestSignatureCtx`, `mococrw::MessageSignatureCtx`, `mococrw::DigestVerificationCtx` and `mococrw::MessageVerificationCtx` provide a pure virtual interface to these methods:

```cpp
class DigestSignatureCtx {
    ...
    virtual std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest) = 0;
};

class MessageSignatureCtx {
    ...
    virtual std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message) = 0;
};

class DigestVerificationCtx {
    ...
    virtual void verifyDigest(const std::vector<uint8_t> &signature,
                              const std::vector<uint8_t> &digest) = 0;
};

class MessageVerificationCtx {
    ...
    virtual void verifyMessage(const std::vector<uint8_t> &signature,
                               const std::vector<uint8_t> &message) = 0;
};
```

#### Example
If a context supports both, signing messages and message digest, the following code snippets are equal. For simplicity it is assumed that SHA256 is used to create the signed hash.
```cpp
    std::shared_ptr<DigestSignatureCtx> ctx = ...; // Hash Function set to SHA256
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    std::vector<uint8_t> digest = mococrw::Hash::sha256(message);
    std::vector<uint8_t> signature = ctx->signDigest(digest);
```
```cpp
    std::shared_ptr<MessageSignatureCtx> = ...; // Hash Function set to SHA256
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    std::vector<uint8_t> siganture = ctx->signMessage(message)
```

The verification contexts behave similarly.

# RSA - Encryption

By default the RSA encryption crypto contexts (for en- and decryption) are using the following options:
 * OAEP Padding:
    * Hash Function SHA256
    * Mask Generation Function: MGF1(SHA256)
    * Empty label

## Encryption (Default Padding)

```cpp
std::string pubKey= R"(-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----)";

std::vector<uint8_t> message = {...};

mococrw::AsymmetricPublicKey key = mococrw::AsymmetricKeypair::readPublicKeyFromPEM(pubKey);

/*
 * ...
 */

mococrw::RSAEncryptionPublicKeyCtx ctx = mococrw::RSAEncryptionPublicKeyCtx(key);

std::vector<uint8_t> encryptedMessage = ctx.encrypt(message)
```

## Decryption (Default Padding)

```cpp
std::string privKey= R"(-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----)";

std::vector<uint8_t> message = {...};

mococrw::AsymmetricPrivateKey key = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(privKey, "");

/*
 * ...
 */

mococrw::RSAEncryptionPrivateKeyCtx ctx = mococrw::RSAEncryptionPrivateKeyCtx(key);

try {
    std::vector<uint8_t> decryptedMessage = ctx.decrypt(message);
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Decryption Failed" << std::endl;
    ...
}
```

## Padding Modes

The current RSA encryption interface supports the following types of paddings for encryption:
* No Padding
* PKCS#1 v1.5
* OAEP

### No Padding
The following code shows how to create contexts that de-/encrypt without padding the content. Please note that this entails that the message size equals the size of the RSA key. Thus, this mode should only be used with care:
```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::NoPadding>();

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

### PKCS#1 v1.5
The following code shows how to create a context that de-/encrypts using the PKCS#1 v1.5 padding:
```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::PKCSPadding>();

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

### OEAP Padding
The OAEP Padding allows to choose the following:
 * Hash Function
 * Mask Generation Function
 * Label

On the contrary to the previous paddings, the OAEP Padding can be configured. The default options for OAEP are:
 * Hash Function: SHA256
 * Mask Generation Function: MGF1 (using the hash function specified as Hash Function)
 * Empty label

A OAEP Padding with default options can be created as follows:
```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::OAEPPadding>();

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

If a hash function other than SHA256 has to be used, the OEAP padding can be built as shown below:
```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::OAEPPadding>(mococrw::openssl::DigestTypes::SHA512);

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

In this case the hash function is set to SHA512. Please note that this also entails that SHA512 will be used by the mask generation function.

If the hash function that has to be used by the mask generation function is different the padding needs to be constructed as shown below:
```cpp
    std::shared_ptr<mococrw::MaskGenerationFunction> mgf = std::make_shared<MGF1>(mococrw::openssl::DigestTypes::SHA512);

    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::OAEPPadding>(mococrw::openssl::DigestTypes::SHA256, mgf);

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

Please note that for the moment being only the mask generation function MGF1 is available. The example above uses SHA256 as OEAP hash function and SHA512 as hash function for MGF1.

# RSA - Signing

Similar to the en-/decrpytion interface the signature interface supports several paddings. By default the following option will be used:
* Hash Function: SHA256
* PSS Padding:
    * Mask Generation Function: MGF1(SHA256)
    * Salt Length: 64

## Verification (Default Hash Function and Padding)

```cpp
std::string pubKey= R"(-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----)";

std::vector<uint8_t> message = {...};
std::vector<uint8_t> signature = {...};

mococrw::AsymmetricPublicKey key = mococrw::AsymmetricKeypair::readPublicKeyFromPEM(pubKey);

/*
 * ...
 */

mococrw::RSASignaturePublicKeyCtx ctx = mococrw::RSASignaturePublicKeyCtx(key);

try {
    // Hash of message is calculated automatically
    ctx.verifyMessage(signature, message);
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Invalid Signature" << std:endl;
    ...
}

// alternative (manual hashing)
std::vector<uint8_t> messageDigest = mococrw::Hash::sha256(message);
try {
    ctx.verifyDigest(signature, messageDigest);
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Invalid Signature" << std:endl;
    ...
}
```

## Signing (Default Hash Function and Padding)

```cpp
std::string privKey= R"(-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----)";

std::vector<uint8_t> message = {...};
std::vector<uint8_t> signature;

mococrw::AsymmetricPrivateKey key = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(privKey, "");

/*
 * ...
 */

mococrw::RSASignaturePrivateKeyCtx ctx = mococrw::RSASignaturePrivateKeyCtx(key);

// Hash of message is calculated automatically
signature = ctx.signMessage(message);

// Alternative (manual hashing)
std::vector<uint8_t> messageDigest = mococrw::Hash::sha256(message);
signature = ctx.signDigest(messageDigest);
```

## Using Different Hash Function
To use different hash function to create the hash to be signed (e.g. SHA512) the contexts have to be created as follows:

```cpp
mococrw::RSASignaturePublicKeyCtx verifyCtx = mococrw::RSASignaturePublicKeyCtx(key, mococrw::openssl::DigestTypes::SHA512);

mococrw::RSASignaturePrivateKeyCtx signCtx = mococrw::RSASignaturePrivateKeyCtx(key, mococrw::openssl::DigestTypes::SHA512);
```

## Padding Modes

Currently, the following padding modes are supported:
* PKCS#1 v1.5 Padding
* PSS Padding

### PKCS#1 v1.5

The following example shows how to create signing / verification contexts using the PKCS#1 v1.5 Padding.

```cpp
std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PKCSPadding>();

mococrw::RSASignaturePublicKeyCtx verifyCtx = mococrw::RSASignaturePublicKeyCtx(key, mococrw::openssl::DigestTypes::SHA256, padding);

mococrw::RSASignaturePrivateKeyCtx signCtx = mococrw::RSASignaturePrivateKeyCtx(key, mococrw::openssl::DigestTypes::SHA256, padding);
```

### PSS Padding

The PSS Padding allows to choose the following:
* Mask Generation Function
* Salt Length

The default values for these options are:
* Mask Generation Function: MGF1 using the hash function used to create the signature digest
* Salt Length: Length of the digests produced by the hash function used to create the signature digests

A PSS Padding with default options can be created as shown below:
```cpp
std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>();
```

The following example shows how to change the hash function (e.g. to SHA512) used by the Mask Generation Function. Please note that currently only
MGF1 is available:
```cpp
std::shared_ptr<MaskGenerationFunction> mgf = std::make_shared<MGF1>(mococrw::openssl::DigestTypes::SHA512);

std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>(mgf);
```

Please note that enforces the hash function of MGF1 to be SHA512, regardless of the hash function used to create the signed hash.

If the salt length shall be a non-default value, `nullptr` can be passed as padding which keeps the default behaviour of the Mask Generation Function. The following example sets the salt length to 20, while keeping the default behaviour for the Mask Generation Function:
```cpp
std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>(nullptr, 20);
```

# ECDSA

ECDSA only allows to choose the hash function that is used to create the signed hash. The default value is `SHA256`.

## Verification (Default Hash Function)

```cpp
std::string pubKey= R"(-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----)";

std::vector<uint8_t> message = {...};
std::vector<uint8_t> signature = {...};

mococrw::AsymmetricPublicKey key = mococrw::AsymmetricKeypair::readPublicKeyFromPEM(pubKey);

/*
 * ...
 */

mococrw::ECDSASignaturePublicKeyCtx ctx = mococrw::ECDSASignaturePublicKeyCtx(key);

try {
    // Hash of message is calculated automatically
    ctx.verifyMessage(signature, message);
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Invalid Signature" << std:endl;
    ...
}

// alternative (manual hashing)
std::vector<uint8_t> messageDigest = mococrw::Hash::sha256(message);
try {
    ctx.verifyDigest(signature, messageDigest);
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Invalid Signature" << std:endl;
    ...
}
```

## Signing (Default Hash Function)

```cpp
std::string privKey= R"(-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----)";

std::vector<uint8_t> message = {...};
std::vector<uint8_t> signature;

mococrw::AsymmetricPrivateKey key = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(privKey, "");

/*
 * ...
 */

mococrw::ECDSASignaturePrivateKeyCtx ctx = mococrw::ECDSASignaturePrivateKeyCtx(key);

// Hash of message is calculated automatically
signature = ctx.signMessage(message);

// Alternative (manual hashing)
std::vector<uint8_t> messageDigest = mococrw::Hash::sha256(message);
signature = ctx.signDigest(messageDigest);
```

## Using Different Hash Function
To use different hash function to create the hash to be signed (e.g. SHA512) the contexts have to be created as follows:

```cpp
mococrw::ECDSASignaturePublicKeyCtx verifyCtx = mococrw::ECDSASignaturePublicKeyCtx(key, mococrw::openssl::DigestTypes::SHA512);

mococrw::ECDSASignaturePrivateKeyCtx signCtx = mococrw::ECDSASignaturePrivateKeyCtx(key, mococrw::openssl::DigestTypes::SHA512);
```

