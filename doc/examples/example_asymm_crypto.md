# Asymmetric Crypto API

# Common Interface

## Encryption Interface

All contexts that support encryption/decryption implement an `encrypt()` or `decrypt()` method respectively. The classes `mococrw::EncryptionCtx` and `mococrw::DecryptionCtx` provide a pure virtual interface to these methods:
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
These classes can be used to access an encryption/decryption contexts in a generic manner.

## Signature Interface

All contexts that support signing implement a method to sign pre-hashed message digests (`signDigest()`) or unhashed messages (`signMessage()`) or both. Note that if a message digest is required to be signed (or verified), it is expected that the client provides the digest of the message to be signed (i.e. performs the hashing on his own). On the contrary, signing a message means that the message digest will be calculated and then signed. The classes `mococrw::DigestSignatureCtx`, `mococrw::MessageSignatureCtx`, `mococrw::DigestVerificationCtx` and `mococrw::MessageVerificationCtx` provide a pure virtual interface to these methods:

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

If a context supports both signing messages and message digest, then the following code snippets are equal. For simplicity, it is assumed that SHA256 is used to create the signed hash.

```cpp
    std::shared_ptr<mococrw::DigestSignatureCtx> ctx = ...; // Hash Function set to SHA256
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    std::vector<uint8_t> digest = mococrw::Hash::sha256(message);
    std::vector<uint8_t> signature = ctx->signDigest(digest);
```

```cpp
    std::shared_ptr<mococrw::MessageSignatureCtx> = ...; // Hash Function set to SHA256
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    std::vector<uint8_t> signature = ctx->signMessage(message)
```

The verification contexts have similar behaviour.

# RSA - Encryption

By default, the RSA encryption crypto contexts (for encryption and decryption) are using the following options:
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

The following code shows how to create contexts that encrypt/decrypt without padding the content. Note, it is required that the message size is equal to the size of the RSA key. Thus, this mode should be used with care:

```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::NoPadding>();

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

### PKCS#1 v1.5

The following code shows how to create contexts that performs encryption and decryption using the PKCS#1 v1.5 padding:

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

Unlike previous paddings, the OAEP Padding can be configured. The default options for OAEP are:
 * Hash Function: SHA256
 * Mask Generation Function: MGF1 (using the hash function specified as Hash Function)
 * Empty label

A OAEP Padding with default options can be created as follows:

```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::OAEPPadding>();

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

If a hash function other than SHA256 is needed, the OEAP padding can be built as shown below:

```cpp
    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::OAEPPadding>(mococrw::openssl::DigestTypes::SHA512);

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

In this case, the hash function is set to SHA512. Note that this also entails that SHA512 will be used by the mask generation function.

If the hash function that has to be used by the mask generation function is different the padding needs to be constructed as shown below:

```cpp
    std::shared_ptr<mococrw::MaskGenerationFunction> mgf = std::make_shared<MGF1>(mococrw::openssl::DigestTypes::SHA512);

    std::shared_ptr<mococrw::RSAEncryptionPadding> padding = std::make_shared<mococrw::OAEPPadding>(mococrw::openssl::DigestTypes::SHA256, mgf);

    mococrw::RSAEncryptionPublicKeyCtx encCtx = mococrw::RSAEncryptionPublicKeyCtx(key, padding);

    mococrw::RSAEncryptionPrivateKeyCtx decCtx = mococrw::RSAEncryptionPrivateKeyCtx(key, padding);
```

Currently, only the mask generation function MGF1 is available. The example above uses SHA256 as OEAP hash function and SHA512 as hash function for MGF1.

# RSA - Signing

Similar to the encryption/decrpytion interface, the signature interface also supports several paddings. By default, the following options are used:
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

## Using Different Hash Functions

To use a different hash function and create the hash to be signed (e.g. SHA512), the contexts have to be created as follows:

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

The PSS Padding allows one to choose the following:
* Mask Generation Function
* Salt Length

The default values for these options are:
* Mask Generation Function: MGF1 using the hash function used to create the signature digest
* Salt Length: Length of the digests produced by the hash function used to create the signature digests

A PSS Padding with default options can be created as shown below:

```cpp
std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>();
```

The following example shows how to change the hash function (e.g. to SHA512) used by the Mask Generation Function. Currently, only
MGF1 is available:

```cpp
std::shared_ptr<MaskGenerationFunction> mgf = std::make_shared<MGF1>(mococrw::openssl::DigestTypes::SHA512);

std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>(mgf);
```

Please note the enforcing of the hash function of MGF1 to be SHA512, regardless of the hash function used to create the signed hash.

If the salt length is a non-default value, `nullptr` can be passed as padding, which keeps the default behaviour of the Mask Generation Function. The following example sets the salt length to 20, while keeping the default behaviour for the Mask Generation Function:

```cpp
std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>(nullptr, 20);
```

# ECDSA

ECDSA limits one to choose only the hash function that is used to create the signed hash. The default value is `SHA256`.

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

## Using Different Hash Functions

To use a different hash function and create the hash to be signed (e.g. SHA512), the contexts have to be created as follows:

```cpp
mococrw::ECDSASignaturePublicKeyCtx verifyCtx = mococrw::ECDSASignaturePublicKeyCtx(key, mococrw::openssl::DigestTypes::SHA512);

mococrw::ECDSASignaturePrivateKeyCtx signCtx = mococrw::ECDSASignaturePrivateKeyCtx(key, mococrw::openssl::DigestTypes::SHA512);
```

## Signature Formats

MoCOCrW supports two different formats for the signature:
* `mococrw::ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS`:
  Encoding of (r,s) as ASN.1 sequence of integers as specified in ANSI X9.62
* `mococrw::ECDSASignatureFormat::IEEE1363`:
  Encoding of (r,s) as raw big endian unsigned integers zero-padded to the key length as specified in IEEE 1363

MoCOCrW offers the following overloads to specify the signature formats:
* `mococrw::ECDSASignaturePublicKeyCtx(const mococrw::AsymmetricPublicKey&, mococrw::openssl::DigestTypes, mococrw::ECDSASignatureFormat)`
* `mococrw::ECDSASignaturePrivateKeyCtx(const mococrw::AsymmetricPrivateKey&, mococrw::openssl::DigestTypes, mococrw::ECDSASignatureFormat)`

# EdDSA

Note, EdDSA only implements signMessage/verifyMessage methods; the hash to be signed cannot be manually specified.

## Verification

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

mococrw::EdDSASignaturePublicKeyCtx ctx(key);

try {
    // Hash of message is calculated automatically
    ctx.verifyMessage(signature, message);
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Invalid Signature" << std:endl;
    ...
}

```

## Signing

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

mococrw::EdDSASignaturePrivateKeyCtx ctx(key);

// Hash of message is calculated automatically
signature = ctx.signMessage(message);
```
