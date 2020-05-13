/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#pragma once

#include <memory>
#include "padding_mode.h"
#include "x509.h"
#include "openssl_wrap.h"

namespace mococrw {

/**
 * @brief Interface for encryption contexts
 */
class EncryptionCtx {
public:

    /**
     * @brief Destructor
     */
    virtual ~EncryptionCtx();

    /**
     * @brief Encrypt a message
     *
     * Encrypts a given message
     *
     * @param message The message to be encrypted
     * @returns The encrypted message
     * @throw MoCOCrWException If the encryption operation fails.
     */
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& message) = 0;
};

/**
 * @brief Interface for decryption contexts
 */
class DecryptionCtx {
public:
    /**
     * @brief Destructor
     */
    virtual ~DecryptionCtx();

    /**
     * @brief Decrypt a message
     *
     * Decrypts a given message
     *
     * @param message The message to be decrypted
     * @returns The decrypted message
     * @throw MoCOCrWException If the decryption operation fails.
     */
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& message) = 0;
};

/**
 * @brief RSAEncryptionPrivateKeyCtx
 *
 * This class supports decryption of RSA encrypted cipher texts.
 * Supported Paddings:
 *  - PKCS v1.5
 *  - OEAP
 *  - No Padding
 *
 * Default Padding: OEAP
 *  - Hash Function: SHA256
 *  - Mask Generation Function: MGF1(\<Hash Function\>)
 *  - Label: Empty String
 */
class RSAEncryptionPrivateKeyCtx : public DecryptionCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param padding OAEP Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key,
                               std::shared_ptr<RSAEncryptionPadding> padding = std::make_shared<OAEPPadding>());
    /**
     * @brief Destructor
     */
    ~RSAEncryptionPrivateKeyCtx();

    /**
     * @brief Copy Constructor
     */
    RSAEncryptionPrivateKeyCtx(const RSAEncryptionPrivateKeyCtx& other);

    /**
     * @brief Copy Assignment
     */
    RSAEncryptionPrivateKeyCtx& operator=(const RSAEncryptionPrivateKeyCtx& other);

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief RSAEncryptionPublicKeyCtx
 *
 * This class supports encryption of plain texts using RSA
 * Supported Paddings:
 *  - PKCS v1.5
 *  - OEAP
 *  - No Padding
 *
 * Default Padding: OEAP
 *  - Hash Function: SHA256
 *  - Mask Generation Function: MGF1(\<Hash Function\>)
 *  - Label: Empty String
 */
class RSAEncryptionPublicKeyCtx : public EncryptionCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param padding Padding parameters to be used (default OEAP)
     * @throw MoCOCrWException If key is not an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key,
                              std::shared_ptr<RSAEncryptionPadding> padding = std::make_shared<OAEPPadding>());
    /**
     * @brief Constructor
     * @param cert X509 Certificate containing RSA public key to be used
     * @param padding Padding parameters to be used (default OAEP)
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const X509Certificate& cert,
                              std::shared_ptr<RSAEncryptionPadding> padding = std::make_shared<OAEPPadding>());

    /**
     * @brief Copy Constructor
     */
    RSAEncryptionPublicKeyCtx(const RSAEncryptionPublicKeyCtx& other);

    /**
     * @brief Copy Assignment
     */
    RSAEncryptionPublicKeyCtx& operator=(const RSAEncryptionPublicKeyCtx& other);

    /**
     * @brief Destructor
     */
    ~RSAEncryptionPublicKeyCtx();

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief Interface for classes that support signing (pre-hashed) digests.
 */
class DigestSignatureCtx {
public:
    /**
     * @brief Destructor
     */
    virtual ~DigestSignatureCtx();

    /**
     * @brief Signs a digest
     *
     * Creates an signature for the given (pre-hashed) digest.
     *
     * @param messageDigest The digest to be signed
     * @return The created signature
     * @throw MoCOCrWException If the sign operation fails.
     * @throw MoCOCrWException If digest size doesn't match the expected digest size.
     */
    virtual std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest) = 0;
};

/**
 * @brief Interface for contexts that support signing messages.
 */
class MessageSignatureCtx {
public:
    /**
     * @brief Destructor
     */
    virtual ~MessageSignatureCtx();

    /**
     * @brief Signs a message
     *
     * Creates an signature for the given (unhashed) message. The message is automatically
     * hashed if required.
     *
     * @param message The message to be signed
     * @return The created signature
     * @throw MoCOCrWException If the sign operation fails.
     */
    virtual std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message) = 0;
};

/**
 * @brief Interface for contexts that support verification of (pre-hashed) digests.
 */
class DigestVerificationCtx {
public:
    /**
     * @brief Destructor
     */
    virtual ~DigestVerificationCtx();

    /**
     * @brief Verifies the signature of a digest
     *
     * Verifies the given signature of the given (pre-hashed) digest.
     *
     * @param signature The signature to be verified
     * @param digest The signed digest
     * @throw MoCOCrWException If the verification fails.
     */
    virtual void verifyDigest(const std::vector<uint8_t> &signature,
                              const std::vector<uint8_t> &digest) = 0;
};

/**
 * @brief Interface for contexts that support verification of message.
 */
class MessageVerificationCtx {
public:
    /**
     * @brief Destructor
     */
    virtual ~MessageVerificationCtx();
    /**
     * @brief Verifies the signature of a message
     *
     * Verifies the given signature of the given (unhashed) message. The message is automatically
     * hashed if required.
     *
     * @param signature The signature to be verified
     * @param message The signed message
     * @throw MoCOCrWException If the verification fails.
     */
    virtual void verifyMessage(const std::vector<uint8_t> &signature,
                               const std::vector<uint8_t> &message) = 0;
};

/**
 * @brief RSASignaturePrivateKeyCtx
 *
 * This class support signing messages and digest using RSA
 * Supported Paddings:
 *  - PKCS v1.5
 *  - PSS
 *
 * Default Padding: PSS
 *  - Hash Function: SHA256
 *  - Mask Generation Function: MGF1(\<Hash Function\>)
 *  - Salt Length: length of \<Hash Function\> digests
 */
class RSASignaturePrivateKeyCtx : public DigestSignatureCtx, public MessageSignatureCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param hashFunction The hash function to be used for signing
     * @param padding PSS Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                              openssl::DigestTypes hashFunction,
                              std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>());

    /**
     * @brief Copy Constructor
     */
    RSASignaturePrivateKeyCtx(const RSASignaturePrivateKeyCtx& other);

    /**
     * @brief Copy Assignment
     */
    RSASignaturePrivateKeyCtx& operator=(const RSASignaturePrivateKeyCtx& other);

    /**
     * @brief Destructor
     */
    ~RSASignaturePrivateKeyCtx();

    std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest) override;

    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief RSASignaturePublicKeyCtx
 *
 * This class support verifying RSA signatures of messages and digests
 * Supported Paddings:
 *  - PKCS v1.5
 *  - PSS
 *
 * Default Padding: PSS
 *  - Hash Function: SHA256
 *  - Mask Generation Function: MGF1(\<Hash Function\>)
 *  - Salt Length: length of \<Hash Function\> digests
 */
class RSASignaturePublicKeyCtx : public DigestVerificationCtx, public MessageVerificationCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param hashFunction The hash function to be used for signing
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA public key
     */
    RSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                             openssl::DigestTypes hashFunction,
                             std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>());

    /**
     * @brief Constructor
     * @param cert Certificate containing the RSA public key to be used
     * @param hashFunction The hash function to be used for signing
     * @param padding PSS Padding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSASignaturePublicKeyCtx(const X509Certificate& cert,
                             openssl::DigestTypes hashFunction,
                             std::shared_ptr<RSASignaturePadding> padding = std::make_shared<PSSPadding>());

    /**
     * @brief Copy Constructor
     */
    RSASignaturePublicKeyCtx(const RSASignaturePublicKeyCtx& other);

    /**
     * @brief Copy Assignment
     */
    RSASignaturePublicKeyCtx& operator=(const RSASignaturePublicKeyCtx& other);

    /**
     * @brief Destructor
     */
    ~RSASignaturePublicKeyCtx();

    void verifyDigest(const std::vector<uint8_t> &signature,
                      const std::vector<uint8_t> &digest) override;

    void verifyMessage(const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief Serialization formats for ECDSA signatures (with typo)
 */
enum class ECSDASignatureFormat {
    ASN1_SEQUENCE_OF_INTS, /**< Encoding of (r,s) as ASN.1 sequence of integers as specified in ANSI X9.62 */
    IEEE1363, /**< Encoding of (r,s) as raw big endian unsigned integers zero-padded to the key length
               *   as specified in IEEE 1363 */
};

/**
 * @brief Serialization formats for ECDSA signatures
 */
enum class ECDSASignatureFormat {
    ASN1_SEQUENCE_OF_INTS, /**< Encoding of (r,s) as ASN.1 sequence of integers as specified in ANSI X9.62 */
    IEEE1363, /**< Encoding of (r,s) as raw big endian unsigned integers zero-padded to the key length
               *   as specified in IEEE 1363 */
};

/**
 * @brief ECDSASignaturePrivateKeyCtx
 *
 * This class supports signing messages and digests using ECDSA
 * Default Hash Function: SHA256
 */
class ECDSASignaturePrivateKeyCtx : public DigestSignatureCtx, public MessageSignatureCtx {
public:
    /**
     * @brief Constructor
     *
     * @param key The private key to be used
     * @param hashFunction The hash function to be used
     * @throw MoCOCrWException If key is not an ECC private key
     */
    ECDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);

    /**
     * @brief Constructor
     *
     * @param key The private key to be used
     * @param hashFunction The hash function to be used
     * @param sigFormat The format of the generated signature
     * @throw MoCOCrWException If key is not an ECC private key
     */
    ECDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key, openssl::DigestTypes hashFunction,
                                ECDSASignatureFormat sigFormat);

    /**
     * @brief Copy Constructor
     */
    ECDSASignaturePrivateKeyCtx(const ECDSASignaturePrivateKeyCtx& other);

    /**
     * @brief Copy Assignment
     */
    ECDSASignaturePrivateKeyCtx& operator=(const ECDSASignaturePrivateKeyCtx& other);

    /**
     * @brief Destructor
     */
    ~ECDSASignaturePrivateKeyCtx();

    std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest) override;

    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief ECDSASignaturePublicKeyCtx
 *
 * This class supports the verification of ECDSA signatures of messages and digests
 * Default Hash Function: SHA256
 */
class ECDSASignaturePublicKeyCtx : public DigestVerificationCtx, public MessageVerificationCtx {
public:
    /**
     * @brief Constructor
     *
     * @param key The public key to be used
     * @param hashFunction The hash function to be used
     * @throw MoCOCrWException If key is not an ECC public key
     */
    ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                               openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);

    /**
     * @brief Constructor
     *
     * @param key The public key to be used
     * @param hashFunction The hash function to be used
     * @param sigFormat The format that in which signatures are provided
     * @throw MoCOCrWException If key is not an ECC public key
     */
    [[deprecated("Replaced by ECDSASignaturePublicKeyCtx() which expects ECDSASignatureFormat instead of ECSDASignatureFormat")]]
    ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key, openssl::DigestTypes hashFunction,
                               ECSDASignatureFormat sigFormat);

    /**
     * @brief Constructor
     *
     * @param key The public key to be used
     * @param hashFunction The hash function to be used
     * @param sigFormat The format that in which signatures are provided
     * @throw MoCOCrWException If key is not an ECC public key
     */
    ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key, openssl::DigestTypes hashFunction,
                               ECDSASignatureFormat sigFormat);

    /**
     * @brief Constructor
     *
     * @param cert The certificate containing the public key to be used
     * @param hashFunction The hash function to be used
     * @throw MoCOCrWException If cert doesn't contain an ECC public key
     */
    ECDSASignaturePublicKeyCtx(const X509Certificate& cert,
                               openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);

    /**
     * @brief Constructor
     *
     * @param cert The certificate containing the public key to be used
     * @param hashFunction The hash function to be used
     * @param sigFormat The format that in which signatures are provided
     * @throw MoCOCrWException If cert doesn't contain an ECC public key
     */
    [[deprecated("Replaced by ECDSASignaturePublicKeyCtx() which expects ECDSASignatureFormat instead of ECSDASignatureFormat")]]
    ECDSASignaturePublicKeyCtx(const X509Certificate& cert, openssl::DigestTypes hashFunction,
                               ECSDASignatureFormat sigFormat);

    /**
     * @brief Constructor
     *
     * @param cert The certificate containing the public key to be used
     * @param hashFunction The hash function to be used
     * @param sigFormat The format that in which signatures are provided
     * @throw MoCOCrWException If cert doesn't contain an ECC public key
     */
    ECDSASignaturePublicKeyCtx(const X509Certificate& cert, openssl::DigestTypes hashFunction,
                               ECDSASignatureFormat sigFormat);

    /**
     * @brief Copy Constructor
     */
    ECDSASignaturePublicKeyCtx(const ECDSASignaturePublicKeyCtx& other);

    /**
     * @brief Copy Assignment
     */
    ECDSASignaturePublicKeyCtx& operator=(const ECDSASignaturePublicKeyCtx& other);

    /**
     * @brief Destructor
     */
    ~ECDSASignaturePublicKeyCtx();

    void verifyDigest(const std::vector<uint8_t> &signature,
                      const std::vector<uint8_t> &digest) override;

    void verifyMessage(const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief EdDSASignaturePrivateKeyCtx
 *
 * This class supports signing message using EdDSA (PureEdDSA according to RFC8032).
 */
class EdDSASignaturePrivateKeyCtx : public MessageSignatureCtx {
public:

    /**
     * @brief Constructor
     * @param key The private key to be used
     * @throw MoCOCrWException If key is not an Ed448 or Ed25519 private key
     */
    EdDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey &key);

    /**
     * @brief Destructor
     */
    ~EdDSASignaturePrivateKeyCtx();

    /**
     * @brief Copy Constructor
     */
    EdDSASignaturePrivateKeyCtx(const EdDSASignaturePrivateKeyCtx &other);


    /**
     * @brief Copy Assignment
     */
    EdDSASignaturePrivateKeyCtx& operator=(const EdDSASignaturePrivateKeyCtx &other);

    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief EdDSASignaturePublicKeyCtx
 *
 * This class supports verifying EdDSA (PureEdDSA according to RFC8032) signatures.
 */
class EdDSASignaturePublicKeyCtx : public MessageVerificationCtx {
public:

    /**
     * @brief Constructor
     * @param key The public key to be used
     * @throw MoCOCrWException If key is not an Ed448 or Ed25519 public key
     */
    EdDSASignaturePublicKeyCtx(const AsymmetricPublicKey &key);

    /**
     * @brief Constructor
     * @param cert The certificate containing the publiy key to be used
     * @throw MoCOCrWException If the certificate does not contain an Ed448 or Ed25519 public key
     */
    EdDSASignaturePublicKeyCtx(const X509Certificate &cert);

    /**
     * @brief Destructor
     */
    ~EdDSASignaturePublicKeyCtx();

    /**
     * @brief Copy Constructor
     */
    EdDSASignaturePublicKeyCtx(const EdDSASignaturePublicKeyCtx &other);

    /**
     * @brief Copy Assignment
     */
    EdDSASignaturePublicKeyCtx& operator=(const EdDSASignaturePublicKeyCtx &other);

    void verifyMessage(const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message) override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};
}
