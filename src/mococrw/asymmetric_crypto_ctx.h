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
 *  - Mask Generation Function: MGF1(SHA256)
 *  - Label: Empty String
 */
class RSAEncryptionPrivateKeyCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param padding OAEP Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key,
                               OAEPPadding padding = OAEPPadding());
    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key, PKCSEncryptionPadding padding);

    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param padding NoPadding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key, NoPadding padding);

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

    /**
     * @brief Decrypt a message
     *
     * Decrypts a given message based on the specified key and padding mode
     *
     * @param message The message to be decrypted
     * @returns The decrypted message
     * @throw MoCOCrWException If the decryption operation fails.
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& message);

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
 *  - Mask Generation Function: MGF1(SHA256)
 *  - Label: Empty String
 */
class RSAEncryptionPublicKeyCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param padding OAEP Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key, OAEPPadding padding = OAEPPadding());

    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key, PKCSEncryptionPadding padding);

    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param padding NoPadding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key, NoPadding padding);

    /**
     * @brief Constructor
     * @param cert X509 Certificate containing RSA public key to be used
     * @param padding OAEP Padding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const X509Certificate& cert, OAEPPadding padding = OAEPPadding());

    /**
     * @brief Constructor
     * @param cert X509 Certificate containing RSA public key to be used
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const X509Certificate& cert, PKCSEncryptionPadding padding);

    /**
     * @brief Constructor
     * @param cert X509 Certificate containing RSA public key to be used
     * @param padding NoPadding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSAEncryptionPublicKeyCtx(const X509Certificate& cert, NoPadding padding);

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

    /**
     * @brief Encrypt a message
     *
     * Encrypts a given message based on the specified key and padding mode
     *
     * @param message The message to be encrypted
     * @returns The encrypted message
     * @throw MoCOCrWException If the encryption operation fails.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& message);

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
 * @brief RSASignaturePrivateKeyCtx
 *
 * This class support signing messages and digest using RSA
 * Supported Paddings:
 *  - PKCS v1.5
 *  - PSS
 *
 * Default Padding: PSS
 *  - Hash Function: SHA256
 *  - Mask Generation Function: MGF1(SHA256)
 *  - Salt Length: 64
 */
class RSASignaturePrivateKeyCtx {
public:
    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param padding PSS Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key, PSSPadding padding = PSSPadding());

    /**
     * @brief Constructor
     * @param key RSA private key to be used
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA private key
     */
    RSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key, PKCSSignaturePadding padding);

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

    /**
     * @brief Signs a message
     *
     * Creates an signature for the given message based on the given key and padding. The message
     * is automatically hashed.
     *
     * @param messageDigest The message to be signed
     * @return The created signature
     * @throw MoCOCrWException If the sign operation fails.
     */
    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message);

    /**
     * @brief Signs a digest
     *
     * Creates an signature for the given digest based on the given key and padding.
     *
     * @param messageDigest The digest to be signed
     * @return The created signature
     * @throw MoCOCrWException If the sign operation fails.
     * @throw MoCOCrWException If digest size doesn't match the expected digest size.
     */
    std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest);

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
 *  - Mask Generation Function: MGF1(SHA256)
 *  - Salt Length: 64
 */
class RSASignaturePublicKeyCtx {
public:

    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA public key
     */
    RSASignaturePublicKeyCtx(const AsymmetricPublicKey& key, PKCSSignaturePadding padding);

    /**
     * @brief Constructor
     * @param key RSA public key to be used
     * @param padding PSS Padding parameters to be used
     * @throw MoCOCrWException If key is not an RSA public key
     */
    RSASignaturePublicKeyCtx(const AsymmetricPublicKey& key, PSSPadding padding = PSSPadding());

    /**
     * @brief Constructor
     * @param cert Certificate containing the RSA public key to be used
     * @param padding PKCS v1.5 Padding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSASignaturePublicKeyCtx(const X509Certificate& cert, PKCSSignaturePadding padding);

    /**
     * @brief Constructor
     * @param cert Certificate containing the RSA public key to be used
     * @param padding PSS Padding parameters to be used
     * @throw MoCOCrWException If cert doesn't contain an RSA public key
     */
    RSASignaturePublicKeyCtx(const X509Certificate& cert, PSSPadding padding = PSSPadding());

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

    /**
     * @brief Verifies the signature of a message
     *
     * Verifies the given signature of the given message based on the given key and padding.
     *
     * @param signature The signature to be verified
     * @param message The signed message
     * @throw MoCOCrWException If the verification fails.
     */
    void verifyMessage(const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message);

    /**
     * @brief Verifies the signature of a digest
     *
     * Verifies the given signature of the given digest based on the given key and padding.
     *
     * @param signature The signature to be verified
     * @param digest The signed digest
     * @throw MoCOCrWException If the verification fails.
     */
    void verifyDigest(const std::vector<uint8_t> &signature,
                      const std::vector<uint8_t> &digest);

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
 * @brief ECDSASignaturePrivateKeyCtx
 *
 * This class supports signing messages and digests using ECDSA
 * Default Hash Function: SHA256
 */
class ECDSASignaturePrivateKeyCtx {
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

    /**
     * @brief Signs a message
     *
     * Creates an signature for the given message based on the given key and padding. The message
     * is automatically hashed.
     *
     * @param messageDigest The message to be signed
     * @return The created signature
     * @throw MoCOCrWException If the sign operation fails.
     */
    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message);

    /**
     * @brief Signs a digest
     *
     * Creates an signature for the given digest based on the given key and padding.
     *
     * @param messageDigest The digest to be signed
     * @return The created signature
     * @throw MoCOCrWException If the sign operation fails.
     * @throw MoCOCrWException If digest size doesn't match the expected digest size.
     */
    std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest);

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
class ECDSASignaturePublicKeyCtx {
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
     * @param cert The certificate containing the public key to be used
     * @param hashFunction The hash function to be used
     * @throw MoCOCrWException If cert doesn't contain an ECC public key
     */
    ECDSASignaturePublicKeyCtx(const X509Certificate& cert,
                               openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);
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

    /**
     * @brief Verifies the signature of a message
     *
     * Verifies the given signature of the given message based on the given key and padding.
     *
     * @param signature The signature to be verified
     * @param message The signed message
     * @throw MoCOCrWException If the verification fails.
     */
    void verifyMessage(const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &message);

    /**
     * @brief Verifies the signature of a digest
     *
     * Verifies the given signature of the given digest based on the given key and padding.
     *
     * @param signature The signature to be verified
     * @param digest The signed digest
     * @throw MoCOCrWException If the verification fails.
     */
    void verifyDigest(const std::vector<uint8_t> &signature,
                      const std::vector<uint8_t> &digest);
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
