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

#include "padding_mode.h"
#include "x509.h"

namespace mococrw {

class AsymmetricCryptoCtx
{
public:

    /**
    * Forward declaration of nested Builder class
    *
    * Definition is below.
    *
    */
    class Builder;

    AsymmetricCryptoCtx(const AsymmetricCryptoCtx &other) : _paddingMode{other._paddingMode->clone()},
                                                            _eccMd{other._eccMd} {}

    AsymmetricCryptoCtx(const AsymmetricCryptoCtx &&other)  : _paddingMode{other._paddingMode->clone()},
                                                             _eccMd{other._eccMd} {}

    virtual ~AsymmetricCryptoCtx() = default;

    /**
     * Returns the type (RSA/ECC) of the underlying asymmetric key.
     * @return the key type.
     */
    virtual AsymmetricKey::KeyTypes getKeyType() const = 0;

    /**
     * Sets the RSA padding mode Object
     * @param rsaPaddingMode padding mode to be used
     */
    void setRsaPaddingMode (std::unique_ptr<RSAPadding> const& rsaPaddingMode)
    { _paddingMode = rsaPaddingMode->clone(); }

    /**
     * Sets the RSA padding mode Object
     * @param rsaPaddingMode padding mode to be used
     */
    void setRsaPaddingMode (std::unique_ptr<RSAPadding>&& rsaPaddingMode)
    { _paddingMode = std::move(rsaPaddingMode); }

    /**
     * Sets the Masking function to be used in the ECC operation
     * @param eccHashing Ecc Masking function
     */
    void setEccHashingFunction(const openssl::DigestTypes& eccHashing) { _eccMd = eccHashing; }

protected:
    AsymmetricCryptoCtx() = default;

    void _setupSignatureOpenSSLCtx(openssl::SSL_EVP_PKEY_CTX_Ptr &keyCtx,
                                   const openssl::OperationTypes &op);

    std::unique_ptr<RSAPadding> _paddingMode{nullptr};
    openssl::DigestTypes _eccMd{openssl::DigestTypes::SHA256};
};

/**
 * @Brief Asymmetric public key operations
 *
 * This class supports all asymmetric crypto operations that can be done with a public key (RSA/ECC)
 * During the construction of this object we can specify the necessary parameters for the operations
 * we want to preform (@ref AsymmetricCryptoCtx::Builder).
 *
 * Operations supported by this class are:
 * - Asymmetric encryption
 * - Asymmetric signature verification
 */
class AsymmetricPubkeyCtx : public AsymmetricCryptoCtx
{
public:
    AsymmetricPubkeyCtx(const AsymmetricPubkeyCtx &other) = default;

    AsymmetricPubkeyCtx(AsymmetricPubkeyCtx &&other) = default;

    virtual ~AsymmetricPubkeyCtx() = default;

    /**
     * @brief Gets the type of the underlying asymmetric public key
     * @return the key type
     */
    AsymmetricKey::KeyTypes getKeyType() const override { return _publicKey.getType(); }

    /**
     * @brief Gets the the underlying asymmetric public key
     * @return the underlying asymmetric key
     */
    AsymmetricPublicKey getKey() const { return  _publicKey; }

    /**
    * @brief Encrypt a message
    *
    * Encrypts the input message based on a given encryption context that contains an asymmetric
    * key pair (RSA/ECC).
    *
    * @param message The message to be encrypted
    * @returns The encrypted message
    * @throw MoCOCrWException if the encryption operation fails.
    */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& message);

    /**
     * @brief Verify a signature
     *
     * Verifies a signature based on the message digest and a given verification context, that
     * includes an asymmetric public key or X509 certificate (RSA/ECC) .
     *
     * @param signature The signature to be verified
     * @param messageDigest The message digest the signature is verified with
     * @throw MoCOCrWException if the verification fails.
     */
    void verify(const std::vector<uint8_t> &signature,
                       const std::vector<uint8_t> &messageDigest);
private:
    friend AsymmetricCryptoCtx::Builder;

    explicit AsymmetricPubkeyCtx(const AsymmetricPublicKey& publicKey) : _publicKey{publicKey} {}

    AsymmetricPublicKey _publicKey;
};

/**
 * @Brief Asymmetric public key operations
 *
 * This class supports asymmetric crypto operations that can be done with a private key (RSA/ECC).
 * During the construction of this object we can specify the necessary parameters for the operations
 * we want to preform (@ref AsymmetricCryptoCtx::Builder).
 *
 * Operations supported by this class are:
 * - Asymmetric decryption
 * - Asymmetric signing
 */
class AsymmetricPrivkeyCtx : public AsymmetricCryptoCtx
{
public:
    AsymmetricPrivkeyCtx(const AsymmetricPrivkeyCtx &other) = default;

    AsymmetricPrivkeyCtx(AsymmetricPrivkeyCtx &&other) = default;

    virtual ~AsymmetricPrivkeyCtx() = default;

    /**
     * @brief Gets the type of the underlying asymmetric key pair
     * @return the key type
     */
    AsymmetricKey::KeyTypes getKeyType() const override { return _keyPair.getType(); }

    /**
     * @brief Gets the the underlying asymmetric key pair
     * @return the underlying asymmetric key pair
     */
    AsymmetricPrivateKey getKey() const { return  _keyPair; }

    /**
    * @brief Decrypt a message
    *
    * Decrypts a ciphered message based on a given decryption (RSA/ECC).
    *
    * @param message The message to be decrypted
    * @returns The decrypted message
    * @throw MoCOCrWException if the encryption operation fails.
    */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& message);

    /**
    * @brief Signs a message
    *
    * Creates an signature for a message digest based on a given private context that contains
    * an asymmetric key par (RSA/ECC).
    *
    * @param messageDigest The message digest to sign
    * @return The created signature of the message
    * @throw MoCOCrWException if the sign operation fails.
    */
    std::vector<uint8_t> sign(const std::vector<uint8_t> &messageDigest);

private:
    friend AsymmetricCryptoCtx::Builder;

    explicit AsymmetricPrivkeyCtx(const AsymmetricPrivateKey& privateKey) : _keyPair{privateKey} {}

    AsymmetricPrivateKey _keyPair;
};

/**
 * @Builder class to construct the Asymmetric context objects.
 *
 * The type of context (Public or Private key context) is built is decided by what type of key is
 * provided to the @ref AsymmetricCryptoCtx::Builder::build() method.
 */
class AsymmetricCryptoCtx::Builder
{
public:
    Builder() = default;

    /**
     * Sets the rsaPaddingMode to be used in the context
     * @param rsaPaddingMode padding mode to be used int hte context creation
     * @return current builder object in use
     */
    Builder &rsaPaddingMode(std::unique_ptr<RSAPadding> const& rsaPaddingMode);

    /**
     * Sets the rsaPaddingMode to be used in the context
     * @param rsaPaddingMode padding mode to be used int hte context creation
     * @return current builder object in use
     */
    Builder &rsaPaddingMode(std::unique_ptr<RSAPadding>&& rsaPaddingMode);

    /**
     * Sets the ECC masking function to be used in the context
     * @param eccMaskingFunction ecc masking function
     * @return current builder object in use
     */
    Builder &eccMaskingFunction(openssl::DigestTypes const& eccMaskingFunction);

    /**
     * Builder method with public key
     * @param publicKey public key to be used by the context
     * @return Asymmetric Public key context
     */
    AsymmetricPubkeyCtx build(const AsymmetricPublicKey& publicKey);

    /**
     * Builder method with X509 certificate
     * @param certificate X509 certificate to extract the public key from
     * @return Asymmetric Public key context
     */
    AsymmetricPubkeyCtx build(const X509Certificate& certificate);

    /**
     * Builder method with private key
     * @param privateKey private key to be used by the context
     * @return Asymmetric Private key context
     */
    AsymmetricPrivkeyCtx build(const AsymmetricPrivateKey& privateKey);

private:
    void _buildHelper(AsymmetricCryptoCtx &ctx);

    std::unique_ptr<RSAPadding> _paddingMode{nullptr};
    openssl::DigestTypes _eccMd{openssl::DigestTypes::SHA256};
};
}
