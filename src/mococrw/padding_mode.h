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

#include "key.h"
#include "openssl_wrap.h"
#include "error.h"

namespace mococrw {

/**
 * @brief Interface for paddings for RSA encryptions
 */
class RSAEncryptionPadding {
public:
    /**
     * @brief Destructor
     */
    virtual ~RSAEncryptionPadding();

    /**
     * @brief Check if a message of a given size can be encrypted using the given padding.
     * @param key The RSA public key that will be used for encryption
     * @param messageSize The size of the message that will be encrypted
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    virtual bool checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const = 0;

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL PKEY context
     */
    virtual void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const = 0;
};

/**
 *  @brief RSASignaturePadding
 *
 *  Base Class for RSA Signature Paddings (because they all share the hash function attribute)
 */
class RSASignaturePadding {
public:
    /**
     * @brief Destructor
     */
    virtual ~RSASignaturePadding();

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL context
     * @param hashFunction The hash function to be used
     */
    virtual void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                                       openssl::DigestTypes hashFunction) const = 0;
};


/**
 * @brief NoPadding
 *
 * This class defines the parameters specific to the RSA no padding mode.
 */
class NoPadding : public RSAEncryptionPadding {
public:
    bool checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const override;

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const override;
};

/**
 * @brief PKCSPadding
 *
 * This class defines the parameters specific to the PKCS#1 v1.5 padding mode.
 *
 */
class PKCSPadding : public RSAEncryptionPadding, public RSASignaturePadding {
public:
    bool checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const override;

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const override;

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                               openssl::DigestTypes hashFunction) const override;

private:
    /**
     * @brief Size overhead added by the PKCS#1 padding on the RSA encryption
     */
    static const int PKCS_MAX_SIZE_OVERHEAD = 11;
};

/**
 * @brief Interface for mask generation functions
 */
class MaskGenerationFunction {
public:
    /**
     * @brief Prepares the given openssl context with the mask generation function specific parameters.
     * @param ctx OpenSSL context
     */
    virtual void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const = 0;
};

/**
 * @brief MGF1
 *
 * This class represents the mask generation function MGF1 (which is currently
 * the only available mask generation function)
 *
 * Defaults:
 *  - Hash Function: SHA256
 */
class MGF1 : public MaskGenerationFunction {
public:
    /**
     * @brief Construtor
     * @param hashFunction Hash function to be used
     */
    MGF1(openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const override;

private:
    /**
     *  Hash function to be used for mask generation
     */
    openssl::DigestTypes _hashFunction;
};

/**
 * @brief OAEPPadding
 *
 * This class defines the parameters specific to the OAEP padding mode:
 *
 * @warning: Because of the currently used implementation of OpenSSL (1.0.2), the label size should
 *           be limited to maximum positive value of an integer (INT_MAX). This is a known bug that
 *           was fixed in OpenSSL v1.1
 *
 * Defaults:
 *  - Hash Function: SHA256
 *  - Mask Generation Function: MGF1(<Hash Function>)
 *  - Label: Empty String
 */
class OAEPPadding : public RSAEncryptionPadding {
public:
    /**
     * @brief Constructor
     * @param hashFunction Hash function to be used
     * @param maskGenerationFunction mask generation function to be used (if equals nullptr
     *                               by default MGF1(hashFunction) will be used)
     * @param label Label to be used
     */
    OAEPPadding(openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256,
                std::shared_ptr<MaskGenerationFunction> maskGenerationFunction = nullptr,
                const std::string& label="");

    /**
     * @brief Copy Constrcutor
     */
    OAEPPadding(const OAEPPadding& other);

    /**
     * @brief Copy Assignment
     */
    OAEPPadding& operator=(const OAEPPadding& other);

    /**
     * @brief Destructor
     */
    ~OAEPPadding();

    bool checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const override;

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the mask generation function objects from clients)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief PSSPadding
 *
 * This class defines the parameters specific to the RSA PSS padding mode.
 *
 * Defaults:
 * - Mask Generation Function: MGF1(<Hash Function>):
 *   By default, the hash function used for the signature is also used for mask generation
 * - Salt length: Length of Hash Digest
 */
class PSSPadding: public RSASignaturePadding {
public:
    /**
     * @brief Constructor
     * @param maskGenerationFunction The mask generation function to be used (if equals nullptr
     *                               by default MGF1(hashFunction) will be used)
     * @param saltLength Length of salt to be used
     */
    PSSPadding(std::shared_ptr<MaskGenerationFunction> maskGenerationFunction = nullptr,
               boost::optional<int> saltLength = boost::none);

    /**
     * @brief Copy Constructor
     */
    PSSPadding(const PSSPadding& other);

    /**
     * @brief Copy Assignment
     */
    PSSPadding& operator=(const PSSPadding& other);

    /**
     * @brief Destructor
     */
    ~PSSPadding();

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                               openssl::DigestTypes hashFunction) const override;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the mask generation function objects from clients)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

}
