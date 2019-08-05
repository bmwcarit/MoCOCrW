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
 * @brief NoPadding
 *
 * This class defines the parameters specific to the RSA no padding mode.
 */
class NoPadding {
public:
    /**
     * @brief Get maximum data size that can encrypted, which is the same as
     * the key when not using padding. Since we're not using any type of
     * padding, the data to encrypt needs to have exactly the same size of
     * the key used
     * @param key RSA public key that will be used for encryption
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    int getDataBlockSize(const AsymmetricPublicKey &key) const;

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL PKEY context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const;
};


/**
 * @brief PKCSEncryptionPadding
 *
 * This class defines the parameters specific to the PKCS1 padding mode.
 *
 */
class PKCSEncryptionPadding {
public:
    /**
     * @brief Get maximum data size that can encrypted using the PKCS padding
     * @param key RSA public key that will be used for encryption
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    int getDataBlockSize(const AsymmetricPublicKey &key) const;

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const;

private:
    /**
     * @brief Size overhead added by the PKCS padding on the RSA encryption
     */
    static const int c_pkcsMaxSizeSOverhead = 11;
};

/**
 *  @brief RSASignaturePadding
 *
 *  Base Class for RSA Signature Paddings (because they all share the hash function attribute)
 */
class RSASignaturePadding  {
public:
    /**
     * @brief Construtor for RSASignaturePadding
     * @param hashFunction Hash function to be used
     */
    RSASignaturePadding(openssl::DigestTypes hashFunction);

     /**
      * @brief Get the hash function
      *
      * Getter method for the hash function.
      *
      * @return The hash function
      */
    openssl::DigestTypes getHashFunction() const;

protected:
    /**
     * @brief Hash function to be used for signing
     */
    openssl::DigestTypes _hashFunction;
};

/**
 * @brief PKCSSignaturePadding
 *
 * This class defines the parameters specific to the PKCS1 padding mode.
 *
 * Defaults:
 * - Hash function: SHA256
 */
class PKCSSignaturePadding: public RSASignaturePadding {
public:
    /**
     * @brief Constructor for PKCSSignaturePadding
     * @param hashFunction Hash function to be used
     */
    PKCSSignaturePadding(openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const;

private:
    /**
     * @brief Size overhead added by the PKCS padding on the RSA encryption
     */
    static const int c_pkcsMaxSizeSOverhead = 11;
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
class MGF1 {
public:
    /**
     * @brief Construtor
     * @param hashFunction Hash function to be used
     */
    MGF1(openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256);

    /**
     * @brief Prepares the given openssl context with the masking function specific parameters.
     * @param ctx OpenSSL context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const;
private:
    /**
     *  Hash function to be used for mask generation
     */
    openssl::DigestTypes _hashFunction;
};

/**
 * @brief PSSPadding
 *
 * This class defines the parameters specific to the RSA PSS padding mode.
 *
 * Defaults:
 * - Hash Function: SHA256
 * - Mask Generation Function: MGF1(<Hash Function>):
 *   By default, the specified hash function is also used for mask generation
 * - Salt length: Length of Hash Digest
 *
 * Currently only supports MGF1 objects for mask generation. If there ever will
 * be another mask generation function a second constructor may be added.
 */
class PSSPadding: public RSASignaturePadding {
public:
    /**
     * @brief Constructor
     * @param hashFunction Hash function to be used
     * @param mgf1 MGF1 mask generation function to be used (if equals boost::none
     *             by default MGF1(hashFunction) will be used)
     * @param saltLength Length of salt to be used
     */
    PSSPadding(openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256,
               boost::optional<MGF1> maskGenerationFunction = boost::none,
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

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL PKEY context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const;

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the masking function objects from clients)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
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
class OAEPPadding {
public:
    /**
     * @brief Constructor
     * @param hashFunction Hash function to be used
     * @param mgf1 MGF1 mask generation function to be used (if equals boost::none
     *             by default MGF1(hashFunction) will be used)
     * @param label Label to be used
     */
    OAEPPadding(openssl::DigestTypes hashFunction = openssl::DigestTypes::SHA256,
                boost::optional<MGF1> maskGenerationFunction = boost::none,
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

    /**
     * @brief Get maximum data size that can encrypted using the OAEP padding
     * @param key RSA public key that will be used for encryption
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    int getDataBlockSize(const AsymmetricPublicKey &key) const;

    /**
     * @brief Prepares the given openssl context with the padding specific parameters.
     * @param ctx OpenSSL PKEY context that will store all specific configurations.
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx);

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the masking function objects from clients)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

}
