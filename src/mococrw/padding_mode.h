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

#include <openssl/evp.h>
#include "key.h"
#include "openssl_wrap.h"
#include "error.h"

namespace mococrw {
/**
 * @brief RSAPadding
 *
 * This class defines the interface for RSA Padding Mode objects, which contains all the parameters
 * specific to a given padding mode used by encryption/description and sign/verify operations.
 */
class RSAPadding
{
public:

    virtual ~RSAPadding() = default;

    /**
     * Crates a copy of the current object and returns it as a unique pointer.
     * @return unique pointer to the copy of the object.
     */
    virtual std::unique_ptr<RSAPadding> clone() = 0;

    /**
     * @brief Get the padding mode
     *
     * Virtual getter method for the padding mode.
     */
    virtual openssl::RSAPaddingMode getPadding() const = 0;

    /**
     * Checks if an given operation is supported by the padding mode
     * @param op Operation to check
     * @return true if the operations is supported, false otherwise
     */
    virtual bool isOperationSupported(const openssl::OperationTypes& op) const = 0;

    /**
     * @brief Get maximum data size that can encrypted using the PKCS padding
     * @param key RSA public key that will be used for encryption
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    virtual int getDataBlockSize(const AsymmetricPublicKey &key) const = 0;

    /**
     * Sets all padding specific configurations on the OpenSSL PKEY context object.
     * @param ctx OpenSSL PKEY context
     */
    virtual void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                                       const openssl::OperationTypes& op) = 0;
};

/**
 * @brief NoPadding
 *
 * This class defines the parameters specific to the RSA no padding mode.
 */
class NoPadding: public RSAPadding {
public:
    virtual ~NoPadding() = default;

    /**
     * Crates a copy of the current NoPadding object and returns it as a unique pointer.
     * @return unique pointer to the copy of the object.
     */
    std::unique_ptr<RSAPadding> clone() override
    { return std::make_unique<NoPadding>(*this); }

    /**
    * @brief Get the padding mode
    *
    * Getter method for the padding mode.
    *
    * @return \ref openssl::RSAPaddingMode::NONE
    */
    openssl::RSAPaddingMode getPadding() const override
    {
        return openssl::RSAPaddingMode::NONE;
    }

    /**
    * Checks if an given operation can be used with no padding mode.
    * @param op Operation to check
    * @return true if the operations is supported, false otherwise
    */
    bool isOperationSupported(const openssl::OperationTypes& op) const override;

    /**
    * @brief Get maximum data size that can encrypted, which is the same as
    * the the key when not using padding. Since we're not using any type of
    * padding, the data to encrypt need to have exactly the same size of
    * the key used
    * @param key RSA public key that will be used for encryption
    * @return the maximum size of the data that can be encrypted in bytes.
    */
    int getDataBlockSize(const AsymmetricPublicKey &key) const override
    {
        return key.getKeySize()/8;
    }

    /**
     * Currently there's no specific action that need to be made when no using any padding mode.
     * @param ctx OpenSSL PKEY context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                               const openssl::OperationTypes&) override
    {
        openssl::_EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(getPadding()));
    }
};

/**
 * @brief PKCSPadding
 *
 * This class defines the parameters specific to the PKCS1 padding mode.
 *
 * Defaults:
 * - Hashing function: SHA256
 */
class PKCSPadding: public RSAPadding {
public:
    PKCSPadding(openssl::DigestTypes hashingFunction = openssl::DigestTypes::SHA256)
        :_hashingFunction(hashingFunction)
    {
    }

    virtual ~PKCSPadding() = default;

    /**
     * Crates a copy of the current PKCSPadding object and returns it as a unique pointer.
     * @return unique pointer to the copy of the object.
     */
    std::unique_ptr<RSAPadding> clone() override
    { return std::make_unique<PKCSPadding>(*this); }

    /**
    * @brief Get the padding mode
    *
    * Getter method for the padding mode.
    *
    * @return \ref openssl::RSAPaddingMode::PKCS1
    */
    openssl::RSAPaddingMode getPadding() const override
    {
        return openssl::RSAPaddingMode::PKCS1;
    }

    /**
    * Checks if an given operation is supported by the PKCS padding mode
    * @return true, since all operations are supported by this padding mode
    */
    bool isOperationSupported(const openssl::OperationTypes&) const override { return true; }

    /**
     * @brief Get the hashing function
     *
     * Getter method for the hashing function.
     *
     * @return The hashing function
     */
    openssl::DigestTypes getHashingFunction() const
    {
        return _hashingFunction;
    }

    /**
     * @brief Get maximum data size that can encrypted using the PKCS padding
     * @param key RSA public key that will be used for encryption
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    int getDataBlockSize(const AsymmetricPublicKey &key) const override
    {
        return key.getKeySize()/8 - c_pkcsMaxSizeSOverhead;
    }

    /**
     * @brief Sets all Padding Mode spcific context Configuration
     * @param ctx OpenSSL context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, const openssl::OperationTypes& op) override;

private:
    /**
     * @brief The masking algorithm to be used. Not necessary for encryption, only when using the
     * signature facility.
     */
    openssl::DigestTypes _hashingFunction;

    /**
     * @brief Size overhead added by the PKCS padding on the RSA encryption
     */
    static const int c_pkcsMaxSizeSOverhead = 11;
};

/**
 * @brief PSSPadding
 *
 * This class defines the parameters specific to the RSA PSS padding mode.
 *
 * Defaults:
 * - Hashing function: SHA256
 * - Masking function: SHA256
 * - Salt length: 20
 */
class PSSPadding: public RSAPadding {
public:
    PSSPadding(openssl::DigestTypes hashing = openssl::DigestTypes::SHA256,
               openssl::DigestTypes masking = openssl::DigestTypes::SHA256,
               int saltLength = c_defaultSaltLength)
        : _hashingFunction{hashing}
        , _maskingFunction(masking)
        , _saltLength{saltLength}
        {
        }

    virtual ~PSSPadding() = default;

    /**
     * Crates a copy of the current PSSPadding object and returns it as a unique pointer.
     * @return unique pointer to the copy of the object.
     */
    std::unique_ptr<RSAPadding> clone() override
    { return std::make_unique<PSSPadding>(*this); }

    /**
    * @brief Get the padding mode
    *
    * Getter method for the padding mode.
    *
    * @return \ref openssl::RSAPaddingMode::PSS
    */
    openssl::RSAPaddingMode getPadding() const override
    {
        return openssl::RSAPaddingMode::PSS;
    }

    /**
    * Checks if an given operation is supported by the PSS padding mode
    * @param op Operation to check
    * @return true if the operations is supported, false otherwise
    */
    bool isOperationSupported(const openssl::OperationTypes& op) const override;

    /**
     * @brief Get the hashing function
     *
     * Getter method for the hashing function.
     *
     * @return The hashing function
     */
    openssl::DigestTypes getHashingFunction() const
    {
        return _hashingFunction;
    }

    /**
     * @brief Get the masking function
     *
     * Getter method for the masking function.
     *
     * @return The masking function
     */
    openssl::DigestTypes getMaskingFunction() const
    {
        return _maskingFunction;
    }

    /**
     * @brief Get the OAEP label
     *
     * Getter method for the OAEP label.
     *
     * @return The OAEP label
     */
    int getSaltLength() const
    {
        return _saltLength;
    }

    /**
     * @brief Sets all PSS specific context configurations.
     * @param ctx OpenSSL PKEY context
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, const openssl::OperationTypes& op) override;

private:
    /**
     * @brief Unused function for PSS because this padding mode is only used for signatures
     * @return -1.
     */
    int getDataBlockSize(const AsymmetricPublicKey &) const override { return -1; }

    /**
     * @brief The masking algorithm to be used. Not necessary for encryption.
     */
    openssl::DigestTypes _hashingFunction;

    /**
     * @brief The mgf1 to be used
     */
    openssl::DigestTypes _maskingFunction;

    /**
     * @brief The salt length
     */
    int _saltLength;

    /**
     * @brief Default value for the salt length
     */
    static const int c_defaultSaltLength = 20;
};

/**
 * @brief OAEPPadding
 *
 * This class defines the parameters specific to the OAEP padding mode:
 * - Hashing function
 * - Masking function
 * - Label
 *
 * @warning: Because of the currently used implementation of OpenSSL (1.0.2), the label size should
 *           be limited to maximum positive value of an integer (INT_MAX). This is a known bug that
 *           was fixed in OpenSSL v1.1
 *
 * All parameters have default values, and the label parameter is optional.
 */
class OAEPPadding: public RSAPadding {
public:
    OAEPPadding(openssl::DigestTypes hashing = openssl::DigestTypes::SHA256,
                    openssl::DigestTypes masking = openssl::DigestTypes::SHA256,
                    std::vector<uint8_t> label={})
        : _hashingFunction{hashing}
        , _maskingFunction{masking}
        , _label{label}
    {
    }

    virtual ~OAEPPadding() = default;

     /**
     * Crates a copy of the current OAEPPadding object and returns it as a unique pointer.
     * @return unique pointer to the copy of the object.
     */
    std::unique_ptr<RSAPadding> clone() override
    { return std::make_unique<OAEPPadding>(*this); }

    /**
     * @brief Get the hashing function
     *
     * Getter method for the hashing function.
     *
     * @return The hashing function
     */
    openssl::DigestTypes getHashingFunction() const
    {
        return _hashingFunction;
    }

    /**
     * @brief Get the masking function
     *
     * Getter method for the masking function.
     *
     * @return The masking function
     */
    openssl::DigestTypes getMaskingFunction() const
    {
        return _maskingFunction;
    }

    /**
     * @brief Get the OAEP label
     *
     * Getter method for the OAEP label.
     *
     * @return The OAEP label
     */
    std::vector<uint8_t> getLabel() const
    {
        return _label;
    }

    /**
     * @brief Get the padding mode
     *
     * Getter method for the padding mode.
     *
     * @return \ref openssl::RSAPaddingMode::OAEP
     */
    openssl::RSAPaddingMode getPadding() const override
    {
        return openssl::RSAPaddingMode::OAEP;
    }

    /**
    * Checks if an given operation is supported by the OAEP padding mode
    * @param op Operation to check
    * @return true if the operations is supported, false otherwise
    */
    bool isOperationSupported(const openssl::OperationTypes& op) const override;

    /**
     * @brief Get maximum data size that can encrypted using the OAEP padding
     * @param key RSA public key that will be used for encryption
     * @return the maximum size of the data that can be encrypted in bytes.
     */
    int getDataBlockSize(const AsymmetricPublicKey &key) const override
    {
        return key.getKeySize()/8 -
                (2 * openssl::_EVP_MD_size(_getMDPtrFromDigestType(_hashingFunction))) - 2;
    }

    /**
     * @brief Preforms all the specific configurations when using the OAEP padding mode.
     * @param ctx OpenSSL PKEY context that will store all specific configurations.
     */
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, const openssl::OperationTypes& op) override;

private:
    /**
     * @brief The masking algorithm to be used
     */
    openssl::DigestTypes _hashingFunction;
    /**
     * @brief The mgf1 to be used
     */
    openssl::DigestTypes _maskingFunction;
    /**
     * @brief The label
     */
    std::vector<uint8_t> _label;
};

}
