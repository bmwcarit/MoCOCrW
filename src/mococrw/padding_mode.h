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
     * @brief Get the padding mode
     *
     * Virtual getter method for the padding mode.
     */
    virtual openssl::RSAPaddingMode getPadding() const = 0;
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

private:
    /**
     * @brief The masking algorithm to be used. Not necessary for encryption, only when using the
     * signature facility.
     */
    openssl::DigestTypes _hashingFunction;
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

private:
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

}
