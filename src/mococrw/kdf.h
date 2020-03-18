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
#include <vector>
#include "mac.h"

namespace mococrw
{

/**
 * @brief Abstract class for key derivation functions
 */
class KeyDerivationFunction
{
public:
    /**
     * destructor
     */
    ~KeyDerivationFunction();

    /**
     * @brief Provides a derived key.
     *
     * This function returns a derived key based on the arguments to this function and the arguments provided to
     * the constructor
     * @param password The password/secret key which shall be used for key derivation
     * @param outputLength The length of the derived key in bits.
     * @param salt The salt used for the key derivation
     * @throws MoCOCrWException if the required output length is greater than the length of the raw output.
     * @return The derived key
     */
    virtual std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password, const uint32_t outputLength,
                                           const std::vector<uint8_t> &salt) = 0;
};

class PBKDF2: public KeyDerivationFunction {
    /**
     * @brief Constructor
     * @param hashFunction The hash function which shall be used
     */
    PBKDF2(openssl::DigestTypes hashFunction);

    /**
     * @brief destructor
     */
    ~PBKDF2() {}

    /**
     * @brief Provides a derived key.
     *
     * This function returns a derived key based on the arguments to this function and the arguments provided to
     * the constructor
     * @param password The password/secret key which shall be used for key derivation
     * @param outputLength The length of the derived key in bits.
     * @param salt The salt used for the key derivation
     * @throws MoCOCrWException if the required output length is greater than the length of the raw output.
     * @return The derived key
     */
    std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password, const uint32_t outputLength,
                                   const std::vector<uint8_t> &salt) override;

private:
    class Impl;

    std::unique_ptr<Impl> _impl;

};

class X963KDF : public KeyDerivationFunction
{
    /**
     * @brief Constructor
     * @param hashFunction The hash function which shall be used
     */
    X963KDF(openssl::DigestTypes hashFunction);

    /**
     * @brief destructor
     */
    ~X963KDF();

    /**
     * @brief Provides a derived key.
     *
     * This function returns a derived key based on the arguments to this function and the arguments provided to
     * the constructor
     * @param password The password/secret key which shall be used for key derivation
     * @param outputLength The length of the derived key in bits.
     * @param salt The salt used for the key derivation
     * @throws MoCOCrWException if the required output length is creater than the length of the raw output.
     * @return The derived key
     */
    std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password, const uint32_t outputLength,
                                   const std::vector<uint8_t> &salt) override;

private:
    class Impl;

    std::unique_ptr<Impl> _impl;
};

}
