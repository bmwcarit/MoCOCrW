/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
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
#include <cstdint>
#include <memory>
#include <vector>
#include "hash.h"

namespace mococrw
{
/**
 * @brief Abstract class for key derivation functions
 */
class KeyDerivationFunction
{
public:
    /**
     * @brief destructor
     */
    virtual ~KeyDerivationFunction();
    /**
     * @brief Provides a derived key.
     *
     * This function returns a derived key based on the arguments passed to this function and the
     * arguments provided to the constructor
     * @param password The password/secret key which shall be used for key derivation
     * @param outputLength The length of the derived key in bytes.
     * @param salt The salt used for the key derivation
     * @throws OpenSSLException This method may throw an OpenSSLException if OpenSSL indicates an
     * error.
     * @return The derived key
     */
    virtual std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password,
                                           const size_t outputLength,
                                           const std::vector<uint8_t> &salt) = 0;
};

class PBKDF2 : public KeyDerivationFunction
{
public:
    /**
     * @brief Constructor
     * @param hashFunction The hash function which shall be used
     * @param iterations Number of iterations performed during deriveKey
     */
    PBKDF2(openssl::DigestTypes hashFunction, uint32_t iterations);

    /**
     * @brief destructor
     */
    ~PBKDF2();

    /**
     * @see KeyDerivationFunction::deriveKey
     */
    std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password,
                                   const size_t outputLength,
                                   const std::vector<uint8_t> &salt) override;

    /**
     * @brief The move constructor
     * @param other The object to move
     */
    PBKDF2(PBKDF2 &&other);

    /**
     * @brief The copy constructor
     * @param other The object to copy
     */
    PBKDF2(const PBKDF2 &other);

    /**
     * @brief The move assignment operator
     * @param other The object to move
     * @return The result of the assignment
     */
    PBKDF2 &operator=(PBKDF2 &&other);

    /**
     * @brief The copy assignment operator
     * @param other The object to copy
     * @return The result of the assignment
     */
    PBKDF2 &operator=(const PBKDF2 &other);

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

class X963KDF : public KeyDerivationFunction
{
public:
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
     * @see KeyDerivationFunction::deriveKey
     */
    std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password,
                                   const size_t outputLength,
                                   const std::vector<uint8_t> &salt) override;

    /**
     * @brief The move constructor
     * @param other The object to move
     */
    X963KDF(X963KDF &&other);

    /**
     * @brief The copy constructor
     * @param other The object to copy
     */
    X963KDF(const X963KDF &other);

    /**
     * @brief The move assignment operator
     * @param other The object to move
     * @return The result of the assignment
     */
    X963KDF &operator=(X963KDF &&other);

    /**
     * @brief The copy assignment operator
     * @param other The object to copy
     * @return The result of the assignment
     */
    X963KDF &operator=(const X963KDF &other);

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

}  // namespace mococrw
