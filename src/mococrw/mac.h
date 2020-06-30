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
#include <memory>
#include <vector>
#include "openssl_wrap.h"

namespace mococrw
{

/**
 * @brief The MessageAuthenticationCode class is the abstract base class for the different implementation of
 * message authentication codes.
 */
class MessageAuthenticationCode {
public:

    /**
     * @brief ~MessageAuthenticationCode
     */
    virtual ~MessageAuthenticationCode();

    /**
     * Adds the message to the hash. This function may be invoked multiple times.
     * For finishing the calculation of the MAC invoke finish().
     *
     * @param message chunk of data used for MAC.
     * @throws MoCOCrWException if this function is invoked after finish was called.
     */
    virtual void update(const std::vector<uint8_t>& message) = 0;

    /**
     * @brief Finalize the MAC.
     *
     * This function calculates the message authentication code.
     *
     * @throws MoCOCrWException if this function is invoked twice.
     * @return The calculated message authentication code.
     */
    virtual std::vector<uint8_t> finish() = 0;

    /**
     * @brief Verifies the MAC
     *
     * This function compares the given value (macValue), with the value calculated during finish().
     * Invoke finish() before calling verify().
     * The length of the calculated value and the given value has to be the same!
     * This function also finishes the MAC if finish is not invoked in advance.
     *
     * The comparison happens in constant time.
     * @throws MoCOCrWException if the verification fails because the values or their lengths differ.
     * @param macValue The value which shall be compared to the calculated value
     */
    virtual void verify(const std::vector<uint8_t> &macValue) = 0;
};

class HMAC : public MessageAuthenticationCode {
public:
    /**
     * @brief Constructor
     * @param hashFunction The hash function which shall be used
     * @param key The key used for HMAC
     */
    HMAC(mococrw::openssl::DigestTypes hashFunction, const std::vector<uint8_t> &key);

    /**
     * @brief destructor
     */
    ~HMAC();

    /**
     * Adds the chunk of data to the hash. H(i-key || message1 [ || message2])
     * For getting the HMAC invoke finish()
     *
     * @param message chunk of data to used for HMAC.
     * @throws MoCOCrWException if this function is invoked after finish was called.
     */
    void update(const std::vector<uint8_t>& message) override;


    /**
     * @brief Finalize the HMAC.
     *
     * This function calculates the message authentication code.
     * H(o-key || H(i-key || message [ || message]))
     *
     * @throws MoCOCrWException if this function is invoked twice.
     * @return The hashed message authentication code
     */
    std::vector<uint8_t> finish() override;

    /**
     * @see MessageAuthenticationCode::verify
     */
    void verify(const std::vector<uint8_t> &hmacValue) override;

    /**
     * @brief The move constructor
     * @param other The other HMAC to be moved
     */
    HMAC(HMAC &&other);

    /**
     * @brief The assignment operator
     * @param other The other HMAC to be assigned
     * @return The result of the assignment
     */
    HMAC &operator=(HMAC &&other);

    /**
     * @brief Delete the copy constructor.
     */
    HMAC(const HMAC &other) = delete;

    /**
     * @brief Delete the copy assignment
     */
    HMAC & operator=(const HMAC&) = delete;

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
