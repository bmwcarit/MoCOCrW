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
 * message authentication code.
 */
class MessageAuthenticationCode {
public:
    ~MessageAuthenticationCode() {}

    /**
     * @brief Calculates the tag/mac based on the key, the message and the parameters provided to the constructor
     * @param key The which shall be used for calculation
     * @param message The message which shall be authenticated
     * @return The message authentication tag
     */
    virtual std::vector<uint8_t> calculate(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) = 0;
};

class HMAC : public MessageAuthenticationCode{
public:
    /**
     * @brief Constructor
     * @param hashFunction The hash function which shall be used
     * @param tagBitsLength The length of the tag/mac in number of bits
     */
    HMAC(openssl::DigestTypes hashFunction, uint32_t tagBitsLength);

    /**
     * @brief destructor
     */
    ~HMAC();

    /**
     * @brief Calculates the tag/mac based on the key, the message and the parameters provided to the constructor
     * @param key The key which shall be used for calculation
     * @param message The message which shall be authenticated
     * @return The message authentication tag
     */
    std::vector<uint8_t> calculate(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) override;

private:
    class Impl;

    std::unique_ptr<Impl> _impl;
};

}
