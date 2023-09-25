/*
 * #%L
 * %%
 * Copyright (C) 2022 BMW Car IT GmbH
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

#include "mococrw/hsm.h"
#include "mococrw/key.h"

#include <mutex>

namespace mococrw
{
/**
 * GMock class to mock the HSM interface.
 *
 */
class HSMMock final : public HSM
{
public:
    MOCK_CONST_METHOD1(loadPublicKey, openssl::SSL_EVP_PKEY_Ptr(const std::vector<uint8_t> &keyID));
    MOCK_CONST_METHOD2(loadPublicKey,
                       openssl::SSL_EVP_PKEY_Ptr(const std::string &keyLabel,
                                                 const std::vector<uint8_t> &keyID));
    MOCK_CONST_METHOD1(loadPrivateKey,
                       openssl::SSL_EVP_PKEY_Ptr(const std::vector<uint8_t> &keyID));
    MOCK_CONST_METHOD2(loadPrivateKey,
                       openssl::SSL_EVP_PKEY_Ptr(const std::string &keyLabel,
                                                 const std::vector<uint8_t> &keyID));
    MOCK_METHOD3(generateKey,
                 openssl::SSL_EVP_PKEY_Ptr(const RSASpec &spec,
                                           const std::string &keyLabel,
                                           const std::vector<uint8_t> &keyID));
    MOCK_METHOD3(generateKey,
                 openssl::SSL_EVP_PKEY_Ptr(const ECCSpec &spec,
                                           const std::string &keyLabel,
                                           const std::vector<uint8_t> &keyID));

    MOCK_METHOD4(generateKey,
                 openssl::SSL_EVP_PKEY_Ptr(const RSASpec &spec,
                                           const std::string &keyLabel,
                                           const std::vector<uint8_t> &keyID,
                                           const HsmKeyParams &params));
    MOCK_METHOD4(generateKey,
                 openssl::SSL_EVP_PKEY_Ptr(const ECCSpec &spec,
                                           const std::string &keyLabel,
                                           const std::vector<uint8_t> &keyID,
                                           const HsmKeyParams &params));
};

}  // namespace mococrw
