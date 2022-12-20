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
    MOCK_CONST_METHOD1(loadPublicKey, openssl::SSL_EVP_PKEY_Ptr(const std::string &keyID));
    MOCK_CONST_METHOD1(loadPrivateKey, openssl::SSL_EVP_PKEY_Ptr(const std::string &keyID));
    MOCK_CONST_METHOD4(generateKey,
                       openssl::SSL_EVP_PKEY_Ptr(const RSASpec &spec,
                                                 const std::string &keyID,
                                                 const std::string &tokenLabel,
                                                 const std::string &keyLabel));
    MOCK_CONST_METHOD4(generateKey,
                       openssl::SSL_EVP_PKEY_Ptr(const ECCSpec &spec,
                                                 const std::string &keyID,
                                                 const std::string &tokenLabel,
                                                 const std::string &keyLabel));
};

}  // namespace mococrw
