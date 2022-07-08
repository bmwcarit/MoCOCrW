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
#include "mococrw/hsm.h"
#include <boost/format.hpp>

namespace mococrw
{
using namespace openssl;

HSM::HSM() {}

HsmEngine::HsmEngine(const std::string &id, const std::string &modulePath, const std::string &pin)
        : _id(id), _modulePath(modulePath), _pin(pin)
{
    // Fetch engine via ID.
    _engine = _ENGINE_by_id(_id);

    _ENGINE_ctrl_cmd_string(_engine.get(), "MODULE_PATH", _modulePath);
    _ENGINE_ctrl_cmd_string(_engine.get(), "PIN", _pin);
    _ENGINE_init(_engine.get());
}

HsmEngine::~HsmEngine() { _ENGINE_finish(_engine.get()); }

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPublicKey(const std::string &keyID)
{
    return _ENGINE_load_public_key(_engine.get(), keyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPrivateKey(const std::string &keyID)
{
    return _ENGINE_load_private_key(_engine.get(), keyID);
}

}  // namespace mococrw
