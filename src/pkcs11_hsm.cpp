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
#include <boost/algorithm/hex.hpp>
#include <boost/format.hpp>
#include "mococrw/hsm.h"

namespace mococrw
{
using namespace openssl;
using namespace p11;

const std::string Pkcs11Engine::ENGINE_ID = "pkcs11";

Pkcs11Engine::Pkcs11Engine(const std::string &module_path, const std::string &pin)
        : HsmEngine(ENGINE_ID, module_path, pin)
{
    pkcs11Ctx = _PKCS11_CTX_new();
    _PKCS11_CTX_load(pkcs11Ctx.get(), _modulePath);
    slotInfo = _PKCS11_enumerate_slots(pkcs11Ctx.get());
}

Pkcs11Engine::~Pkcs11Engine()
{
    _PKCS11_release_all_slots(pkcs11Ctx.get(), slotInfo);
    _PKCS11_CTX_unload(pkcs11Ctx.get());
}

P11_PKCS11_SLOT_PTR Pkcs11Engine::startOperation()
{
    // Step 1: Find the first suitable token.
    P11_PKCS11_SLOT_PTR slot = _PKCS11_find_token(pkcs11Ctx.get(), slotInfo);

    // Step 2: Open a session for the operation.
    _PKCS11_open_session(slot, SessionMode::ReadWrite /* set R/W permissions */);

    // Step 3: Log in.
    _PKCS11_login(slot, _pin);

    return slot;
}

void Pkcs11Engine::finishOperation(P11_PKCS11_SLOT_PTR slot)
{
    // Perform log out.
    _PKCS11_logout(slot);
}

void Pkcs11Engine::storePublicKey(EVP_PKEY *key, const std::string &label, const std::string &keyID)
{
    P11_PKCS11_SLOT_PTR slot = startOperation();

    // Get token to peform operation on.
    P11_PKCS11_TOKEN_PTR token = _PKCS11_getTokenFromSlot(slot);

    // Perform key storage.
    _PKCS11_store_public_key(token, key, label, keyID);

    finishOperation(slot);
}

void Pkcs11Engine::storePrivateKey(EVP_PKEY *key,
                                   const std::string &label,
                                   const std::string &keyID)
{
    P11_PKCS11_SLOT_PTR slot = startOperation();

    // Get token to peform operation on.
    P11_PKCS11_TOKEN_PTR token = _PKCS11_getTokenFromSlot(slot);

    // Perform key storage.
    _PKCS11_store_private_key(token, key, label, keyID);

    finishOperation(slot);
}

void Pkcs11Engine::generateKey(unsigned int bits, const std::string &label, const std::string &id)
{
    P11_PKCS11_SLOT_PTR slot = startOperation();

    // Get token to peform operation on.
    P11_PKCS11_TOKEN_PTR token = _PKCS11_getTokenFromSlot(slot);

    // Generate key inside HSM.
    _PKCS11_generate_key(token, bits, label, id);

    finishOperation(slot);
}

const std::string Pkcs11Engine::getName() { return ENGINE_ID; }

}  // namespace mococrw
