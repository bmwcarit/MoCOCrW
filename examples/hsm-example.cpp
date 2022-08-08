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
#include <mococrw/asymmetric_crypto_ctx.h>
#include <mococrw/hsm.h>
#include <iostream>

/* This example demonstrates how to create a PKCS11 engine object,
 * and store a key inside the HSM.
 */

using namespace mococrw;

int main(void)
{
    // Information for engine loading and key management.
    std::string id("pkcs11");
    std::string modulePath("/usr/lib/softhsm/libsofthsm2.so");
    std::string pin("1234");
    std::string keyID("1001");

    // Step 2: Initialise the PKCS11 Engine.
    HsmEngine hsmEngine(id, modulePath, pin);

    // Step 4: Load the key from the HSM and print it.
    auto pubKey = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyID);
    std::cout << "Loaded key: \n\n" << pubKey.publicKeyToPem() << "\n\n" << std::endl;

    return 0;
}