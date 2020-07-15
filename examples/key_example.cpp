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
#include <mococrw/key.h>
#include <iostream>
#include "mococrw/private/IOUtils.h"

#include "key_example.h"

void printPublicKey(const struct KeyData &keyData, const std::string &pubPem)
{
    if (!keyData.pubOut) {
        return;
    }
    if (keyData.pubOutFile) {
        writePemToFile(pubPem, *keyData.pubOutFile);
    } else {
        std::cout << pubPem << std::endl;
    }
}

void createKey(const struct KeyData &keyData)
{
    std::shared_ptr<AsymmetricKey::Spec> spec;
    if (keyData.rsa) {
        spec = std::make_shared<RSASpec>(keyData.keySize);
    } else {
        spec = std::make_shared<ECCSpec>(keyData.curve);
    }
    auto key = AsymmetricKeypair::generate(*spec);

    auto pem = key.privateKeyToPem(keyData.password);
    std::string pubPem;

    if (keyData.pubOut) {
        pubPem = key.publicKeyToPem();
    }

    if (!keyData.outFile.empty()) {
        writePemToFile(pem, keyData.outFile);
        printPublicKey(keyData, pubPem);
    } else {
        std::cout << pem << std::endl;
        printPublicKey(keyData, pubPem);
    }
}


