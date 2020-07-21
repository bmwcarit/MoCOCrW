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
#include "ecies_example.h"

#include <mococrw/x509.h>
#include <iostream>

using namespace mococrw;

bool isPubKeyAnEccKey(const AsymmetricPublicKey &pubKey)
{
    std::shared_ptr<AsymmetricKey::Spec> spec = pubKey.getKeySpec();
    auto eccSpec = std::dynamic_pointer_cast<ECCSpec>(spec);
    if (eccSpec) {
        /* The key is an ECC key */
        return true;
    }
    return false;
}

std::unique_ptr<ECIESEncryptionCtx> buildEncryptionContext(const struct EciesData &eciesData)
{
    ECIESCtxBuilder encBuilder;
    std::unique_ptr<ECIESEncryptionCtx> encCtx;

    if (eciesData.kdfFunc) {
        encBuilder.setKDF(eciesData.kdfFunc);
    }

    if (eciesData.macFunc) {
        encBuilder.setMacFactoryFunction(eciesData.macFunc);
        encBuilder.setMacKeySize(eciesData.macKeySize);
    }

    if (eciesData.pubKey) {
        return encBuilder.buildEncryptionCtx(*eciesData.pubKey.get());
    }

    /* we got a certificate */
    return encBuilder.buildEncryptionCtx(*eciesData.cert.get());
}

std::unique_ptr<ECIESDecryptionCtx> buildDecryptionContext(const struct EciesData &eciesData)
{
    ECIESCtxBuilder decBuilder;

    if (eciesData.kdfFunc) {
        decBuilder.setKDF(eciesData.kdfFunc);
    }

    if (eciesData.macFunc) {
        decBuilder.setMacFactoryFunction(eciesData.macFunc);
        decBuilder.setMacKeySize(eciesData.macKeySize);
    }

    return decBuilder.buildDecryptionCtx(*eciesData.privKey.get(), *eciesData.ephKey.get());
}

void printChainingData(const po::variables_map &vm)
{
    if (vm.count("kdf-algo")) {
        std::cout << "--kdf-algo " << (vm["kdf-algo"].as<std::string>()) << " ";
        std::cout << "--kdf-hash-algo " << vm["kdf-hash-algo"].as<std::string>() << " ";
        if (vm.count("kdf-algo-iterations")) {
            std::cout  << "--kdf-algo-iterations " << vm["kdf-algo-iterations"].as<uint>() << " ";
        }
    }

    if (vm.count("mac-algo")) {
        std::cout << "--mac-algo " << vm["mac-algo"].as<std::string>() << " ";
        std::cout << "--mac-hash-algo " << vm["mac-hash-algo"].as<std::string>() << " ";
        std::cout << "--mac-key-size " << std::to_string(vm["mac-key-size"].as<uint>()) << " ";
    }
}

void encrypt_ecies(const struct EciesData &eciesData)
{
    std::unique_ptr<ECIESEncryptionCtx> encCtx = buildEncryptionContext(eciesData);

    try {
         encCtx->update(eciesData.data);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Error encrypting data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (eciesData.chaining) {
        printChainingData(*eciesData.vm.get());
        std::cout << "--data " << utility::toHex(encCtx->finish()) << " ";
        std::cout << "--eph-key " << utility::toHex(encCtx->getEphemeralKey().toECPoint(eciesData.ecForm))
                  << " ";
        std::cout << "--mac-value " << utility::toHex(encCtx->getMAC()) << std::endl;
        return;
    }

    std::cout << "Ciphertext: " << utility::toHex(encCtx->finish()) << std::endl;
    std::cout << "Ephemeral key: " << utility::toHex(encCtx->getEphemeralKey().toECPoint(eciesData.ecForm))
              << std::endl;
    std::cout << "MAC: " << utility::toHex(encCtx->getMAC()) << std::endl;
}

void decrypt_ecies(const struct EciesData &eciesData)
{
    /* We need
     * - mac value
     * - ephemeral key
     * - private key
     */

    /* Use the default values, which should match here. */
    auto decCtx = buildDecryptionContext(eciesData);
    try {
        /* Decrypt the ciphertext */
        decCtx->update(eciesData.data);

        /* Set the received mac value */
        decCtx->setMAC(eciesData.macValue);
    } catch (MoCOCrWException &e) {
        std::cerr << "Error decrypting integrated encryption scheme." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    /* Get the plaintext and verify the MAC */
    auto result = decCtx->finish();

    std::cout << utility::toHex(result) << std::endl;
}
