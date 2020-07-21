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
#include <iostream>
#include <mococrw/asymmetric_crypto_ctx.h>

#include "rsa_example.h"

void printChainingData(const po::variables_map &vm)
{
    if (vm.count("padding")) {
        std::cout << "--padding " << vm["padding"].as<std::string>() << " ";
    }

    if (vm.count("oaep-hash-algo")) {
        std::cout << "--oaep-hash-algo " << vm["oaep-hash-algo"].as<std::string>() << " ";
    }

    if (!vm["oaep-label"].as<std::string>().empty()) {
        std::cout << "--oaep-label " << vm["oaep-label"].as<std::string>() << " ";
    }

    std::cout << "--data ";
}

void encrypt_rsa(const struct RsaData &rsaData) {
    RSAEncryptionPublicKeyCtx rsaPubCtx(*rsaData.pubKey.get(), rsaData.padding);

    std::vector<uint8_t> ciphertext;
    try {
        ciphertext = rsaPubCtx.encrypt(rsaData.data);
    } catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure encrypting data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (mococrw::MoCOCrWException &e) {
        std::cerr << "Failure in crypto engine: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (rsaData.chaining) {
        printChainingData(*rsaData.vm.get());
    } else {
        std::cout << "Ciphertext: ";
    }
    std::cout << utility::toHex(ciphertext) << std::endl;
}

void decrypt_rsa(const struct RsaData &rsaData) {
    std::vector<uint8_t> plaintext;
    try {
        RSAEncryptionPrivateKeyCtx rsaPrivCtx(*rsaData.privKey.get(), rsaData.padding);
        plaintext = rsaPrivCtx.decrypt(rsaData.data);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Error decrypting data." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    std::cout << utility::toHex(plaintext) << std::endl;
}
