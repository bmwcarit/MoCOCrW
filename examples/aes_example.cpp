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

#include "aes_example.h"

AuthenticatedEncryptionI* setAuthenticatedCipherData(const AesData &aesData,
                                                     std::shared_ptr<SymmetricCipherI> cryptor)
{
    AuthenticatedEncryptionI *authenticatedEncryptor = nullptr;
    // NOTE: Usually you know type of the encryption in advance and hardly need
    // to cast. Here we do this to keep tests compact and improve on code reuse.
    authenticatedEncryptor = dynamic_cast<AuthenticatedEncryptionI*>(cryptor.get());
    if (aesData.authData) {
        authenticatedEncryptor->addAssociatedData(*aesData.authData);
    }

    return authenticatedEncryptor;
}

void aesEncrypt(const AesData &aesData)
{
    auto &plaintext = aesData.data;
    auto encryptorBuilder = AESCipherBuilder{aesData.operationMode, aesData.secretKey.size() == 32 ?
                SymmetricCipherKeySize::S_256 : SymmetricCipherKeySize::S_128, aesData.secretKey};
    encryptorBuilder.setPadding(aesData.padding);
    if (!aesData.iv.empty()) {
        encryptorBuilder.setIV(aesData.iv);
    }

    std::shared_ptr<SymmetricCipherI> encryptor;
    // This is a raw pointer, as it will only be a downcast of encryptor, which is already a smart pointer
    AuthenticatedEncryptionI *authenticatedEncryptor = nullptr;
    if (isAuthenticatedCipherMode(aesData.operationMode)) {
        if (aesData.authTagLength) {
            encryptorBuilder.setAuthTagLength(*aesData.authTagLength);
        }
        encryptor = encryptorBuilder.buildAuthenticatedEncryptor();
        authenticatedEncryptor = setAuthenticatedCipherData(aesData, encryptor);
    }
    else {
        encryptor = encryptorBuilder.buildEncryptor();
    }

    std::vector<uint8_t> ciphertext;
    try {
        encryptor->update(plaintext);
        ciphertext = encryptor->finish();
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (MoCOCrWException &e) {
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    auto iv = encryptor->getIV();

    std::vector<uint8_t> tag;

    // The rest of the function outpus the data

    if (aesData.chaining) {
        std::cout << "--operation-mode " << (*aesData.vm.get())["operation-mode"].as<std::string>() << " ";
        std::cout << "--iv " << utility::toHex(iv) << " ";
        std::cout << "--data " << utility::toHex(ciphertext) << " ";
        std::cout << "--padding " << (*aesData.vm.get())["padding"].as<std::string>() << " ";
        if (authenticatedEncryptor) {
            std::cout << "--auth-tag " << utility::toHex(authenticatedEncryptor->getAuthTag()) << " ";
            if (aesData.authTagLength) {
                std::cout << "--auth-tag-length " << (*aesData.vm.get())["auth-tag-length"].as<size_t>() << " ";
            }
            if (aesData.authData) {
                std::cout << "--auth-data " << (*aesData.vm.get())["auth-data"].as<std::string>();
            }
        }
        std::cout << std::endl;
        return;
    }

    std::cout << "Ciphertext: " << utility::toHex(ciphertext) << std::endl;
    std::cout << "IV: " << utility::toHex(iv) << std::endl;

    if (authenticatedEncryptor) {
        std::cout << "Authentication Tag: " << utility::toHex(authenticatedEncryptor->getAuthTag()) << std::endl;
    }
}

void aesDecrypt(const AesData &aesData)
{
    auto &ciphertext = aesData.data;
    auto decryptorBuilder = AESCipherBuilder{aesData.operationMode, aesData.secretKey.size() == 32 ?
                SymmetricCipherKeySize::S_256 : SymmetricCipherKeySize::S_128, aesData.secretKey}.setIV(aesData.iv);
    decryptorBuilder.setPadding(aesData.padding);

    std::shared_ptr<SymmetricCipherI> decryptor;
    if (isAuthenticatedCipherMode(aesData.operationMode)) {
        decryptor = decryptorBuilder.buildAuthenticatedDecryptor();
        setAuthenticatedCipherData(aesData, decryptor)->setAuthTag(*aesData.authTag);
    } else {
        decryptor = decryptorBuilder.buildDecryptor();
    }

    decryptor->update(ciphertext);
    try {
        std::cout << utility::toHex(decryptor->finish()) << std::endl;
    }  catch (MoCOCrWException &e) {
        std::cout << "Decryption failed!" << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}
