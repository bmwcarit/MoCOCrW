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

#include <mococrw/symmetric_crypto.h>
#include <iostream>

using namespace mococrw;

static const std::vector<uint8_t> plaintext = utility::fromHex("deadbeef");
static const std::vector<uint8_t> expectedCiphertext = utility::fromHex("c0bdb9ef");
static const SymmetricCipherMode aeOperationMode = SymmetricCipherMode::GCM;
static const SymmetricCipherMode plainOperationMode = SymmetricCipherMode::CBC;
static const SymmetricCipherPadding padding = SymmetricCipherPadding::PKCS;
static const std::vector<uint8_t> aesKey = utility::fromHex("000102030405060708090a0b0c0d0e0f");
static const std::vector<uint8_t> associatedData = utility::fromHex("beefdead");
static const std::vector<uint8_t> iv = utility::fromHex("00102030405060708090a0b0c0d0e0f0");
static const size_t authTagLength = 16;

struct AesAuthenticatedEncryptionResult
{
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> authTag;
};

struct AesEncryptionResult
{
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
};

AesAuthenticatedEncryptionResult aesAuthenticatedEncryption()
{
    auto authenticatedEncryptor =
            AESCipherBuilder{aeOperationMode, SymmetricCipherKeySize::S_128, aesKey}
                    // Padding mode is optional. Default is SymmetricCipherPadding::PKCS
                    .setPadding(padding)
                    // The IV is optional. Default is a random value (Recommendation: use a random
                    // value)
                    .setIV(iv)
                    // the authTagLength is an optional value. Default 16 bytes. Only needed by AES
                    // AEAD.
                    .setAuthTagLength(authTagLength)
                    .buildAuthenticatedEncryptor();

    std::vector<uint8_t> ciphertext;
    try {
        authenticatedEncryptor->addAssociatedData(associatedData);
        authenticatedEncryptor->update(plaintext);
        ciphertext = authenticatedEncryptor->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* Low level OpenSSL failure */
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - update was invoked after finish()
         * - the message is too big
         * - finish was invoked twice
         * - associated data was set after invoking update() or finish()
         */
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return AesAuthenticatedEncryptionResult{
            authenticatedEncryptor->getIV(), ciphertext, authenticatedEncryptor->getAuthTag()};
}

std::vector<uint8_t> aesAuthenticatedDecryption(
        const AesAuthenticatedEncryptionResult &aesEncryptResult)
{
    auto authenticatedDecryptor =
            AESCipherBuilder{aeOperationMode, SymmetricCipherKeySize::S_128, aesKey}
                    // Optional. Defaults to SymmetricCipherPadding::PKCS
                    .setPadding(padding)
                    // mandatory value for decryption. Don't forget to set it. Set the same value as
                    // set during encryption
                    .setIV(aesEncryptResult.iv)
                    // the authTagLength is an optional value. Default 16 bytes. Only needed by AEAD
                    // modes of operation.
                    .setAuthTagLength(authTagLength)
                    .buildAuthenticatedEncryptor();

    std::vector<uint8_t> plaintext;
    try {
        authenticatedDecryptor->addAssociatedData(associatedData);
        authenticatedDecryptor->update(aesEncryptResult.ciphertext);
        authenticatedDecryptor->setAuthTag(aesEncryptResult.authTag);
        plaintext = authenticatedDecryptor->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* Low level OpenSSL failure */
        std::cerr << "Failure decrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - update was invoked after finish()
         * - the message is too big
         * - finish was invoked twice
         * - authentication tag verification failed
         * - authentication tag wasn't set before invoking finish()
         * - associated data was set after invoking update() or finish()
         */
        std::cout << "Decryption or auth tag verification failed!" << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return plaintext;
}

AesEncryptionResult aesEncryption()
{
    auto encryptor = AESCipherBuilder{plainOperationMode, SymmetricCipherKeySize::S_128, aesKey}
                             // Padding mode is optional. Default is SymmetricCipherPadding::PKCS
                             .setPadding(padding)
                             // The IV is optional. Default is a random value (Recommendation: use a
                             // random value)
                             .setIV(iv)
                             .buildEncryptor();

    std::vector<uint8_t> ciphertext;
    try {
        encryptor->update(plaintext);
        ciphertext = encryptor->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* Low level OpenSSL failure */
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - update was invoked after finish()
         * - the message is too big
         * - finish was invoked twice */
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return AesEncryptionResult{encryptor->getIV(), ciphertext};
}

std::vector<uint8_t> aesDecryption(const AesEncryptionResult &aesEncryptResult)
{
    auto decryptor = AESCipherBuilder{plainOperationMode, SymmetricCipherKeySize::S_128, aesKey}
                             // Padding mode is optional. Default is SymmetricCipherPadding::PKCS
                             .setPadding(padding)
                             // mandatory value for decryption. Don't forget to set it. Set the same
                             // value as set during encryption
                             .setIV(aesEncryptResult.iv)
                             .buildDecryptor();

    std::vector<uint8_t> plaintext;
    try {
        decryptor->update(aesEncryptResult.ciphertext);
        plaintext = decryptor->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* Low level OpenSSL failure */
        std::cerr << "Failure encrypting the data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - update was invoked after finish()
         * - the message is too big
         * - finish was invoked twice */
        std::cout << "Decryption failed!" << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return plaintext;
}

int main(void)
{
    /* Authenticated encryption and decryption */
    auto aeResult = aesAuthenticatedEncryption();
    if (expectedCiphertext != aeResult.ciphertext) {
        std::cerr << "Something is wrong with AEAD encryption." << std::endl;
        return -1;
    }
    auto decryptionResult = aesAuthenticatedDecryption(aeResult);
    if (plaintext != decryptionResult) {
        std::cerr << "Failure decrypting AEAD data." << std::endl;
        return -1;
    }

    /* symmetric encryption and decryption */
    auto result = aesEncryption();
    decryptionResult = aesDecryption(result);
    if (plaintext != decryptionResult) {
        std::cerr << "Failure decrypting data." << std::endl;
        return -1;
    }

    std::cout << "En- and decryption using AES was successful" << std::endl;
    return 0;
}
