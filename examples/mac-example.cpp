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
#include <mococrw/mac.h>
#include <mococrw/util.h>
#include <iostream>

using namespace mococrw;

void verify(DigestTypes digestType,
            const std::vector<uint8_t> &key,
            const std::vector<uint8_t> &message,
            const std::vector<uint8_t> &authenticationTag)
{
    try {
        auto hmac = std::make_unique<mococrw::HMAC>(digestType, key);
        hmac->update(message);
        hmac->verify(authenticationTag);
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - key for HMAC is empty
         * - finish is invoked twice
         * - HMAC values (calculated/provided) differ in length
         * - HMAC values (calculated/provided) differ in content
         * - update is invoked after finish or verify
         */
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    std::cout << "Verification successful." << std::endl;
}

void verify(CmacCipherTypes cipherType,
            const std::vector<uint8_t> &key,
            const std::vector<uint8_t> &message,
            const std::vector<uint8_t> &authenticationTag)
{
    try {
        auto cmac = std::make_unique<CMAC>(cipherType, key);
        cmac->update(message);
        cmac->verify(authenticationTag);
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - key for CMAC is empty or has wrong size
         * - finish is invoked twice
         * - CMAC values (calculated/provided) differ in length
         * - CMAC values (calculated/provided) differ in content
         * - update is invoked after finish or verify
         */
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    std::cout << "Verification successful." << std::endl;
}

std::vector<uint8_t> calculate(DigestTypes digestType,
                               const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &message)
{
    try {
        auto hmac = std::make_unique<mococrw::HMAC>(digestType, key);
        hmac->update(message);
        return hmac->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - key for HMAC is empty
         * - finish is invoked twice
         * - update is invoked after finish
         */
        std::cerr << "HMAC calculation failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
}

std::vector<uint8_t> calculate(CmacCipherTypes cipherType,
                               const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &message)
{
    try {
        auto cmac = std::make_unique<CMAC>(cipherType, key);
        cmac->update(message);
        return cmac->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - key for CMAC is empty or has wrong size
         * - finish is invoked twice
         * - update is invoked after finish
         */
        std::cerr << "CMAC initialisation or calculation failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    auto hmacTag = calculate(
            DigestTypes::SHA512, utility::fromHex("beefdead"), utility::fromHex("deadbeef"));
    verify(DigestTypes::SHA512,
           utility::fromHex("beefdead"),
           utility::fromHex("deadbeef"),
           hmacTag);

    auto cmacTag = calculate(CmacCipherTypes::AES_CBC_128,
                             utility::fromHex("beefdead12345678"
                                              "12345678deadbeef"),
                             utility::fromHex("deadbeef"));
    verify(CmacCipherTypes::AES_CBC_128,
           utility::fromHex("beefdead12345678"
                            "12345678deadbeef"),
           utility::fromHex("deadbeef"),
           cmacTag);

    return 0;
}
