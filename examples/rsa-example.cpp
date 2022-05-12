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
#include <mococrw/asymmetric_crypto_ctx.h>
#include <mococrw/padding_mode.h>
#include <iostream>

using namespace mococrw;

std::vector<uint8_t> encrypt_rsa(const AsymmetricPublicKey &pubKey,
                                 const std::shared_ptr<RSAEncryptionPadding> &padding,
                                 const std::vector<uint8_t> &data)
{
    RSAEncryptionPublicKeyCtx rsaPubCtx(pubKey, padding);

    std::vector<uint8_t> ciphertext;
    try {
        ciphertext = rsaPubCtx.encrypt(data);
    } catch (const mococrw::MoCOCrWException &e) {
        /* Possible reasons:
         * - Error in openssl
         * - Message size is not suited for encryption
         * - Message to big
         * - Encryption context is not set
         */
        std::cerr << "Failure in crypto engine: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return ciphertext;
}

std::vector<uint8_t> decrypt_rsa(const AsymmetricPrivateKey &privKey,
                                 const std::shared_ptr<RSAEncryptionPadding> &padding,
                                 const std::vector<uint8_t> &ciphertext)
{
    std::vector<uint8_t> plaintext;
    /* Padding is optional. Default is OAEP with SHA256 and MGF1(SHA256) as mask generation function
     */
    RSAEncryptionPrivateKeyCtx rsaPrivCtx(privKey, padding);
    try {
        plaintext = rsaPrivCtx.decrypt(ciphertext);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - Error in openssl (padding, decryption, ...)
         */
        std::cerr << "Error decrypting data." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    return plaintext;
}

int main(void)
{
    auto keyPair = AsymmetricKeypair::generateRSA();
    std::vector<uint8_t> data = utility::fromHex("deadbeef");
    DigestTypes oaepDigestType = DigestTypes::SHA512;
    std::string oaepLabel = "this is my awesome label";

    // you can use a different hash function for MGF1 than for OAEP padding if you want/need to
    // beware that this is really uncommon
    auto maskGenerationFunction = std::make_shared<MGF1>(MGF1(DigestTypes::SHA3_256));

    /* no argument to OAEPPadding is mandatory:
     * - default hashFunction = SHA256
     * - default maskGenerationFunction = MGF1 with with the hash function specified in parameter
     * hashFunction
     * - default label = "" (empty string)
     */
    auto padding = std::make_shared<OAEPPadding>(
            OAEPPadding(oaepDigestType, maskGenerationFunction, oaepLabel));
    auto ciphertext = encrypt_rsa(keyPair, padding, data);
    auto plaintext = decrypt_rsa(keyPair, padding, ciphertext);

    if (data == plaintext) {
        return 0;
    }

    return 1;
}
