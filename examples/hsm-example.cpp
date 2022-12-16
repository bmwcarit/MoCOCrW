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
#include <mococrw/hash.h>
#include <mococrw/hsm.h>
#include <mococrw/key.h>
#include <iostream>

/* This example demonstrates how to create a PKCS11 engine object,
 * and store a key inside the HSM.
 */

using namespace mococrw;

std::vector<uint8_t> ecdsaSign(const AsymmetricPrivateKey &privKey,
                               const DigestTypes digestType,
                               const ECDSASignatureFormat sigFormat,
                               const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageSignatureCtx> signCtx;
    try {
        /* The argument hashFunction is optional. Default is SHA256
         * The default signature format is ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS */
        signCtx = std::make_shared<ECDSASignaturePrivateKeyCtx>(privKey, digestType, sigFormat);
    } catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> signature;
    try {
        signature = signCtx->signMessage(message);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - error in openssl (sign, padding, ...)
         * - Hash function's digest size doesn't match the message's digest size
         * - Invalid signature format set
         */
        std::cerr << "Failure occurred during signing." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return signature;
}

void ecdsaVerify(const AsymmetricPublicKey &pubKey,
                 const DigestTypes digestType,
                 const ECDSASignatureFormat sigFormat,
                 const std::vector<uint8_t> &signature,
                 const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    try {
        verifyCtx = std::make_shared<ECDSASignaturePublicKeyCtx>(pubKey, digestType, sigFormat);
    } catch (const MoCOCrWException &e) {
        std::cerr << "Please check your ECC key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    try {
        verifyCtx->verifyMessage(signature, message);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - error in openssl (sign, padding, ...)
         * - Hash function's digest size doesn't match the message's digest size
         * - Invalid signature format set
         * - Signature can't be parsed
         * - Invalid signature
         */
        std::cerr << "Verification failed!" << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    // Information for engine loading and key management.
    std::string id("pkcs11");
    std::string modulePath("/usr/lib/softhsm/libsofthsm2.so");
    std::string pin("1234");
    std::vector<uint8_t> message = utility::fromHex("deadbeef");
    HsmEngine hsmEngine(id, modulePath, pin);


    /************** ECDSA signature **************/
    std::string keyIDEcc("5567");
    auto ecdsaDigestType = DigestTypes::SHA512;
    ECCSpec ecspec;
    auto eccPrivKey = AsymmetricPrivateKey::genKeyOnHsmGetPrivate(
            hsmEngine, ecspec, keyIDEcc, "token-label", "DobarKey");
    auto ecdsaSigFormat = ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;

    /* The argument hashFunction is optional. Default is SHA256
     * The default signature format is ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS */
    auto signature = ecdsaSign(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, message);

    /* Use-Case 1: You want to check your own signature:
     * we can use here the private key, as it also contains the public key.
     * In MoCOCrW the AsymmetricPrivateKey is a specialisation of AsymmetricPublicKey. Thus
     * we do an implicit upcast here.
     */
    ecdsaVerify(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, signature, message);

    /* Use-Case 2: The public key used for verification is stored in the HSM */
    auto pubKeyEcc = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyIDEcc);
    ecdsaVerify(pubKeyEcc, ecdsaDigestType, ecdsaSigFormat, signature, message);

    /* Use-Case 3: You want to write the public key to a PEM file and use it later
     * for verification
     */
    auto pubKeyPem = eccPrivKey.publicKeyToPem();
    /* Omitted: Write PEM data to a file and read it again */
    auto pubKeyEccFromPEm = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pubKeyPem);
    ecdsaVerify(pubKeyEccFromPEm, ecdsaDigestType, ecdsaSigFormat, signature, message);
    /*********************************************/

    /************** RSA key generation **************/
    std::string keyIDRsa("8890");
    mococrw::RSASpec rsaSpec;
    auto rsaPrivKey = AsymmetricPrivateKey::genKeyOnHsmGetPrivate(
            hsmEngine, rsaSpec, keyIDRsa, "token-label", "BarfoKey");

    /* Read public key from HSM */
    auto pubKeyRsa = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyIDRsa);

    /* Do whatever you want using the private and public key. See rsa-example.cpp or
     * sig-example.cpp for further examples.
     */
    /*********************************************/

    return 0;
}