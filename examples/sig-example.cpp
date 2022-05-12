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
#include <mococrw/hash.h>
#include <iostream>

using namespace mococrw;

std::vector<uint8_t> rsaSign(const AsymmetricPrivateKey &privKey,
                             const DigestTypes digestType,
                             std::shared_ptr<RSASignaturePadding> padding,
                             const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageSignatureCtx> signCtx;

    try {
        /* Padding is optional. Default: PSSPadding with MGF1 as mask generation function.
         * DigestType is used as hash function for the padding schemes and for MGF1 (if used) */
        signCtx = std::make_shared<RSASignaturePrivateKeyCtx>(privKey, digestType, padding);
    } catch (const MoCOCrWException &e) {
        std::cerr << "Please check your RSA key. Failure creating context." << std::endl;
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
         */
        std::cerr << "Failure occurred during signing." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return signature;
}

void rsaVerify(const AsymmetricPublicKey &pubKey,
               std::shared_ptr<RSASignaturePadding> rsaPadding,
               DigestTypes digestType,
               const std::vector<uint8_t> &signature,
               const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    try {
        /* Padding is optional. Default: PSSPadding with MGF1 as mask generation function.
         * DigestType is used as hash function for the padding schemes and for MGF1 (if used) */
        verifyCtx = std::make_shared<RSASignaturePublicKeyCtx>(pubKey, digestType, rsaPadding);
    } catch (const MoCOCrWException &e) {
        std::cerr << "Please check your RSA key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    try {
        verifyCtx->verifyMessage(signature, message);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - error in openssl (sign, padding, ...)
         * - Hash function's digest size doesn't match the message's digest size
         * - Invalid signature
         */
        std::cerr << "Verification failed!" << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

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

std::vector<uint8_t> edDsaSign(const AsymmetricPrivateKey &privKey,
                               const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageSignatureCtx> signCtx;
    try {
        signCtx = std::make_shared<EdDSASignaturePrivateKeyCtx>(privKey);
    } catch (const MoCOCrWException &e) {
        std::cerr << "Please check your ECC-Ed key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> signature;
    try {
        signature = signCtx->signMessage(message);
    } catch (const MoCOCrWException &e) {
        /* Posible reason:
         * - error in openssl
         */
        std::cerr << "Failure occurred during signing." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return signature;
}

void edDsaVerify(const AsymmetricPublicKey &pubKey,
                 const std::vector<uint8_t> &signature,
                 const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    try {
        verifyCtx = std::make_shared<EdDSASignaturePublicKeyCtx>(pubKey);
    } catch (const MoCOCrWException &e) {
        std::cerr << "Please check your ECC-Ed key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    try {
        verifyCtx->verifyMessage(signature, message);
    } catch (const MoCOCrWException &e) {
        /* Posible reason:
         * - error in openssl
         * - Invalid signature
         */
        std::cerr << "Verification failed!" << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    std::vector<uint8_t> message = utility::fromHex("deadbeef");

    /************** RSA signature **************/
    auto rsaPrivKey = AsymmetricPrivateKey::generateRSA();
    /* If the default MGF function is used, the digest type for MGF and for PSS-Padding is the same
     */
    auto mgf1DigestType = DigestTypes::SHA256;
    auto rsaSignatureDigestType = DigestTypes::SHA512;
    auto mgf1 = std::make_shared<MGF1>(MGF1(mgf1DigestType));
    int saltLength = mococrw::Hash::getDigestSize(rsaSignatureDigestType);
    auto padding = std::make_shared<PSSPadding>(PSSPadding(mgf1, saltLength));

    /* Padding is optional. Default: PSSPadding with MGF1 as mask generation function
     * (both using the same digest type (e.g. SHA-256) */
    auto signature = rsaSign(rsaPrivKey, rsaSignatureDigestType, padding, message);

    /* we can use here the private key, as it also contains the public key.
     * In MoCOCrW the AsymmetricPrivateKey is a specialisation of AsymmetricPublicKey. Thus
     * we do an implicit upcast here.
     */
    rsaVerify(rsaPrivKey, padding, rsaSignatureDigestType, signature, message);
    /*******************************************/

    /************** ECDSA signature **************/
    auto ecdsaDigestType = DigestTypes::SHA512;
    auto eccPrivKey = AsymmetricPrivateKey::generateECC();
    auto ecdsaSigFormat = ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;

    /* The argument hashFunction is optional. Default is SHA256
     * The default signature format is ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS */
    signature = ecdsaSign(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, message);

    /* we can use here the private key, as it also contains the public key.
     * In MoCOCrW the AsymmetricPrivateKey is a specialisation of AsymmetricPublicKey. Thus
     * we do an implicit upcast here.
     */
    ecdsaVerify(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, signature, message);
    /*********************************************/

    /************** EdDSA signature **************/
    auto edPrivKey = AsymmetricPrivateKey::generateEd25519();

    signature = edDsaSign(edPrivKey, message);

    /* we can use here the private key, as it also contains the public key.
     * In MoCOCrW the AsymmetricPrivateKey is a specialisation of AsymmetricPublicKey. Thus
     * we do an implicit upcast here.
     */
    edDsaVerify(edPrivKey, signature, message);
    /*********************************************/
}
