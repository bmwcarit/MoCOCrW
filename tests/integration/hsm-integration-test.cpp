/*
 * #%L
 * %%
 * Copyright (C) 2023 BMW Car IT GmbH
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
#include <mococrw/ecies.h>
#include <mococrw/hash.h>
#include <mococrw/hsm.h>
#include <mococrw/key.h>
#include <iostream>

using namespace mococrw;

/**
 * Helper functions taken from ecies-examples.cpp
 */
struct EciesEncryptResult
{
    std::vector<uint8_t> ephemeralKey;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> mac;
};

EciesEncryptResult encryptData(const std::vector<uint8_t> &message,
                               const AsymmetricPublicKey &pubKey)
{
    std::unique_ptr<ECIESEncryptionCtx> encCtx = ECIESCtxBuilder{}.buildEncryptionCtx(pubKey);

    std::vector<uint8_t> encryptedData;
    try {
        encCtx->update(message);
        encryptedData = encCtx->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cout << "Error encrypting data." << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - symmetric cipher is not initalized
         * - update is invoked after finish
         * - symmetric cipher's finish() is already invoked
         * - symmetric cipher's update() is invoked after its finish()
         * - Message is too big
         * - finish is invoked twice
         * - MAC's finish() is already invoked
         * - MAC's update() is invoked after MAC's finish()
         */
        std::cout << "Error encrypting data." << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> ephemeralKey;
    try {
        ephemeralKey = encCtx->getEphemeralKey().toECPoint(
                openssl::EllipticCurvePointConversionForm::uncompressed);
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cout << "Failure transforming EC key." << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - Key object doesn't contain an EC key
         */
        std::cout << "Failure transforming EC key." << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return EciesEncryptResult{
            /* The serialization of the ephemeral key's public component is up to the implementer.
             * The standard is not defining a format. Available formats in MoCOCrW are:
             * - uncompressed (used here)
             * - compressed
             * - hybrid
             */
            ephemeralKey,
            encryptedData,
            encCtx->getMAC(),
    };
}

void decryptData(const EciesEncryptResult &eciesData, const AsymmetricPrivateKey &privKey)
{
    std::shared_ptr<AsymmetricKey::Spec> spec = privKey.getKeySpec();
    auto eccSpec = std::dynamic_pointer_cast<ECCSpec>(spec);
    if (!eccSpec) {
        std::cout << "Given key is not an ECC key." << std::endl;
        exit(EXIT_FAILURE);
    }

    auto _ephemeralKey = AsymmetricPublicKey::fromECPoint(eccSpec, eciesData.ephemeralKey);

    auto decCtx = ECIESCtxBuilder{}.buildDecryptionCtx(privKey, _ephemeralKey);

    /* Decrypt the data and verify the MAC */
    std::vector<uint8_t> decryptedData;
    try {
        /* Decrypt the ciphertext */
        decCtx->update(eciesData.ciphertext);

        /* Set the received mac value */
        decCtx->setMAC(eciesData.mac);

        /* Get the plaintext and verify the MAC */
        decryptedData = decCtx->finish();
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cout << "Failure decrypting data." << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - symmetric cipher is not initalized
         * - update is invoked after finish
         * - symmetric cipher's finish() is already invoked
         * - symmetric cipher's update() is invoked after its finish()
         * - Message is too big
         * - finish is invoked twice
         * - MAC's finish() is already invoked
         * - MAC's update() is invoked after MAC's finish()
         * - MAC is not set before invoking finish()
         * - MAC verification failed
         */
        std::cout << "Error decrypting integrated encryption scheme." << std::endl;
        std::cout << e.what();
        exit(EXIT_FAILURE);
    }
}

/**
 * Helper function taken from sig-example.cpp
 */

std::vector<uint8_t> rsaSign(const AsymmetricPrivateKey &privKey,
                             const DigestTypes digestType,
                             const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageSignatureCtx> signCtx;

    try {
        signCtx = std::make_shared<RSASignaturePrivateKeyCtx>(privKey, digestType);
    } catch (const MoCOCrWException &e) {
        std::cout << "Please check your RSA key. Failure creating context." << std::endl;
        std::cout << e.what();
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
        std::cout << "Failure occurred during signing." << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return signature;
}

void rsaVerify(const AsymmetricPublicKey &pubKey,
               DigestTypes digestType,
               const std::vector<uint8_t> &signature,
               const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    try {
        verifyCtx = std::make_shared<RSASignaturePublicKeyCtx>(pubKey, digestType);
    } catch (const MoCOCrWException &e) {
        std::cout << "Please check your RSA key. Failure creating context." << std::endl;
        std::cout << e.what();
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
        std::cout << "Verification failed!" << std::endl;
        std::cout << e.what() << std::endl;
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
        signCtx = std::make_shared<ECDSASignaturePrivateKeyCtx>(privKey, digestType, sigFormat);
    } catch (MoCOCrWException &e) {
        std::cout << "Please check your ECC key. Failure creating context." << std::endl;
        std::cout << e.what();
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
        std::cout << "Failure occurred during signing." << std::endl;
        std::cout << e.what() << std::endl;
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
        std::cout << "Please check your ECC key. Failure creating context." << std::endl;
        std::cout << e.what();
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
        std::cout << "Verification failed!" << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    // Information for engine loading and key management.
    std::string id("pkcs11");
    std::string modulePath("/usr/lib/softhsm/libsofthsm2.so");
    std::string tokenLabel("token-label");
    // Don't hardcode the pin in your application, this is just for demonstration purposes
    std::string pin("1234");
    HsmEngine hsmEngine(id, modulePath, tokenLabel, pin);
    // Test that this doesn't invalidate Pin from hsmEngine
    HsmEngine hsmEngine2(id, modulePath, tokenLabel, "0000000");
    utility::stringCleanse(pin);
    std::vector<uint8_t> message = utility::fromHex("deadbeef");
    // Default specs are used in numerous places
    ECCSpec eccSpec;
    RSASpec rsaSpec;

    // Put everything in a try-catch block to avoid doing it for every function
    // call
    try {
        /************** Key generation and loading **************/
        std::cout << "0. Testing key generation and loading:" << std::endl;

        std::vector<uint8_t> emptyKeyId{};
        std::string keyLabel_1{"key-label-1"};
        std::cout << "Try to generate a key without specifying the key ID...";
        try {
            auto keypair = AsymmetricPrivateKey::generateKeyOnHSM(
                    hsmEngine, eccSpec, keyLabel_1, emptyKeyId);
            exit(1);
        } catch (const MoCOCrWException &e) {
            std::cout << std::string(e.what()) + "...";
        }
        std::cout << "Success" << std::endl;

        std::cout << "Try to load a key without specifying the key ID...";
        try {
            auto keypair =
                    AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmEngine, keyLabel_1, emptyKeyId);
            exit(1);
        } catch (const MoCOCrWException &e) {
            std::cout << std::string(e.what()) + "...";
        }
        std::cout << "Success" << std::endl;

        std::string emptyLabel{};
        std::vector<uint8_t> keyId_1{0x11};
        std::cout << "Generate a key without specifying the label...";
        AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, eccSpec, emptyLabel, keyId_1);
        std::cout << "Success" << std::endl;

        std::vector<uint8_t> keyId_2{0x12};
        std::cout << "Generate another key without specifying the label...";
        AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, eccSpec, emptyLabel, keyId_2);
        std::cout << "Success" << std::endl;

        std::cout << "Load them both and test that different keys have been loaded...";
        if (AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmEngine, keyId_1) ==
            AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmEngine, keyId_2)) {
            std::cout << "Generated keys with different IDs and empty labels should not be the same"
                      << std::endl;
            exit(1);
        }
        std::cout << "Success" << std::endl;

        std::cout << "Try to generate a key with the same ID as in previous steps...";
        try {
            AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, eccSpec, keyLabel_1, keyId_1);
            exit(1);
        } catch (const MoCOCrWException &e) {
            std::cout << std::string(e.what()) + "...";
        }
        std::cout << "Success" << std::endl;

        std::vector<uint8_t> keyId_3{0x13};
        std::string keyLabel_2{"key-label-2"};
        std::cout << "Generate another key with some label and unique ID...";
        AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, eccSpec, keyLabel_2, keyId_3);
        std::cout << "Success" << std::endl;

        std::vector<uint8_t> keyId_4{0x14};
        std::cout << "Generate another key with the same label and unique ID...";
        AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, eccSpec, keyLabel_2, keyId_4);
        std::cout << "Success" << std::endl;

        std::cout << "Load them both and test that different keys have been loaded...";
        if (AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmEngine, keyLabel_2, keyId_3) ==
            AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmEngine, keyLabel_2, keyId_4)) {
            std::cout << "Generated keys with different IDs and same labels should not be the same"
                      << std::endl;
            exit(1);
        }
        std::cout << "Success\n" << std::endl;

        /************** ECC key generation and ECDSA **************/
        std::vector<uint8_t> keyIDECC{0x21};
        std::string keyLabelECC("ecc-key-label");
        auto ecdsaDigestType = DigestTypes::SHA512;
        auto ecdsaSigFormat = ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;

        std::cout << "1. Testing digital signatures using ECC keys on HSM:" << std::endl;
        std::cout << "Generating ECC keys on HSM...";
        AsymmetricKeypair eccPrivKey =
                AsymmetricKeypair::generateKeyOnHSM(hsmEngine, eccSpec, keyLabelECC, keyIDECC);
        std::cout << "Success" << std::endl;
        /**
         * Signing is expected to be executed inside softhsm using a PKCS11 function C_Sign.
         * This is expected to be the case whenever key is loaded from HSM, which is the case
         * when generateKeyOnHSM() is called
         */
        std::cout << "Signing a message using an ECC private key generated on HSM...";
        auto ECDSAsignature = ecdsaSign(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, message);
        std::cout << "Success" << std::endl;

        // AsymmetricPrivateKey also contains the public key.
        std::cout << "Verifying the message with the corresponding public key...";
        ecdsaVerify(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
        std::cout << "Success" << std::endl;

        std::cout << "Explicitly loading a public key from HSM and trying to verify a signature...";
        auto pubKeyEcc =
                AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelECC, keyIDECC);
        ecdsaVerify(pubKeyEcc, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
        std::cout << "Success" << std::endl;

        std::cout
                << "Transforming a public key from HSM to a PKCS8 format that can be written to a "
                   "PEM file...";
        auto pubKeyPem = eccPrivKey.publicKeyToPem();
        std::cout << "Success" << std::endl;

        std::cout << "Constructing a public key from PKCS8 format...";
        auto pubKeyEccFromPem = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pubKeyPem);
        std::cout << "Success" << std::endl;

        /**
         * Since this key object is contructed from PEM string, this verification is executed
         * in software.
         */
        std::cout
                << "Doing the verification with public key from PKCS8 format (this verification is "
                   "done in software)...";
        ecdsaVerify(pubKeyEccFromPem, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
        std::cout << "Success\n" << std::endl;

        /************** RSA key generation, loading and digital signatures **************/
        std::vector<uint8_t> keyIDRSA{0x31};
        std::string keyLabelRSA{"rsa-key-label"};
        auto rsaSignatureDigestType = DigestTypes::SHA512;

        /**
         * Generate an RSA keypair and load the public part
         */
        std::cout << "2. Testing digital signatures using RSA keys on HSM:" << std::endl;
        std::cout << "Generating ECC keys on HSM...";
        auto rsaPrivKey =
                AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, rsaSpec, keyLabelRSA, keyIDRSA);
        std::cout << "Success" << std::endl;

        std::cout << "Explicitly loading a public key from HSM and trying to verify a signature...";
        auto pubKeyRsa =
                AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelRSA, keyIDRSA);
        std::cout << "Success" << std::endl;

        /**
         * Do signing/verification
         */
        std::cout << "Signing a message using an RSA private key generated on HSM...";
        auto RSAsignature = rsaSign(rsaPrivKey, rsaSignatureDigestType, message);
        std::cout << "Success" << std::endl;
        // We can use here the private key, as it also contains the public key.
        std::cout << "Verifying the message with the corresponding public key...";
        rsaVerify(rsaPrivKey, rsaSignatureDigestType, RSAsignature, message);
        std::cout << "Success\n" << std::endl;

        /************** ECIES scheme **************/
        std::cout << "3. Testing ECIES scheme using ECC keys on HSM:" << std::endl;
        std::cout << "Encrypting the message...";
        auto eciesData = encryptData(message, pubKeyEcc);
        std::cout << "Success" << std::endl;

        std::cout << "Decrypting the message...";
        decryptData(eciesData, eccPrivKey);
        std::cout << "Success\n" << std::endl;

        /**
         * Generate extractable and non-extractable keys for ECC and RSA
         */
        HsmKeyParams hsmKeyParamsExtract = {/*.CKA_EXTRACTABLE =*/true,
                                            /* .CKA_SENSITIVE = */ false};
        HsmKeyParams hsmKeyParamsDefault;

        /* We need a new token otherwise the keys generated before litter the slot */

        std::string tokenLabel2("token-label2");
        // Don't hardcode the pin in your application, this is just for demonstration purposes
        std::string pin("1234");
        HsmEngine hsmEngine2(id, modulePath, tokenLabel2, pin);
        utility::stringCleanse(pin);

        // ECC
        std::vector<uint8_t> keyIdEcExtract{0x41};
        std::vector<uint8_t> keyIdEcDefault{0x42};
        std::string keyLabel_ecc_att{};
        auto keypairecc = AsymmetricPrivateKey::generateKeyOnHSM(
                hsmEngine2, ECCSpec(), "key-ecc-extractable", keyIdEcExtract, hsmKeyParamsExtract);
        keypairecc = AsymmetricPrivateKey::generateKeyOnHSM(
                hsmEngine2, ECCSpec(), "key-ecc-default", keyIdEcDefault, hsmKeyParamsDefault);

        // RSA
        std::vector<uint8_t> keyIdRsaExtract{0x43};
        std::vector<uint8_t> keyIdRsaDefault{0x44};
        std::string keyLabel_rsa_att{};
        auto keypairrsa = AsymmetricPrivateKey::generateKeyOnHSM(
                hsmEngine2, RSASpec(), "key-rsa-extractable", keyIdRsaExtract, hsmKeyParamsExtract);
        keypairrsa = AsymmetricPrivateKey::generateKeyOnHSM(
                hsmEngine2, RSASpec(), "key-rsa-default", keyIdRsaDefault, hsmKeyParamsDefault);

    } catch (const MoCOCrWException &e) {
        std::cout << "Integration test failed with MoCOCrWException: " << e.what() << std::endl;
        exit(1);
    } catch (const openssl::OpenSSLException &e) {
        std::cout << "Integration test failed with OpenSSLException: " << e.what() << std::endl;
        exit(1);
    } catch (...) {
        std::cout << "Integration test failed with unknown exception" << std::endl;
        exit(1);
    }
    return 0;
}
