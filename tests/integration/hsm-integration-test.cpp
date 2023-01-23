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
        std::cerr << "Error encrypting data." << std::endl;
        std::cerr << e.what() << std::endl;
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
        std::cerr << "Error encrypting data." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> ephemeralKey;
    try {
        ephemeralKey = encCtx->getEphemeralKey().toECPoint(
                openssl::EllipticCurvePointConversionForm::uncompressed);
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Failure transforming EC key." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Possible reasons:
         * - Key object doesn't contain an EC key
         */
        std::cerr << "Failure transforming EC key." << std::endl;
        std::cerr << e.what() << std::endl;
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
        std::cerr << "Given key is not an ECC key." << std::endl;
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
        std::cerr << "Failure decrypting data." << std::endl;
        std::cerr << e.what() << std::endl;
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
        std::cerr << "Error decrypting integrated encryption scheme." << std::endl;
        std::cerr << e.what();
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
               DigestTypes digestType,
               const std::vector<uint8_t> &signature,
               const std::vector<uint8_t> &message)
{
    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    try {
        verifyCtx = std::make_shared<RSASignaturePublicKeyCtx>(pubKey, digestType);
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
    std::string tokenLabel("token-label");
    // Don't hardcode the pin in your application, this is just for demonstration purposes
    std::string pin("1234");
    HsmEngine hsmEngine(id, modulePath, tokenLabel, pin);
    std::vector<uint8_t> message = utility::fromHex("deadbeef");

    /************** ECC key generation and ECDSA **************/
    std::vector<uint8_t> keyIDECC{};
    std::string keyLabelECC("ecc-key-label");
    auto ecdsaDigestType = DigestTypes::SHA512;
    auto ecdsaSigFormat = ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;
    ECCSpec ecspec;

    std::cerr << "1. Testing digital signatures using ECC keys on HSM:\n";
    std::cerr << "Generating ECC keys on HSM...";
    auto eccPrivKey =
            AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, ecspec, keyLabelECC, keyIDECC);
    std::cerr << "Success\n";

    /**
     * Signing is expected to be executed inside softhsm using a PKCS11 function C_Sign.
     * This is expected to be the case whenever key is loaded from HSM, which is the case
     * when generateKeyOnHSM() is called
     */
    std::cerr << "Signing a message using an ECC private key generated on HSM...";
    auto ECDSAsignature = ecdsaSign(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, message);
    std::cerr << "Success\n";

    // AsymmetricPrivateKey also contains the public key.
    std::cerr << "Verifying the message with the corresponding public key...";
    ecdsaVerify(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
    std::cerr << "Success\n";

    std::cerr << "Explicitly loading a public key from HSM and trying to verify a signature...";
    auto pubKeyEcc = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelECC, keyIDECC);
    ecdsaVerify(pubKeyEcc, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
    std::cerr << "Success\n";

    std::cerr << "Transforming a public key from HSM to a PKCS8 format that can be written to a "
                 "PEM file...";
    auto pubKeyPem = eccPrivKey.publicKeyToPem();
    std::cerr << "Success\n";

    std::cerr << "Constructing a public key from PKCS8 format...";
    auto pubKeyEccFromPem = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pubKeyPem);
    std::cerr << "Success\n";

    /**
     * Since this key object is contructed from PEM string, this verification is executed
     * in software.
     */
    std::cerr << "Doing the verification with public key from PKCS8 format (this verification is "
                 "done in software)...";
    ecdsaVerify(pubKeyEccFromPem, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
    std::cerr << "Success\n\n";

    /************** RSA key generation, loading and digital signatures **************/
    std::vector<uint8_t> keyIDRSA{0x12, 0x34};
    std::string keyLabelRSA{"rsa-key-label"};
    mococrw::RSASpec rsaSpec;
    auto rsaSignatureDigestType = DigestTypes::SHA512;

    /**
     * Generate an RSA keypair and load the public part
     */
    std::cerr << "2. Testing digital signatures using RSA keys on HSM:\n";
    std::cerr << "Generating ECC keys on HSM...";
    auto rsaPrivKey =
            AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, rsaSpec, keyLabelRSA, keyIDRSA);
    std::cerr << "Success\n";

    std::cerr << "Explicitly loading a public key from HSM and trying to verify a signature...";
    auto pubKeyRsa = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelRSA, keyIDRSA);
    std::cerr << "Success\n";

    /**
     * Do signing/verification
     */
    std::cerr << "Signing a message using an RSA private key generated on HSM...";
    auto RSAsignature = rsaSign(rsaPrivKey, rsaSignatureDigestType, message);
    std::cerr << "Success\n";
    // We can use here the private key, as it also contains the public key.
    std::cerr << "Verifying the message with the corresponding public key...";
    rsaVerify(rsaPrivKey, rsaSignatureDigestType, RSAsignature, message);
    std::cerr << "Success\n\n";

    /************** ECIES scheme **************/
    std::cerr << "3. Testing ECIES scheme using ECC keys on HSM:\n";
    std::cerr << "Encrypting the message...";
    auto eciesData = encryptData(message, pubKeyEcc);
    std::cerr << "Success\n";

    std::cerr << "Decrypting the message...";
    decryptData(eciesData, eccPrivKey);
    std::cerr << "Success\n\n";

    return 0;
}
