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

EciesEncryptResult encrypt_data(const std::vector<uint8_t> &message,
                                const AsymmetricPublicKey &pubKey)
{
    /* The standard for ECIES (IEEE 1363a-2004) doesn't specify the details of the different cipher
     * blocks. Thus it is up to the implementer to define its own protocol (hash-function, key
     * derivation function, message authentication code, symmetric cipher, key serialization) used
     * for encryption and decryption. In the current example the following is used:
     * - SHA512 everywhere where a hash function is required
     * - X963(SHA512) as key derivation function
     * - HMAC(SHA512) as message authentication code
     * - AES CBC with PKCS padding, zero IV and 256 bit key size
     * - Additionally salts for KDF and MAC can be set (optional value, default: empty)
     *
     * The defaults if the builder is invoked without any optional parameters are:
     * - X963(SHA512) as key derivation function
     * - HMAC(SHA512)
     * - AES CBC with PKCS padding, zero IV and 256 bit key size
     * - empty salts for KDF and MAC
     */
    /* Get the encryption context */
    std::unique_ptr<ECIESEncryptionCtx> encCtx =
            ECIESCtxBuilder{} /* This is optional. The default is X963 with SHA512 */
                    .setKDF(std::make_shared<X963KDF>(DigestTypes::SHA512))
                    /* This is optional. The default is HMAC with SHA512
                     * Dependency injection function, as the key for MAC is generated based on a
                     * random ECC key in the ECIES class */
                    .setMacFactoryFunction([](const std::vector<uint8_t> &key)
                                                   -> std::unique_ptr<MessageAuthenticationCode> {
                        return std::make_unique<mococrw::HMAC>(DigestTypes::SHA512, key);
                    })
                    /* This is optional. The default key length is 512 / 8 bytes (length of hash
                       sum) */
                    .setMacKeySize(Hash::getDigestSize(DigestTypes::SHA512))
                    /* The next two lines are optional. Default: AES CBC with PKCS padding, zero IV
                       and 256 bit key size */
                    .setSymmetricCipherFactoryFunction(
                            [](const std::vector<uint8_t> &key)
                                    -> std::unique_ptr<SymmetricCipherI> {
                                return AESCipherBuilder(SymmetricCipherMode::CBC,
                                                        SymmetricCipherKeySize::S_256,
                                                        key)
                                        .setIV(std::vector<uint8_t>(
                                                AESCipherBuilder::getDefaultIVLength(
                                                        SymmetricCipherMode::CBC)))
                                        .setPadding(SymmetricCipherPadding::PKCS)
                                        .buildEncryptor();
                            })
                    .setSymmetricCipherKeySize(
                            getSymmetricCipherKeySize(SymmetricCipherKeySize::S_256))
                    .buildEncryptionCtx(pubKey);

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

void decrypt_data(const EciesEncryptResult &eciesData, const AsymmetricPrivateKey &privKey)
{
    /* We need
     * - mac value
     * - ephemeral key
     * - ciphertext
     * - private key
     */

    /* The standard for ECIES (IEEE 1363a-2004) doesn't specify the details of the different cipher
     * blocks. Thus it is up to the user to define its own set of cipher blocks (hash-function, key
     * derivation function, message authentication code, symmetric cipher) used for encryption and
     * decryption. In the current example the following is used:
     * - SHA512 everywhere where a hash function is required
     * - X963(SHA512) as key derivation function
     * - HMAC(SHA512) as message authentication code
     * - AES CBC with PKCS padding, zero IV and 256 bit key size
     * - Additionally salts for KDF and MAC can be set (optional value, default: empty)
     *
     * The defaults if the builder is invoked without any optional parameters are:
     * - X963(SHA512) as key derivation function
     * - HMAC(SHA512)
     * - AES CBC with PKCS padding, zero IV and 256 bit key size
     * - empty salts for KDF and MAC
     */

    std::shared_ptr<AsymmetricKey::Spec> spec = privKey.getKeySpec();
    auto eccSpec = std::dynamic_pointer_cast<ECCSpec>(spec);
    if (!eccSpec) {
        std::cerr << "Given key is no ECC key." << std::endl;
        exit(EXIT_FAILURE);
    }

    /* The underlying openssl function recognizes the used serialization format of the ephemeral key
     * reading the first byte of the serialized data, which defines the format.
     * The variable eccSpec contains the used elliptic curve of the ephemeral key */
    auto _ephemeralKey = AsymmetricPublicKey::fromECPoint(eccSpec, eciesData.ephemeralKey);

    /* Get the decryption context */
    auto decCtx =
            ECIESCtxBuilder{}  // This is optional. The default is X963 with SHA512
                    .setKDF(std::make_shared<X963KDF>(DigestTypes::SHA512))
                    // This is optional. The default is HMAC with SHA512
                    .setMacFactoryFunction([](const std::vector<uint8_t> &key)
                                                   -> std::unique_ptr<MessageAuthenticationCode> {
                        return std::make_unique<mococrw::HMAC>(DigestTypes::SHA512, key);
                    })
                    // This is optional. The default key length is 512 / 8 bytes (length of hash
                    // sum)
                    .setMacKeySize(Hash::getDigestSize(DigestTypes::SHA512))
                    // This is optional. Default: AES CBC with PKCS padding, zero IV and 256 bit key
                    // size
                    .setSymmetricCipherFactoryFunction(
                            [](const std::vector<uint8_t> &key)
                                    -> std::unique_ptr<SymmetricCipherI> {
                                return AESCipherBuilder(SymmetricCipherMode::CBC,
                                                        SymmetricCipherKeySize::S_256,
                                                        key)
                                        .setIV(std::vector<uint8_t>(
                                                AESCipherBuilder::getDefaultIVLength(
                                                        SymmetricCipherMode::CBC)))
                                        .setPadding(SymmetricCipherPadding::PKCS)
                                        .buildDecryptor();
                            })
                    .setSymmetricCipherKeySize(
                            getSymmetricCipherKeySize(SymmetricCipherKeySize::S_256))
                    .buildDecryptionCtx(privKey, _ephemeralKey);

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
    ECCSpec ecspec;
    auto eccPrivKey =
            AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, ecspec, keyLabelECC, keyIDECC);
    auto ecdsaSigFormat = ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;

    /* The argument hashFunction is optional. Default is SHA256
     * The default signature format is ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS */
    auto ECDSAsignature = ecdsaSign(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, message);

    /* Use-Case 1: You want to check your own signature.
     * We can use here the private key, as it also contains the public key.
     * In MoCOCrW the AsymmetricPrivateKey is a specialisation of AsymmetricPublicKey. Thus
     * we do an implicit upcast here.
     */
    ecdsaVerify(eccPrivKey, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);

    /* Use-Case 2: The public key used for verification is stored in the HSM */
    auto pubKeyEcc = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelECC, keyIDECC);
    ecdsaVerify(pubKeyEcc, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);

    /* Use-Case 3: You want to write the public key to a PEM file and use it later
     * for verification
     */
    auto pubKeyPem = eccPrivKey.publicKeyToPem();
    /* Write PEM data to a file and read it again */
    auto pubKeyEccFromPem = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pubKeyPem);
    ecdsaVerify(pubKeyEccFromPem, ecdsaDigestType, ecdsaSigFormat, ECDSAsignature, message);
    /*********************************************/

    /************** RSA key generation, loading and digital signatures **************/
    std::vector<uint8_t> keyIDRSA{0x12, 0x34};
    std::string keyLabelRSA{"rsa-key-label"};
    auto mgf1DigestType = DigestTypes::SHA256;
    mococrw::RSASpec rsaSpec;
    auto rsaSignatureDigestType = DigestTypes::SHA512;
    auto mgf1 = std::make_shared<MGF1>(mgf1DigestType);
    int saltLength = mococrw::Hash::getDigestSize(rsaSignatureDigestType);
    auto padding = std::make_shared<PSSPadding>(mgf1, saltLength);

    /**
     * Generate an RSA keypair and load the public part
     */
    auto rsaPrivKey =
            AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, rsaSpec, keyLabelRSA, keyIDRSA);
    auto pubKeyRsa = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelRSA, keyIDRSA);

    /**
     * Do signing/verification
     */
    auto RSAsignature = rsaSign(rsaPrivKey, rsaSignatureDigestType, padding, message);
    // We can use here the private key, as it also contains the public key.
    rsaVerify(rsaPrivKey, padding, rsaSignatureDigestType, RSAsignature, message);
    // ... or you can use the public key
    rsaVerify(pubKeyRsa, padding, rsaSignatureDigestType, RSAsignature, message);
    /**
     * See rsa-example.cpp or sig-example.cpp for further examples.
     */

    /**
     * Use the keys for ECIES scheme
     */
    auto eciesData = encrypt_data(message, pubKeyEcc);
    decrypt_data(eciesData, eccPrivKey);

    return 0;
}
