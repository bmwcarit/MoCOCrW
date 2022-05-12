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

#include <mococrw/ecies.h>
#include <mococrw/hash.h>
#include <mococrw/openssl_wrap.h>
#include <mococrw/util.h>

#include <iostream>

using namespace mococrw;

struct EciesEncryptResult
{
    std::vector<uint8_t> ephemeralKey;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> mac;
};

EciesEncryptResult encrypt_data(const std::vector<uint8_t> &message)
{
    const std::string pubKeyPem = R"(
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELGj/fqXab+amxDOcbDWMArPBsUMOPons
9NePVyS9CbIkI8e3nPYi3ytHjJm03M22vM5R4XAxI9cMv5biylFJW0HBlyf/cZTO
xOVCTvRDUHLGTdGXNlz74YtWLF+CMX5A
-----END PUBLIC KEY-----
    )";

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
    /* Read the public key */
    auto pubKey = AsymmetricPublicKey::readPublicKeyFromPEM(pubKeyPem);

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

void decrypt_data(const EciesEncryptResult &eciesData)
{
    /* We need
     * - mac value
     * - ephemeral key
     * - ciphertext
     * - private key
     */

    const std::string privKeyPem = R"(
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDP/GdwmJa6KFj/R7QJRi7wNNG+viSMos2B+4zIi7fO5BUpIMZObh6/
ujDnPKFx4SugBwYFK4EEACKhZANiAAQsaP9+pdpv5qbEM5xsNYwCs8GxQw4+iez0
149XJL0JsiQjx7ec9iLfK0eMmbTczba8zlHhcDEj1wy/luLKUUlbQcGXJ/9xlM7E
5UJO9ENQcsZN0Zc2XPvhi1YsX4IxfkA=
-----END EC PRIVATE KEY-----
    )";

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

    /* Read the private key and thet the ECC specification of the private key.
     * The elliptic curve of the ephemeral key is the same as the private key's one as it is derived
     * from the corresponding public key. */
    auto privKey = AsymmetricPrivateKey::readPrivateKeyFromPEM(privKeyPem, "");
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

int main(void)
{
    std::vector<uint8_t> message = utility::fromHex("deadbeef");
    auto eciesData = encrypt_data(message);
    decrypt_data(eciesData);
    return 0;
}
