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
#pragma once
#include "symmetric_crypto.h"
#include "mac.h"
#include "kdf.h"
#include "asymmetric_crypto_ctx.h"

namespace mococrw {

class ECIESCtxBuilder;

/**
 * @brief This class supports encryption of plain texts using ECIES (as described in IEEE 1363a-2004)
 *
 * This class supports encryption of plain texts using ECIES (as described in IEEE 1363a-2004) with the following
 * limitations.
 * Supported:
 * - ECSVDP-DH -> Elliptic Curve secret value derivation primitive - Diffie Helman
 * - ECSVDP-DHC (with the limitation for curves having a cofactor h == 1)
 * https://crypto.stackexchange.com/questions/18222/difference-between-ecdh-with-cofactor-key-and-ecdh-without-cofactor-key
 *
 * NOT Supported:
 * - DLIES (Discrete Logarithm Integrated Encryption Scheme) as this is not ECIES
 *
 * Elliptic curve integrated encryption scheme provides you the functionality to encrypt a plaintext with a one time
 * shared secret (based on an ephemeral key) using a symmetric encryption scheme. All you have to know is:
 * - The public EC key of the recipient (P_recipient)
 * - The agreed cipher (values in brackets are defaults if not changed/set):
 *   - EC group/curve (e.g. secp384r1)
 *   - symmetric cipher (e.g. AES-CBC, no padding, IV=0x00)
 *   - key derivation function (KDF) (e.g. X9.63)
 *   - message authentication code (MAC) (e.g. HMAC-SHA512)
 *   - optional salts for MAC and KDF
 *
 * The algorithm for ECIES encryption is as follows
 * 1. generate a random private public EC key pair (the public key is the mulitplication of the private key with a
 * generator: P_eph = r_eph * G)
 * 2. calculate the shared secret (P_shared = r_eph * P_recipient)
 * 3. generate the key for symmetric encryption and MAC (key_sym || key_mac = KDF(P_shared)) (using the optional salt)
 * 4. encrypt the plaintext
 * 5. calculate the MAC over the ciphertext (with the optional salt concatenated to the ciphertext)
 *
 * Send P_eph, ciphertext and MAC to the recipient. This is left to the caller. This class doesn't do any serialization
 * as there is no agreed standard yet.
 *
 * For using the ECIESEncryptionCtx a builder class is provided which takes the parameter described above as input.
 * Afterwards the ECIESEncryptionCtx can be used like a symmetric cipher. This means that you can call update for adding
 * plaintext bytes to the cipertext and finish() for calculating the MAC.
 *
 * The MAC and the ephemeral key can be obtained via getter functions.
 *
 * Workflow for Encryption:
 * 1. Get the necessary data (public key, MAC scheme, KDF scheme, symmetric cipher scheme, optional salts)
 * 2. Construct an ECIESEncryptionCtx using the ECIESEncryptionCtxBuilder providing providing the data from 1.
 * 3. Encrypt your plaintext using update()
 * 4. Finish the encryption and calculate the MAC using finish()
 * 5. Get the ephemeral key and the MAC
 * 6. Store the ephemeral key, the ciphertext and the MAC in a format of your purpose
 * 7. Transmit the data to the receiver
 *
 */
class ECIESEncryptionCtx {
public:
    /**
     * @brief Destructor
     */
    ~ECIESEncryptionCtx();

    /**
     * Encrypt a chunk of data.
     *
     * This function encrypts the data chunk.
     * The authentication tag is calculated over the ciphertext when finish() is invoked.
     *
     * @param message chunk of data to encrypt.
     * @throws MoCOCrWException if this function is invoked after finish was called.
     */
    void update(const std::vector<uint8_t>& message);

    /**
     * @brief Finalize the encryption.
     *
     * This includes (according to IEEE 1363a-2004):
     * 1. Encrypt the plaintext and return the encrypted data
     * 2. Calculate the tag/mac (use getMAC() for getting it)
     *
     * After invoking this function, the ephemeral key and the authentication key can be obtained using the getter
     * functions.
     * @throws MoCOCrWException if this function is invoked twice.
     * @return The encrypted data.
     */
    std::vector<uint8_t> finish();

    /**
     * @brief Returns the ephemeral key
     *
     * The ephemeral key is generated in the constructor of the instance. This public key (in combination with the
     * private key of the receiver) is necessary for decrypting the ciphertext.
     * @return The ephemeral key generated during encryption
     */
    AsymmetricPublicKey getEphemeralKey();

    /**
     * @brief Return the authentication tag
     *
     * The authentication tag is calculated as the last step during encryption. This tag verifies the
     * authenticity of the message.
     * @throws MoCOCrWException if finish() wasn't invoked beforehand
     * @return The tag/mac
     */
    std::vector<uint8_t> getMAC();

private:
    friend ECIESCtxBuilder;
    ECIESEncryptionCtx(const ECIESCtxBuilder &ctxBuilder);

    /**
     * Internal class for applying the PIMPL design pattern
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @see ECIESEncryptionCtx
 *
 * For decrypting you need the private key of the recipient instead of his/her/its public key and the ephemeral key
 * received from the sender.
 *
 * The algorithm for ECIES decryption is as follows:
 * 1. calculate the shared secret (P_shared = P_ephemeral * r_recipient = r_eph * r_recipient * G = r_eph * P_recipient)
 * 2. generate the key for symmetric encryption and MAC (key_sym || key_mac = KDF(P_shared)) (with the optional salt)
 * 3. calculate and verify the MAC (using the optional salt for MAC)
 * 4. decrypt the ciphertext
 *
 * For using the ECIESDecryptionCtx a builder class is provided which takes the parameter described above as input.
 * Afterwards the ECIESDecryptionCtx can be used like a symmetric cipher.
 *
 * The ephemeral key and the MAC can be set after creating the ECIESDecryptionCtx object. After setting the ephemeral
 * key the shared secret and the keys for decrypting and MAC are calculated automatically.
 *
 * After setting the ephemeral key you can use update() for adding ciphertext bytes and finish() for verifing the MAC
 * and getting the plaintext. If the verification fails no plaintext is returned, but an error is thrown instead.
 *
 * Workflow for Decryption:
 * 1. Receive the data
 * 2. Split it into ephemeral key, ciphertext and MAC
 * 3. Get the necessary data (private key, MAC scheme, KDF scheme, symmetric cipher scheme, optional salts)
 * 4. Construct an ECIESDecryptionCtx using the ECIESDecryptionCtxBuilder providing the cipher data (@see
 *    ECIESEncryptionCtx). The ephemeral key is needed here.
 * 5. Decrypt the ciphertext using update()
 * 6. Set the MAC (setMac())
 * 7. Invoke finish for verifying the MAC and for getting the plaintext
 */
class ECIESDecryptionCtx {
public:

    /**
     * @brief Destructor
     */
    ~ECIESDecryptionCtx();

    /**
     * @brief Decrypt a chunk of data.
     *
     * Furthermore the data is used for MAC calculation.
     *
     * The ephemeral key (using setEphemeralKey()) has to be set before invoking update().
     *
     * @param message chunk of data to decrypt.
     * @throws MoCOCrWException if this function is invoked after finish was called.
     * @throws MoCOCrWException when no ephemeral key is set.
     */
    void update(const std::vector<uint8_t>& message);

    /**
     * @brief Finalizes decryption and verifies authenticity
     *
     * During verification the calculated authentication tag is compared to the given one received via setMAC().
     * The authentication tag is calculated over the ciphertext provided via update().
     *
     * The MAC (using setMac()) has to be set before invoking finish().
     *
     * @throws MoCOCrWException when the received tag/mac differs from the calculated tag/mac.
     * @throws MoCOCrWException when no MAC is set.
     * @throws MoCOCrWException when no ephemeral key is set.
     * @return The decrypted message
     */
    std::vector<uint8_t> finish();

    /**
     * @brief Set the authentication tag
     *
     * As the last step during encryption the authentication tag is calculated. Set this tag before calling finish() so
     * that the authenticity the received message can be verified.
     * If the MAC is not set a MoCOCrWException is thrown when finish() is invoked.
     * @param tag The authentication tag
     */
    void setMAC(const std::vector<uint8_t>& tag);

private:
    friend ECIESCtxBuilder;
    ECIESDecryptionCtx(const ECIESCtxBuilder &ctxBuilder);

    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

/**
 * @brief The ECIESCtxBuilder class provides help to create Encryption and Decryption contexts.
 *
 * The ECIESCtxBuilder simplifies the creation of the ECIES Encryption and Decryption contexts. This is done by
 * providing setters for all available parameters according to IEEE 1363a and default values for these parameters if
 * none is set.
 */
class ECIESCtxBuilder
{
public:
    /**
     * @brief constructor
     */
    ECIESCtxBuilder();

    ~ECIESCtxBuilder();

    /**
     * @brief Sets the key derivation function used for ECIES
     * @param kdf The actual object used in ECIES
     * @return builder instance
     */
    ECIESCtxBuilder &setKDF(std::shared_ptr<KeyDerivationFunction> kdf);

    /**
     * @brief Sets the required key size for MAC ciphers
     *
     * Default: The default MAC-Cipher is HMAC-SHA512, thus the MAC key size is 512/8 = 64
     * @param keySize The key size in bytes
     * @return builder instance
     */
    ECIESCtxBuilder &setMacKeySize(size_t keySize);

    /**
     * @brief Sets a function for creating the MAC object inside ECIES
     *
     * Default: HMAC-SHA512 if not set
     *
     * As the key for MAC is generated during ECIES key generation, the MAC object has to be instantiated after that.
     * This function is a dependency injection.
     * (example using HMAC-SHA512:
     \code{.cpp}
        auto macFunc = [](const std::vector<uint8_t> &key) -> std::unique_ptr<MessageAuthenticationCode> {
            return std::make_unique<mococrw::HMAC>(openssl::DigestTypes::SHA512, key);
        };
     \endcode
     * )
     * @param func A std::function which returns an object implementing the MessageAuthenticationCode interface
     * @return builder instance
     */
    ECIESCtxBuilder &setMacFactoryFunction(std::function<std::unique_ptr<MessageAuthenticationCode>(
                                               const std::vector<uint8_t>&)> func);

    /**
     * @brief Sets the required key size for symmetric ciphers
     *
     * Default: The default symmetric cipher is AES-CBC PKCS7, with a key length of 256/8 = 32
     * @param keySize The key size in bytes
     * @return builder instance
     */
    ECIESCtxBuilder &setSymmetricCipherKeySize(size_t keySize);

    /**
     * @brief Sets a function for creating the AES object inside ECIES
     *
     * Default: If no function is set the default value is AES-CBC PKCS7-padding IV=0x00
     *
     * As the key for AES is generated during ECIES key generation, the AES object has to be instantiated after that.
     * This function is a dependency injection.
     * (e.g. for AES-CBC PKCS7-padding IV=0x00:
     \code{.cpp}
        auto cipherDecFunc = [](const std::vector<uint8_t> &key) -> std::unique_ptr<AESCipher> {
            return AESCipherBuilder(SymmetricCipherMode::CBC, SymmetricCipherKeySize::S_256, key)
                    .setIV(std::vector<uint8_t>(AESCipherBuilder::getDefaultIVLength(mode)))
                    .setPadding(SymmetricCipherPadding::PKCS)
                    .buildDecryptor();
        };

        auto cipherEncFunc = [](const std::vector<uint8_t> &key) -> std::unique_ptr<AESCipher> {
            return AESCipherBuilder(SymmetricCipherMode::CBC, SymmetricCipherKeySize::S_256, key)
                    .setIV(std::vector<uint8_t>(AESCipherBuilder::getDefaultIVLength(mode)))
                    .setPadding(SymmetricCipherPadding::PKCS)
                    .buildEncryptor();
        };
    \endcode
     * @param func A std::function which will be provided with the symmetric key (of key size provided
     * in setSymmetricCipherKeySize) and should return an object implementing the SymmetricCipherI interface.
     * @return builder instance
     */
    ECIESCtxBuilder &setSymmetricCipherFactoryFunction(std::function<std::unique_ptr<SymmetricCipherI>(
                                                           const std::vector<uint8_t>&)> func);


    /**
     * @brief Sets the salt for the key derivation function (KDF).
     *
     * If no value is set, the KDF calculation is done without any salt
     * @param kdfSalt The salt value used for key derivation.
     * @return builder instance
     */
    ECIESCtxBuilder &setKDFSalt(std::vector<uint8_t> kdfSalt);

    /**
     * @brief Sets the salt for the message authentication code.
     *
     * If no value is set, the MAC calculation is done without any salt
     * @param macSalt The salt value used for message authentication code.
     * @return builder instance
     */
    ECIESCtxBuilder &setMACSalt(std::vector<uint8_t> macSalt);

    /**
     * @brief Create the ECIES encryption context.
     *
     * Call this function after you have set the options, which differ from the default value
     * @throws MoCOCrWException If a required parameter is not set.
     * @param bobsKey The public key of the receiver
     * @return An ECIES encryption context, which can be used for encryption.
     */
    std::unique_ptr<ECIESEncryptionCtx> buildEncryptionCtx(AsymmetricPublicKey bobsKey);

    /**
     * @overload std::unique_ptr<ECIESEncryptionCtx> buildEncryptionCtx(const AsymmetricPublicKey& bobsKey);
     * @param bobsCert The certificate of the receiver. This must contain a public key.
     */
    std::unique_ptr<ECIESEncryptionCtx> buildEncryptionCtx(X509Certificate bobsCert);

    /**
     * @brief Create the ECIES decryption context
     *
     * Call this function after you have set all the options to the values used by the sender.
     * For decrypting the ciphertext the ephemeral public key, which was generated during encryption, is needed.
     * @throws MoCOCrWException If a required parameter is not set.
     * @param bobsKey The private key of the receiver
     * @param ephKey The ephemeral key generated during encryption
     * @return An ECIES decryption context, which can be used for decryption.
     */
    std::unique_ptr<ECIESDecryptionCtx> buildDecryptionCtx(AsymmetricPrivateKey bobsKey,
                                                           AsymmetricPublicKey ephKey);

protected:
    friend class ECIESImpl;
    friend class ECIESEncryptionCtx;
    friend class ECIESDecryptionCtx;

    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};
} // mococrw
