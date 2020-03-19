/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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

class ECIESEncryptionCtxBuilder;

/**
 * @brief ECIESEncryptionCtx
 *
 * This class supports encryption of plain texts using ECIES
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
     * This function stores the data in the internal buffer.
     * The data in the internal buffer is encrypted, when the finish method is invoked.
     *
     * @param message chunk of data to encrypt.
     * @throws MoCOCrWException if this function is invoked after finish was called.
     */
    void update(const std::vector<uint8_t>& message);

    /**
     * @brief Finalize the encryption.
     *
     * This includes:
     * 1. Creating the ephemeral key used for encryption (use getEphemeralKey() for getting it)
     * 2. Encrypt the plaintext
     * 3. Calculate the tag/mac (use getMac() for getting it)
     *
     * After invoking this function, the ephemeral key and the authentication key can obtained using the getter
     * functions.
     * @return The encrypted data.
     */
    std::vector<uint8_t> finish();

    /**
     * @brief Returns the ephemeral key
     *
     * The ephemeral key is generated during encryption. This public key (in combination with the private key of the
     * receiver) is necessary for decrypting the ciphertext.
     * @throws MoCOCrWException if finish() hasn't been invoked beforehand
     * @return The ephemeral key generated during encryption
     */
    AsymmetricPublicKey getEphemeralKey();

    /**
     * @brief Return the authentication tag
     *
     * The authentication tag is calculated as the last step during encryption. This tag verifies the
     * authenticity of the message.
     * @throws MoCOCrWException if finish() hasn't been invoked beforehand
     * @return The tag/mac
     */
    std::vector<uint8_t> getAuthTag();

private:
    ECIESEncryptionCtx(const AsymmetricPublicKey& pubKey,
                       const std::shared_ptr<mococrw::KeyDerivationFunction> kdf,
                       const std::shared_ptr<mococrw::MessageAuthenticationCode> mac,
                       const mococrw::SymmetricCipherMode mode,
                       const mococrw::SymmetricCipherKeySize keySize,
                       const mococrw::SymmetricCipherPadding padding,
                       const std::vector<uint8_t>& S1,
                       const std::vector<uint8_t>& S2,
                       const std::vector<uint8_t>& iv);

    ECIESEncryptionCtx(const X509Certificate& cert,
                       const std::shared_ptr<mococrw::KeyDerivationFunction> kdf,
                       const std::shared_ptr<mococrw::MessageAuthenticationCode> mac,
                       const mococrw::SymmetricCipherMode mode,
                       const mococrw::SymmetricCipherKeySize keySize,
                       const mococrw::SymmetricCipherPadding padding,
                       const std::vector<uint8_t>& S1,
                       const std::vector<uint8_t>& S2,
                       const std::vector<uint8_t>& iv);

    friend ECIESEncryptionCtxBuilder;

    /**
     * Internal class for applying the PIMPL design pattern
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

class ECIESDecryptionCtxBuilder;

/**
 * @brief ECIESDecryptionCtx
 *
 * This class supports decryption of plain texts using ECIES
 *
 */
class ECIESDecryptionCtx {
public:

    /**
     * @brief Destructor
     */
    ~ECIESDecryptionCtx();

    /**
     * Decrypt a chunk of data.
     *
     * This function stores the data in the internal buffer.
     * The data in the internal buffer is decrypted, when the finish method is invoked.
     *
     * @param message chunk of data to decrypt.
     * @throws MoCOCrWException if this function is invoked after finish was called.
     */
    void update(const std::vector<uint8_t>& message);

    /**
     * @brief Decrypts all the content stored in the internal buffer via the update function.
     *
     * @throws MoCOCrWException when the tag/mac of the message differs from the calculated tag/mac.
     * @throws MoCOCrWException when the ephemeral public key has different domain parameters then the private key.
     * @return The decrypted message
     */
    std::vector<uint8_t> finish();

    /**
     * @brief Sets the ephemeral public key which was generated during encryption
     *
     * For decrypting the ciphertext the ephemeral public key, which was generated during encryption, is needed.
     * @param ephKey The ephemeral key generated during encryption
     */
    void setEphemeralKey(const AsymmetricPublicKey& ephKey);

    /**
     * @brief Set the authentication tag
     *
     * As the last step during encryption the authentication tag is calculated. Set this tag to verify the authenticity
     * of the received message.
     * @param tag The authentication tag
     */
    void setAuthTag( const std::vector<uint8_t>& tag);

private:

    ECIESDecryptionCtx(const AsymmetricPrivateKey& privKey,
                       const std::shared_ptr<mococrw::KeyDerivationFunction> kdf,
                       const std::shared_ptr<mococrw::MessageAuthenticationCode> mac,
                       const mococrw::SymmetricCipherMode mode,
                       const mococrw::SymmetricCipherKeySize keySize,
                       const mococrw::SymmetricCipherPadding padding,
                       const std::vector<uint8_t>& iv,
                       const std::vector<uint8_t>& S1,
                       const std::vector<uint8_t>& S2);

    friend ECIESDecryptionCtxBuilder;

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
 * @brief The ECIESCtxBuilder class is an pseudo abstract class for providing common functions to the Encryption and
 * Decryption context builders.
 */
class ECIESCtxBuilder
{
public:
    /**
     * @brief Sets the key derivation function used for ECIES (Default: mococrw::X963KDF with SHA512)
     * @param kdf The actual object used in ECIES
     * @return builder instance
     */
    ECIESCtxBuilder &setKDF(std::shared_ptr<mococrw::KeyDerivationFunction> kdf);

    /**
     * @brief Sets the message authentication code used for ECIES. (Default: mococrw::HMAC with SHA512)
     * @param mac The actual object used in ECIES
     * @return builder instance
     */
    ECIESCtxBuilder &setMAC(std::shared_ptr<mococrw::MessageAuthenticationCode> mac);

    /**
     * @brief Sets the symmetric cipher mode. (Default: mococrw::SymmetricCipherMode::CBC)
     * @param mode The mode used in ECIES
     * @return builder instance
     */
    ECIESCtxBuilder &setSymmetricCipherMode(mococrw::SymmetricCipherMode mode);

    /**
     * @brief Sets the key size for the symmetric encryption. (Default: mococrw::SymmetricCipherKeySize::S_256)
     * @param keySize The key size to be used
     * @return builder instance
     */
    ECIESCtxBuilder &setSymmetricCipherKeySize(mococrw::SymmetricCipherKeySize keySize);

    /**
     * @brief Sets the padding for the symmetric encryption. (Default: mococrw::SymmetricCipherPadding::NO)
     * @param padding The padding scheme to be used.
     * @return builder instance
     */
    ECIESCtxBuilder &setSymmetircCipherPadding(mococrw::SymmetricCipherPadding padding);

    /**
     * @brief Sets the initialisation vector (IV) for the symmetric encryption. (Default: zeros)
     * @param iv The initialisation vector. The length shall be the same as the key length
     * @return builder instance
     */
    ECIESCtxBuilder &setSymmetricCipherIv(const std::vector<uint8_t>& iv);

    /**
     * @brief Sets the salt for the key derivation function (KDF). (Default: empty vector -> not used)
     * @param kdfSalt The salt value used for key derivation.
     * @return builder instance
     */
    ECIESCtxBuilder &setKDFSalt(std::vector<uint8_t> kdfSalt);

    /**
     * @brief Sets the salt for the message authentication code. (Default: empty vector -> not used).
     * @param macSalt The salt value used for message authentication code.
     * @return builder instance
     */
    ECIESCtxBuilder &setMACSalt(std::vector<uint8_t> macSalt);

protected:
    /**
     * @brief constructor
     *
     * This class shall not be instantiated (except by subclasses)
     */
    ECIESCtxBuilder();

private:
    std::shared_ptr<mococrw::KeyDerivationFunction> kdf;
    std::shared_ptr<mococrw::MessageAuthenticationCode> mac;
    mococrw::SymmetricCipherMode mode;
    mococrw::SymmetricCipherKeySize keySize;
    mococrw::SymmetricCipherPadding padding;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> kdfSalt;
    std::vector<uint8_t> macSalt;

};

class ECIESEncryptionCtxBuilder : public ECIESCtxBuilder
{
public:
    /**
     * \brief Constructor for public keys
     * \param bobsKey The public key of the receiver.
     */
    ECIESEncryptionCtxBuilder(const AsymmetricPublicKey& bobsKey);

    /**
     * @brief Constructor for certificates
     * @param bobsCert The certificate of the receiver which contains his/her public key.
     */
    ECIESEncryptionCtxBuilder(const X509Certificate& bobsCert);

    /**
     * @brief Create the ECIES encryption context.
     *
     * Call this function after you have set the options, which differ from the default value
     * @return An ECIES encryption context, which can be used for encryption.
     */
    std::unique_ptr<ECIESEncryptionCtx> buildEncryptionCtx();

private:
    AsymmetricPublicKey pubKey;
    X509Certificate cert;
};

class ECIESDecryptionCtxBuilder : public ECIESCtxBuilder
{
public:
    /**
     * @brief Constructor
     * @param bobsKey The private key of the receiver. This key is needed for decrypting the ciphertext
     */
    ECIESDecryptionCtxBuilder(const AsymmetricPrivateKey& bobsKey);

    /**
     * @brief Create the ECIES decryption context
     *
     * Call this function after you have set all the options to the values used by the sender.
     * @return An ECIES decryption context, which can be used for decryption.
     */
    std::unique_ptr<ECIESDecryptionCtx> buildDecryptionCtx();

private:
    AsymmetricPrivateKey privKey;
};

}
