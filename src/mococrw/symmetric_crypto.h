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

#include <cstdint>
#include <memory>
#include <vector>

#include "openssl_wrap.h"

namespace mococrw
{

/**
 * SymmetricCipherMode defines symmetric cipher modes supported by the library.
 */
enum class SymmetricCipherMode
{
    GCM,
    CBC,
    CTR
};

/**
 * Supported key lengths for symmetric cipher
 */
enum class SymmetricCipherKeySize
{
    S_128,
    S_256
};

/**
 * Supported padding types for symmetric encryption.
 */
enum class SymmetricCipherPadding
{
    NO,
    PKCS
};

/**
 * @brief Returns the length of the symmetric key in bytes
 * @param keySize The key size in enum representation
 * @return The size of the key in bytes
 */
size_t getSymmetricCipherKeySize(SymmetricCipherKeySize keySize);

/**
 * Abstract interface for symmetric encryption and decryption.
 *
 * This interface defines cipher type and mode agnostic interface for one-shot and stream-based
 * operations.
 *
 * The interface of an encryptor and decryptor is the same and type and mode agnostic. Once created
 * by a correspondent builder, block- or stream-based modes of operation can be used:
 *
 * In **one-shot**, an input chunk of data is encrypted/decrypted by a single call to update().
 * Then, the operation is finalized and processed data is returned by finish().
 *
 * **Stream-mode** allows to encrypt/decrypt data in chunks. Put a portion of input data into the
 * cipher using update() and obtain the result data using realAll()/read(). When all data is
 * processed, finish() must be called.
 *
 * Simple example of encryption:
 * @code
 *   // Encryption
 *   auto encryptor = AESCipherBuilder{SymmetricCipherMode::CTR, SymmetricCipherKeySize::S_256, secretKey}.buildEncryptor();
 *   encryptor->update(plaintext);
 *   auto ciphertext = encryptor->finish();
 *   auto iv = encryptor->getIV();
 *
 *   // Decryption
 *   auto decryptor = AESCipherBuilder{SymmetricCipherMode::CTR, SymmetricCipherKeySize::S_256, secretKey}.setIV(iv).buildDecryptor();
 *   decryptor->update(ciphertext);
 *   auto decryptedText = decryptor->finish();
 * @endcode
 */
class SymmetricCipherI
{
public:
    virtual ~SymmetricCipherI() = default;

    /**
     * Decrypt or encrypt a chunk of data.
     *
     * This function encrypts or decrypts a chunk of data and places result in the internal buffer.
     * Processed data can be accessed via read() and/or readAll().
     *
     * @param message chunk of data to encrypt/decrypt.
     */
    virtual void update(const std::vector<uint8_t> &message) = 0;

    /**
     * Read a portion of encrypted/decrypted data from cipher buffer.
     *
     * Depending on the (internal) memory strategy and the size of read chunk, performance of this
     * method will vary. The current version uses queue of vectors as internal buffer. Therefore,
     * alternating update() and read() of data blocks of the same size (or readAll()) are zero-copy
     * operations.
     *
     * @param length size of the requested chunk of data.
     * @return processed chunk of \c length or smaller.
     */
    virtual std::vector<uint8_t> read(size_t length) = 0;

    /**
     * Read all available encrypted/decrypted data from the cipher buffer.
     *
     * If there is more than one chunk in the internal buffer, readAll() reassembles the result from
     * encrypted/decrypted blocks previously passed to update(). Note that no copying occurs if
     * there is only one chunk in the internal buffer, i.e. a loop of update()/read() calls has the
     * same performance as calling update()/readAll(). Additional copy operations are to be expected
     * when update() was called more than once.
     *
     * @return all processed data
     */
    virtual std::vector<uint8_t> readAll() = 0;

    /**
     * Finalize encryption/decryption and return all processed data not yet read by
     * read()/readAll().
     *
     * @note When using with authenticated encryption modes in decryption operations, this method
     * will throw a \c MoCOCrWException when validation of the auth tag fails.
     *
     * @throws MoCOCrWException when used with authenticated encryption schemes and auth tag
     *         validation fails on decyrption.
     * @return any remaining processed data
     */
    virtual std::vector<uint8_t> finish() = 0;

    /**
     * Get initialization vector
     *
     * @sa AESCipherBuilder
     *
     * @return the initialization vector used for this cryptographic operation
     */
    virtual std::vector<uint8_t> getIV() const = 0;
};

/**
 * This interface declares an authenticated encryption extension to SymmetricCipherI
 *
 * @code
 *   // Encryption
 *   auto encryptor = AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, secretKey}.buildAuthenticatedEncryptor();
 *   encryptor->update(plaintext);
 *   auto ciphertext = encryptor->finish();
 *   auto iv = encryptor->getIV();
 *   auto tag = encryptor->getAuthTag();
 *
 *   // Decryption
 *   auto decryptor = AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, secretKey}.setIV(iv).buildAuthenticatedDecryptor();
 *   decryptor->update(ciphertext);
 *   decryptor->setAuthTag(tag);
 *   std::vector<uint8_t> decryptedText;
 *   try {
 *       decryptedText = decryptor->finish();
 *   } except (const MoCOCrWException& e) {
 *       // decryption (or auth tag validation) failed
 *   }
 * @endcode
 */
class AuthenticatedEncryptionI
{
public:
    /**
     * Set authentication tag.
     *
     * For an authenticated cipher, setAuthTag() must be called before finalizing decryption using
     * SymmetricCipherI::finish().
     *
     * @param tag authentication tag
     */
    virtual void setAuthTag(const std::vector<uint8_t> &tag) = 0;

    /**
     * Get authentication tag.
     *
     * For an authenticated cipher, getAuthTag() must be called after encryption is finalized using
     * SymmetricCipherI::finish().
     *
     * @return the auth tag for this encryption operation
     */
    virtual std::vector<uint8_t> getAuthTag() const = 0;

    /**
     * Add associated data.
     *
     * This function adds the associated data in AEAD modes for authenticating while encrypting or verifying while
     * decrypting. addAssociatedData() can be called multiple times but it must be called before finalizing decryption
     * using SymmetricCipherI::finish() and before putting encrypted data to the message
     * using SymmetricCipherI::update()
     *
     * @param associatedData chunk of data to associate/verify.
     */
    virtual void addAssociatedData(const std::vector<uint8_t> &associatedData) = 0;
};

class AESCipherBuilder;

/**
 * AES cipher
 *
 * @sa SymmetricCipherI
 */
class AESCipher : public SymmetricCipherI
{
public:
    ~AESCipher();

    // Implementation of SymmetricCipherI
    void update(const std::vector<uint8_t> &message) override;
    std::vector<uint8_t> read(size_t length) override;
    std::vector<uint8_t> readAll() override;
    std::vector<uint8_t> finish() override;
    std::vector<uint8_t> getIV() const override;

protected:
    friend AESCipherBuilder;

    enum class Operation
    {
        Encryption,
        Decryption
    };

    AESCipher(SymmetricCipherMode mode, SymmetricCipherKeySize keySize,
              SymmetricCipherPadding padding, const std::vector<uint8_t> &secretKey,
              const std::vector<uint8_t> &iv, Operation operation);

    class Impl;

    std::unique_ptr<Impl> _impl;
};

/**
 * Authenticated AES cipher
 *
 * @sa SymmetricCipherI
 * @sa AuthenticatedEncryptionI
 */
class AuthenticatedAESCipher : public AESCipher, public AuthenticatedEncryptionI
{
public:
    // Implementation of AuthenticatedEncryptionI
    std::vector<uint8_t> getAuthTag() const override;
    void setAuthTag(const std::vector<uint8_t> &tag) override;
    void addAssociatedData(const std::vector<uint8_t> &associatedData) override;

private:
    friend AESCipherBuilder;

    AuthenticatedAESCipher(SymmetricCipherMode mode, SymmetricCipherKeySize keySize, SymmetricCipherPadding padding,
                           const std::vector<uint8_t> &secretKey, const std::vector<uint8_t> &iv,
                           size_t authTagLength, AESCipher::Operation operation);
};

/**
 * Factory for creating AES ciphers.
 *
 * @code
 * auto decryptor = AESCipherBuilder{SymmetricCipherMode::CTR, SymmetricCipherKeySize::S_256, secretKey}.setIV(iv).buildDecryptor();
 * @endcode
 */
class AESCipherBuilder
{
public:
    /**
     * Default constructor for AESCipherBuilder
     *
     * @param mode cipher mode of operation.
     * @param keySize key size of AES cipher (128 or 256 bits)
     * @param secretKey secret key. Size of the key must match the created cipher.
     * For AES-256 it must be 32 bytes long.
     */
    AESCipherBuilder(SymmetricCipherMode mode, SymmetricCipherKeySize keySize,
                     const std::vector<uint8_t> &secretKey);

    /**
     * Destructor, removes secret key material from memory by overwriting it
     * with zeroes.
     */
    ~AESCipherBuilder();

    /**
     * Set padding
     *
     * Optionally change type of padding of the created cipher. Defaults to SymmetricCipherPadding::PKCS.
     *
     * @param padding type of padding.
     * @return builder instance
     */
    AESCipherBuilder &setPadding(SymmetricCipherPadding padding);

    /**
     * Set IV
     *
     * When creating a cipher, this method can be used to provide the IV. If a cipher is created for
     * decryption, calling this method is mandatory. If the cipher is created for encryption,
     * a random IV of the default IV length as used in TLS (128 bit for AES-CBC and AES-CTR, 96 bit
     * for AES-GCM) is generated by the builder by default. Users can still can override the default
     * IV with their own values.
     *
     * @note If you set a custom IV for encryption, make sure that it is supported by the type of
     * cipher you are building. Also, use cryptographically secure IVs using
     * utility::cryptoRandomBytes().
     *
     * @param iv the initialization vector. Usually, you get this value together with the ciphertext and password.
     * @return builder instance
     */
    AESCipherBuilder &setIV(const std::vector<uint8_t> &iv);

    /**
     * @brief Get the default length of the IV in bytes given the cipher mode.
     * @param mode The mode
     * @return The length of the IV in bytes.
     */
    static size_t getDefaultIVLength(SymmetricCipherMode mode);

    /**
     * Set length of authentication tag for authenticated encryption.
     *
     * Use this method to change default length of authentication tag which the encryptor will
     * return in getAuthTag(). Default value is 128 bits.
     *
     * @note Do not use when creating a cipher for decryption. It does not make sense and will throw.
     *
     * @warning Please note that security of authenticated encryption directly depends on the length
     * of the authentication tag. If you think that you have valid reasons for using tag lengths
     * less than 64bit, please consult with Appendix C of
     * https://csrc.nist.gov/publications/detail/sp/800-38d/final.
     *
     * @param length
     * @return builder instance
     */
    AESCipherBuilder &setAuthTagLength(size_t length);

    /**
     * Create cipher for encryption.
     *
     * @return encryptor
     */
    std::unique_ptr<AESCipher> buildEncryptor();

    /**
     * Create cipher for decryption.
     *
     * @return dencryptor
     */
    std::unique_ptr<AESCipher> buildDecryptor();

    /**
     * Create authenticated cipher for encryption.
     *
     * This method must be called to build authenticated cipher such as SymmetricCipherMode::GCM.
     *
     * @return encryptor
     */
    std::unique_ptr<AuthenticatedAESCipher> buildAuthenticatedEncryptor();

    /**
     * Create authenticated cipher for decryption.
     *
     * This method must be called to build authenticated cipher such as SymmetricCipherMode::GCM.
     *
     * @return decryptor
     */
    std::unique_ptr<AuthenticatedAESCipher> buildAuthenticatedDecryptor();

private:
    static const size_t DefaultAuthTagLength;

    std::vector<uint8_t> _iv;
    SymmetricCipherMode _mode;
    SymmetricCipherKeySize _keySize;
    SymmetricCipherPadding _padding = SymmetricCipherPadding::PKCS;
    std::vector<uint8_t> _secretKey;
    size_t _authTagLength = DefaultAuthTagLength;
};

/**
 * Check if given symmetric cipher mode is an authenticated cipher.
 *
 * This helper function, knowing operation mode, allows implementing polymorphic behaviors. E.g.
 * creating encryptor/decryptor of a given type.
 *
 * @sa AESCipherBuilder
 *
 * @param mode cipher operation mode.
 * @return true if \c mode is authenticated encryption mode and false if not.
 */
bool isAuthenticatedCipherMode(SymmetricCipherMode mode);

} // namespace mococrw
