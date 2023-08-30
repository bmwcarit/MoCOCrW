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

#include "mococrw/symmetric_memory.h"

#include <string>
#include <type_traits>

#include <openssl/evp.h>

#include "mococrw/error.h"
#include "mococrw/openssl_wrap.h"
#include "mococrw/symmetric_crypto.h"
#include "mococrw/util.h"

namespace mococrw
{
using namespace openssl;

size_t getSymmetricCipherKeySize(SymmetricCipherKeySize keySize)
{
    if (keySize == SymmetricCipherKeySize::S_128) {
        return 128 / 8;
    } else if (keySize == SymmetricCipherKeySize::S_256) {
        return 256 / 8;
    }

    throw MoCOCrWException("Key size is not supported.");
}

/**
 * Get the default length of the IV in bytes given the cipher mode.
 *
 * @return The IV length in bytes.
 */
size_t AESCipherBuilder::getDefaultIVLength(SymmetricCipherMode mode)
{
    switch (mode) {
        case SymmetricCipherMode::GCM:
            return 12;
        case SymmetricCipherMode::CBC:
        case SymmetricCipherMode::CTR:
            return 16;
    }
    throw MoCOCrWException(
            "Could not determine default IV length for cipher mode " +
            std::to_string(static_cast<std::underlying_type_t<decltype(mode)>>(mode)));
}

class AESCipher::Impl
{
public:
    Impl(SymmetricCipherMode mode,
         SymmetricCipherKeySize keySize,
         SymmetricCipherPadding padding,
         const std::vector<uint8_t> &secretKey,
         const std::vector<uint8_t> &iv,
         Operation operation,
         std::unique_ptr<CipherMemoryStrategyI> memoryStrategy =
                 std::make_unique<QueueOfVectorsMemoryStrategy>())
            : _mode{mode}
            , _iv{iv}
            , _operation{operation}
            , _bufferStrategy(std::move(memoryStrategy))
    {
        _ctx = _EVP_CIPHER_CTX_new();

        const EVPCipherConstructor evpCipherConstructor =
                getEVPCipherConstructorForModeAndSize(mode, keySize);

        _EVP_CipherInit_ex(_ctx.get(),
                           evpCipherConstructor(),
                           nullptr,
                           nullptr,
                           nullptr,
                           this->_operation == Operation::Encryption);

        // Check id key size matches cipher block size
        size_t expectedKeySize = _EVP_CIPHER_CTX_key_length(_ctx.get());
        if (secretKey.size() != expectedKeySize) {
            auto formatter = boost::format("Invalid size of Key %d bytes. Must be %d bytes.");
            formatter % secretKey.size() % expectedKeySize;
            throw MoCOCrWException(formatter.str());
        }

        // Check IV length and adjust if cipher supports it
        switch (mode) {
            case SymmetricCipherMode::GCM: {
                if (_iv.size() == 0) {
                    throw MoCOCrWException("IV is empty, but AES-GCM does not support empty IVs.");
                }
                _EVP_CIPHER_CTX_ctrl(_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, _iv.size(), nullptr);
            } break;
            case SymmetricCipherMode::CTR:
                //[[fallthrough]];
            case SymmetricCipherMode::CBC: {
                size_t expectedIVSize = _EVP_CIPHER_CTX_iv_length(_ctx.get());
                if (_iv.size() != expectedIVSize) {
                    auto formatter =
                            boost::format("Invalid size of IV %d bytes. Must be %d bytes.");
                    formatter % _iv.size() % expectedIVSize;
                    throw MoCOCrWException(formatter.str());
                }
            } break;
        }

        _EVP_CipherInit_ex(_ctx.get(),
                           nullptr,
                           nullptr,
                           secretKey.data(),
                           _iv.data(),
                           this->_operation == Operation::Encryption);

        /* IV length sanity check
         * EVP_CIPHER_CTX_iv_length() returns int and compiler complains about type mismatch.
         * That's why casting and size check for safe casting are needed.
         */
        if (_iv.size() > INT_MAX) {
            throw MoCOCrWException("Suspicious IV length");
        }
        if (static_cast<int>(_iv.size()) != _EVP_CIPHER_CTX_iv_length(_ctx.get())) {
            throw MoCOCrWException("Length of set IV doesn't match length of IV OpenSSL uses");
        }

        switch (padding) {
            case SymmetricCipherPadding::PKCS:
                // OpenSSL uses PKCS padding by default.
                break;
            case SymmetricCipherPadding::NO:
                _EVP_CIPHER_CTX_set_padding(_ctx.get(), 0);
                break;
        }
    };

    void update(const std::vector<uint8_t> &message)
    {
        if (_isFinished) {
            throw MoCOCrWException(
                    "Further calls to update() are not allowed once finish() was called.");
        }

        if (message.size() > static_cast<std::decay_t<decltype(message)>::size_type>(
                                     std::numeric_limits<int>::max() - EVP_MAX_BLOCK_LENGTH)) {
            throw MoCOCrWException("Message is too big.");
        }

        int processingChunkSize = message.size();
        if (processingChunkSize <= 0) {
            return;
        }
        std::vector<uint8_t> processedChunk(processingChunkSize + EVP_MAX_BLOCK_LENGTH);

        _EVP_CipherUpdate(_ctx.get(),
                          processedChunk.data(),
                          &processingChunkSize,
                          message.data(),
                          message.size());

        if (processingChunkSize > 0) {
            processedChunk.resize(processingChunkSize);
            _bufferStrategy->write(std::move(processedChunk));
        }

        _isUpdated = true;
    }

    void addAssociatedData(const std::vector<uint8_t> &associatedData)
    {
        if (_isUpdated) {
            throw MoCOCrWException(
                    "Further calls to addAssociatedData() are not allowed once update() was "
                    "called.");
        }
        if (_isFinished) {
            throw MoCOCrWException(
                    "Further calls to addAssociatedData() are not allowed once finish() was "
                    "called.");
        }

        int len = 0;
        _EVP_CipherUpdate(_ctx.get(), NULL, &len, associatedData.data(), associatedData.size());
    }

    std::vector<uint8_t> read(size_t length) { return _bufferStrategy->read(length); }

    std::vector<uint8_t> readAll() { return _bufferStrategy->readAll(); }

    std::vector<uint8_t> finish()
    {
        if (_isFinished) {
            throw MoCOCrWException("finish() can't be called twice.");
        }

        int processingChunkSize = 0;
        std::vector<uint8_t> processedChunk(EVP_MAX_BLOCK_LENGTH);

        if (isAuthenticatedCipherMode(_mode) && _operation == Operation::Decryption) {
            if (_authTag.size() == 0) {
                throw MoCOCrWException(
                        "Authentication Tag must be set before calling finish() "
                        "for cipher which implements authenticated encryption.");
            }
            _EVP_CIPHER_CTX_ctrl(
                    _ctx.get(), EVP_CTRL_GCM_SET_TAG, _authTag.size(), _authTag.data());
        }

        try {
            _EVP_CipherFinal_ex(_ctx.get(), processedChunk.data(), &processingChunkSize);
        } catch (const OpenSSLException &e) {
            // OpenSSL does not set any specific error codes which we can use to distinguish
            // authentication failure from other type of errors. Therefore, if there is an error
            // on decrypting authenticated ciphertext we assume that there is a problem with
            // the key, padding or IV.
            if (isAuthenticatedCipherMode(_mode) && _operation == Operation::Decryption) {
                throw MoCOCrWException(
                        "Unable to decrypt authenticated ciphertext. Either ciphertext was"
                        " modified or wrong combination of key, iv and authTag was used.");
            } else {
                throw e;
            }
        }

        if (_mode == SymmetricCipherMode::GCM && _operation == Operation::Encryption) {
            _authTag.resize(_requestedAuthTagLength);
            _EVP_CIPHER_CTX_ctrl(
                    _ctx.get(), EVP_CTRL_GCM_GET_TAG, _requestedAuthTagLength, _authTag.data());
        }

        processedChunk.resize(processingChunkSize);
        _bufferStrategy->write(std::move(processedChunk));
        _isFinished = true;

        return _bufferStrategy->readAll();
    }

    std::vector<uint8_t> getIV() { return _iv; }

    void setAuthTagLength(size_t length) { _requestedAuthTagLength = length; }

    std::vector<uint8_t> getAuthTag() { return _authTag; }

    void setAuthTag(const std::vector<uint8_t> &authTag) { _authTag = authTag; }

private:
    SymmetricCipherMode _mode;
    std::vector<uint8_t> _iv;
    std::vector<uint8_t> _authTag;
    size_t _requestedAuthTagLength;
    Operation _operation;

    SSL_EVP_CIPHER_CTX_Ptr _ctx = nullptr;
    std::unique_ptr<CipherMemoryStrategyI> _bufferStrategy = nullptr;
    bool _isFinished = false;
    bool _isUpdated = false;

    using EVPCipherConstructor = const EVP_CIPHER *(*)();

    EVPCipherConstructor getEVPCipherConstructorForModeAndSize(SymmetricCipherMode mode,
                                                               SymmetricCipherKeySize keySize)
    {
        EVPCipherConstructor constructor = nullptr;

        switch (mode) {
            case SymmetricCipherMode::GCM:
                switch (keySize) {
                    case SymmetricCipherKeySize::S_256:
                        constructor = EVP_aes_256_gcm;
                        break;
                    case SymmetricCipherKeySize::S_128:
                        constructor = EVP_aes_128_gcm;
                        break;
                    default:
                        throw MoCOCrWException("Not yet implemented key size for the given mode.");
                }
                break;
            case SymmetricCipherMode::CBC:
                switch (keySize) {
                    case SymmetricCipherKeySize::S_256:
                        constructor = EVP_aes_256_cbc;
                        break;
                    case SymmetricCipherKeySize::S_128:
                        constructor = EVP_aes_128_cbc;
                        break;
                    default:
                        throw MoCOCrWException("Not yet implemented key size for the given mode.");
                }
                break;
            case SymmetricCipherMode::CTR:
                switch (keySize) {
                    case SymmetricCipherKeySize::S_256:
                        constructor = EVP_aes_256_ctr;
                        break;
                    case SymmetricCipherKeySize::S_128:
                        constructor = EVP_aes_128_ctr;
                        break;
                    default:
                        throw MoCOCrWException("Not yet implemented key size for the given mode.");
                }
                break;
            default:
                throw MoCOCrWException("Not yet implemented cipher mode.");
        }

        return constructor;
    }
};

AESCipher::AESCipher(SymmetricCipherMode mode,
                     SymmetricCipherKeySize keySize,
                     SymmetricCipherPadding padding,
                     const std::vector<uint8_t> &secretKey,
                     const std::vector<uint8_t> &iv,
                     Operation operation)
{
    _impl = std::make_unique<AESCipher::Impl>(mode, keySize, padding, secretKey, iv, operation);
}

AESCipher::~AESCipher() = default;

void AESCipher::update(const std::vector<uint8_t> &message) { _impl->update(message); }

std::vector<uint8_t> AESCipher::read(size_t length) { return _impl->read(length); }

std::vector<uint8_t> AESCipher::readAll() { return _impl->readAll(); }

std::vector<uint8_t> AESCipher::finish() { return _impl->finish(); }

std::vector<uint8_t> AESCipher::getIV() const { return _impl->getIV(); }

AuthenticatedAESCipher::AuthenticatedAESCipher(SymmetricCipherMode mode,
                                               SymmetricCipherKeySize keySize,
                                               SymmetricCipherPadding padding,
                                               const std::vector<uint8_t> &secretKey,
                                               const std::vector<uint8_t> &iv,
                                               size_t authTagLength,
                                               AESCipher::Operation operation)
        : AESCipher(mode, keySize, padding, secretKey, iv, operation)
{
    _impl->setAuthTagLength(authTagLength);
}

std::vector<uint8_t> AuthenticatedAESCipher::getAuthTag() const { return _impl->getAuthTag(); }

void AuthenticatedAESCipher::setAuthTag(const std::vector<uint8_t> &tag) { _impl->setAuthTag(tag); }

void AuthenticatedAESCipher::addAssociatedData(const std::vector<uint8_t> &associatedData)
{
    _impl->addAssociatedData(associatedData);
}

const size_t AESCipherBuilder::DefaultAuthTagLength = 16;

AESCipherBuilder::AESCipherBuilder(SymmetricCipherMode mode,
                                   SymmetricCipherKeySize keySize,
                                   const std::vector<uint8_t> &secretKey)
        : _mode{mode}, _keySize{keySize}, _secretKey{secretKey}
{
}

AESCipherBuilder::~AESCipherBuilder() { utility::vectorCleanse(_secretKey); }

AESCipherBuilder &AESCipherBuilder::setIV(const std::vector<uint8_t> &iv)
{
    _iv = iv;
    return *this;
}

AESCipherBuilder &AESCipherBuilder::setPadding(SymmetricCipherPadding padding)
{
    _padding = padding;
    return *this;
}

AESCipherBuilder &AESCipherBuilder::setAuthTagLength(size_t length)
{
    _authTagLength = length;
    return *this;
}

bool isAuthenticatedCipherMode(SymmetricCipherMode mode)
{
    switch (mode) {
        case SymmetricCipherMode::GCM:
            return true;
        case SymmetricCipherMode::CTR:
            //[[fallthrough]];
        case SymmetricCipherMode::CBC:
            return false;
    }

    throw MoCOCrWException(
            "Could not determine whether cipher mode " +
            std::to_string(static_cast<std::underlying_type_t<decltype(mode)>>(mode)) +
            " offers authenticated encryption");
}

std::unique_ptr<AESCipher> AESCipherBuilder::buildEncryptor()
{
    if (isAuthenticatedCipherMode(_mode)) {
        throw MoCOCrWException(
                "Specified cipher supports authenticated encryption."
                " buildAuthenticatedEncryptor() should be used instead.");
    }

    std::vector<uint8_t> newIV;
    if (_iv.size() == 0) {
        // When no IV was specified manually, always create a new IV when
        // calling buildEncryptor()
        newIV = utility::cryptoRandomBytes(getDefaultIVLength(_mode));
    }
    const std::vector<uint8_t> &iv = (_iv.size() == 0) ? newIV : _iv;

    auto cipher = new AESCipher{
            _mode, _keySize, _padding, _secretKey, iv, AESCipher::Operation::Encryption};
    return std::unique_ptr<AESCipher>(cipher);
}

std::unique_ptr<AESCipher> AESCipherBuilder::buildDecryptor()
{
    if (isAuthenticatedCipherMode(_mode)) {
        throw MoCOCrWException(
                "Specified cipher supports authenticated encryption."
                " buildAuthenticatedDecryptor() should be used instead.");
    }
    auto cipher = new AESCipher{
            _mode, _keySize, _padding, _secretKey, _iv, AESCipher::Operation::Decryption};
    return std::unique_ptr<AESCipher>(cipher);
}

std::unique_ptr<AuthenticatedAESCipher> AESCipherBuilder::buildAuthenticatedEncryptor()
{
    if (!isAuthenticatedCipherMode(_mode)) {
        throw MoCOCrWException(
                "Specified cipher does not support authenticated encryption."
                " buildEncryptor() should be used instead.");
    }

    std::vector<uint8_t> newIV;
    if (_iv.size() == 0) {
        // When no IV was specified manually, always create a new IV when
        // calling buildAuthenticatedEncryptor()
        newIV = utility::cryptoRandomBytes(getDefaultIVLength(_mode));
    }
    const std::vector<uint8_t> &iv = (_iv.size() == 0) ? newIV : _iv;

    auto cipher = new AuthenticatedAESCipher(_mode,
                                             _keySize,
                                             _padding,
                                             _secretKey,
                                             iv,
                                             _authTagLength,
                                             AESCipher::Operation::Encryption);
    return std::unique_ptr<AuthenticatedAESCipher>(cipher);
}

std::unique_ptr<AuthenticatedAESCipher> AESCipherBuilder::buildAuthenticatedDecryptor()
{
    if (!isAuthenticatedCipherMode(_mode)) {
        throw MoCOCrWException(
                "Specified cipher does not support authenticated encryption."
                " buildDecryptor() should be used instead.");
    }
    if (_authTagLength != DefaultAuthTagLength) {
        throw MoCOCrWException(
                "It does not make sense to set length of the authentication tag"
                " for a decryptor. This setting will be ignored and will confuse"
                " reader of your code.");
    }
    auto cipher = new AuthenticatedAESCipher(_mode,
                                             _keySize,
                                             _padding,
                                             _secretKey,
                                             _iv,
                                             _authTagLength,
                                             AESCipher::Operation::Decryption);
    return std::unique_ptr<AuthenticatedAESCipher>(cipher);
}

}  // namespace mococrw
