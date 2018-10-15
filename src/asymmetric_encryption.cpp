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
#include "mococrw/asymmetric_encryption.h"

#include <fstream>

#include "mococrw/error.h"
#include "mococrw/hash.h"
#include "mococrw/padding_mode.h"
#include "mococrw/util.h"

namespace mococrw {

using namespace openssl;

using SSL_RSA_OAEP_LABEL_Ptr = std::unique_ptr<uint8_t, SSLFree<uint8_t>>;

using SSL_RSA_ENCRYPTION_DATA_Ptr = std::unique_ptr<unsigned char, SSLFree<unsigned char>>;

AsymmetricEncryption::CryptoData::CryptoData(const std::string& data)
    : _data{data.begin(), data.end()}
{
}

AsymmetricEncryption::CryptoData::CryptoData(const std::vector<uint8_t>& data)
    : _data{data}
{
}

AsymmetricEncryption::CryptoData& AsymmetricEncryption::CryptoData::operator=(
                                                                    const std::vector<uint8_t>& data)
{
    _data=data;
    return *this;
}

AsymmetricEncryption::CryptoData& AsymmetricEncryption::CryptoData::operator=(
                                                                    const std::string& data)
{
    _data=std::vector<uint8_t>(data.begin(), data.end());
    return *this;
}

std::string AsymmetricEncryption::CryptoData::toString() const {
    return std::string(_data.begin(), _data.end());
}

std::vector<uint8_t> AsymmetricEncryption::CryptoData::toByteArray() const {
    return _data;
}

std::string AsymmetricEncryption::CryptoData::toHex() const {
    return utility::toHex(_data);
}

std::ostream& operator<<(std::ostream& os, const AsymmetricEncryption::CryptoData& data)
{
    os << data.toString();
    return os;
}

std::vector<uint8_t> AsymmetricEncryption::encrypt(AsymmetricPublicKey key,
                                                   const RSAPadding &pad,
                                                   const CryptoData& message)
{
    SSL_RSA_OAEP_LABEL_Ptr label_copy{nullptr};
    SSL_RSA_ENCRYPTION_DATA_Ptr encryptedMessage{nullptr};
    size_t encryptedMessageLen{0};
    int maxSize{0};

    try {
        const auto keyCtx = _EVP_PKEY_CTX_new(key.internal());

        const auto paddingMode = pad.getPadding();

        if (!keyCtx.get()) {
            throw MoCOCrWException("Encryption context is empty");
        }

        switch(paddingMode) {
            case RSAPaddingMode::PKCS1: {
                maxSize = RSA_size(key.internal()->pkey.rsa) - c_pkcsMaxSizeSubtract;
                break;
            }
            case RSAPaddingMode::OAEP: {
                const auto oaepPaddingMode = static_cast<const OAEPPadding&>(pad);
                maxSize = RSA_size(key.internal()->pkey.rsa) -
                (2 * _EVP_MD_size(_getMDPtrFromDigestType(oaepPaddingMode.getHashingFunction())) - 2);
                break;
            }
            case RSAPaddingMode::NONE: {
                maxSize = RSA_size(key.internal()->pkey.rsa);
                break;
            }
            default: throw MoCOCrWException("Unsupported encryption mode");
        }

        /* Validate message size */
        if (static_cast<int>(message.toByteArray().size()) > maxSize) {
            throw MoCOCrWException("Message too long for RSA key size");
        }
        _CRYPTO_malloc_init();
        _EVP_PKEY_encrypt_init(keyCtx.get());
        _EVP_PKEY_CTX_set_rsa_padding(keyCtx.get(), static_cast<int>(paddingMode));

        if (RSAPaddingMode::OAEP == paddingMode) {
            const auto oaepPaddingMode = static_cast<const OAEPPadding&>(pad);

            _EVP_PKEY_CTX_set_rsa_oaep_md(keyCtx.get(),
                                    _getMDPtrFromDigestType(oaepPaddingMode.getHashingFunction()));

            _EVP_PKEY_CTX_set_rsa_mgf1_md(keyCtx.get(),
                                    _getMDPtrFromDigestType(oaepPaddingMode.getMaskingFunction()));

            if(oaepPaddingMode.getLabel().size() > 0){

                /* Make a copy of the label, since the context takes ownership of it when calling
                 * '_EVP_PKEY_CTX_set_rsa_oaep_label()' function*/
                label_copy.reset(static_cast<uint8_t*>(
                                            _OPENSSL_malloc(oaepPaddingMode.getLabel().size())));
                memcpy(label_copy.get(),
                                &oaepPaddingMode.getLabel()[0], oaepPaddingMode.getLabel().size());

                _EVP_PKEY_CTX_set_rsa_oaep_label(keyCtx.get(),
                                             static_cast<unsigned char*>(label_copy.get()),
                                             static_cast<int>(oaepPaddingMode.getLabel().size()));

                /* Release ownership from the unique_ptr since the function above takes ownership of
                 * the label pointer unless it throws an exception. Unique_ptr should only keep
                 * ownership if an exception is thrown by _EVP_PKEY_CTX_set_rsa_oaep_label.*/
                label_copy.release();
            }
        }

        /* First call to determine the buffer length */
        _EVP_PKEY_encrypt(keyCtx.get(),
                          nullptr,
                          &encryptedMessageLen,
                          reinterpret_cast<const unsigned char *>(&message.toByteArray()[0]),
                          message.toByteArray().size());

        /* Allocate memory for the buffer, based on the size returned by _EVP_PKEY_encrypt */
        encryptedMessage.reset(static_cast<unsigned char*>(
                                        _OPENSSL_malloc(static_cast<int>(encryptedMessageLen))));

        /* Second call to perform the actual encryption */
        _EVP_PKEY_encrypt(keyCtx.get(),
                          encryptedMessage.get(),
                          &encryptedMessageLen,
                          reinterpret_cast<const unsigned char *>(&message.toByteArray()[0]),
                          message.toByteArray().size());

    } catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }

    return std::vector<uint8_t>(encryptedMessage.get(), encryptedMessage.get() + encryptedMessageLen);
}

AsymmetricEncryption::CryptoData AsymmetricEncryption::decrypt(AsymmetricPrivateKey key,
                                                               const RSAPadding &pad,
                                                               const std::vector<uint8_t>& message)
{
    size_t decryptedMessageLen{0};
    SSL_RSA_OAEP_LABEL_Ptr label_copy{nullptr};
    SSL_RSA_ENCRYPTION_DATA_Ptr decryptedMessage{nullptr};

    try {
        auto keyCtx = _EVP_PKEY_CTX_new(key.internal());
        const auto paddingMode = pad.getPadding();

        _CRYPTO_malloc_init();

        _EVP_PKEY_decrypt_init(keyCtx.get());
        _EVP_PKEY_CTX_set_rsa_padding(keyCtx.get(), static_cast<int>(paddingMode));

        if(openssl::RSAPaddingMode::OAEP == paddingMode) {
            const auto oaepPaddingMode = static_cast<const OAEPPadding&>(pad);

            _EVP_PKEY_CTX_set_rsa_oaep_md(keyCtx.get(),
                                    _getMDPtrFromDigestType(oaepPaddingMode.getHashingFunction()));

            _EVP_PKEY_CTX_set_rsa_mgf1_md(keyCtx.get(),
                                    _getMDPtrFromDigestType(oaepPaddingMode.getMaskingFunction()));

            if(oaepPaddingMode.getLabel().size() > 0){

                /* Make a copy of the label, since the context takes ownership of it when calling
                 * '_EVP_PKEY_CTX_set_rsa_oaep_label()' function */
                label_copy.reset(static_cast<uint8_t*>(
                                            _OPENSSL_malloc(oaepPaddingMode.getLabel().size())));
                memcpy(label_copy.get(),
                                &oaepPaddingMode.getLabel()[0], oaepPaddingMode.getLabel().size());

                _EVP_PKEY_CTX_set_rsa_oaep_label(keyCtx.get(),
                                             static_cast<unsigned char*>(label_copy.get()),
                                             static_cast<int>(oaepPaddingMode.getLabel().size()));

                /* Release ownership from the unique_ptr since the function above takes ownership of
                 * the label pointer unless it throws an exception*/
                label_copy.release();
            }

        }

        /* First call to determine the buffer length */
        _EVP_PKEY_decrypt(keyCtx.get(), nullptr, &decryptedMessageLen,
                          reinterpret_cast<const unsigned char *>(&message[0]),
                          message.size());

        decryptedMessage.reset(static_cast<unsigned char*>(
                                        _OPENSSL_malloc(static_cast<int>(decryptedMessageLen))));

        /* Second call to perform the actual decryption */
        _EVP_PKEY_decrypt(keyCtx.get(), decryptedMessage.get(), &decryptedMessageLen,
                          reinterpret_cast<const unsigned char *>(&message[0]),
                          message.size());

    } catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }

    return std::vector<uint8_t>(decryptedMessage.get(), decryptedMessage.get() + decryptedMessageLen);
}

} // namespace mococrw
