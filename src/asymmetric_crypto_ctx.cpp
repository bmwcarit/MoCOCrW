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

#include "mococrw/asymmetric_crypto_ctx.h"

namespace mococrw {

    using namespace openssl;

    using SSL_RSA_ENCRYPTION_DATA_Ptr = std::unique_ptr<unsigned char, SSLFree<unsigned char>>;

    using SSL_SIGNATURE_DATA_Ptr = std::unique_ptr<unsigned char, SSLFree<unsigned char>>;

    std::vector<uint8_t> AsymmetricPubkeyCtx::encrypt(const std::vector<uint8_t>& message)
    {
        SSL_RSA_ENCRYPTION_DATA_Ptr encryptedMessage{nullptr};
        size_t encryptedMessageLen{0};

        if(getKeyType() != AsymmetricKey::KeyTypes::RSA){
            throw mococrw::MoCOCrWException("Asymmetric encryption only supports RSA keys");
        }
        else if (_paddingMode == nullptr){
            throw mococrw::MoCOCrWException("When using a RSA key the RSAPadding context "
                                            "member needs to be set");
        }

        try {
            if (!_paddingMode->isOperationSupported(OperationTypes::Encrypt)){
                throw MoCOCrWException("Unsupported padding mode");
            }

            auto keyCtx = _EVP_PKEY_CTX_new(_publicKey.internal());
            if (!keyCtx.get()) {
                throw MoCOCrWException("Encryption context is empty");
            }

            int maxSize{_paddingMode->getDataBlockSize(_publicKey)};
            /* Validate message size when not using padding*/
            if (_paddingMode->getPadding() == RSAPaddingMode::NONE &&
                maxSize != static_cast<int>(message.size())){
                throw MoCOCrWException("Message size is different from the key size");
            }
            /* Validate message size */
            if (static_cast<int>(message.size()) > maxSize) {
                throw MoCOCrWException("Message too long for RSA key size");
            }

            _EVP_PKEY_encrypt_init(keyCtx.get());
            _paddingMode->prepareOpenSSLContext(keyCtx, OperationTypes::Encrypt);

            /* First call to determine the buffer length */
            _EVP_PKEY_encrypt(keyCtx.get(),
                              nullptr,
                              &encryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

            /* Allocate memory for the buffer, based on the size returned by _EVP_PKEY_encrypt */
            encryptedMessage.reset(static_cast<unsigned char*>(
                                           _OPENSSL_malloc(static_cast<int>(encryptedMessageLen))));

            /* Second call to perform the actual encryption */
            _EVP_PKEY_encrypt(keyCtx.get(),
                              encryptedMessage.get(),
                              &encryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

        } catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }

        return std::vector<uint8_t>(encryptedMessage.get(), encryptedMessage.get() + encryptedMessageLen);
    }

    void AsymmetricPubkeyCtx::verify(const std::vector<uint8_t> &signature,
                                      const std::vector<uint8_t> &messageDigest)
    {
        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_publicKey.internal());
            _EVP_PKEY_verify_init(keyCtx.get());

            _setupSignatureOpenSSLCtx(keyCtx, OperationTypes::Verify);

            _EVP_PKEY_verify(keyCtx.get(),
                             reinterpret_cast<const unsigned char *>(signature.data()),
                             signature.size(),
                             reinterpret_cast<const unsigned char *>(messageDigest.data()),
                             messageDigest.size());
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }

    std::vector<uint8_t> AsymmetricPrivkeyCtx::decrypt(const std::vector<uint8_t>& message)
    {
        size_t decryptedMessageLen{0};
        SSL_RSA_ENCRYPTION_DATA_Ptr decryptedMessage{nullptr};

        if (getKeyType() != AsymmetricKey::KeyTypes::RSA){
            throw MoCOCrWException("Asymmetric decryption is only supported for RSA Keys");
        }
        else if (_paddingMode == nullptr){
            throw mococrw::MoCOCrWException("When using a RSA key the RSAPadding context "
                                            "member needs to be set");
        }

        try {
            if (!_paddingMode->isOperationSupported(OperationTypes::Decrypt)){
                throw MoCOCrWException("Unsupported padding mode");
            }
            auto keyCtx = _EVP_PKEY_CTX_new(_keyPair.internal());
            _EVP_PKEY_decrypt_init(keyCtx.get());

            /* Preform padding specific configurations*/
            _paddingMode->prepareOpenSSLContext(keyCtx, OperationTypes::Decrypt);

            /* First call to determine the buffer length */
            _EVP_PKEY_decrypt(keyCtx.get(), nullptr, &decryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

            decryptedMessage.reset(static_cast<unsigned char*>(
                                           _OPENSSL_malloc(static_cast<int>(decryptedMessageLen))));

            /* Second call to perform the actual decryption */
            _EVP_PKEY_decrypt(keyCtx.get(), decryptedMessage.get(), &decryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

        } catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }

        return std::vector<uint8_t>(decryptedMessage.get(), decryptedMessage.get() + decryptedMessageLen);
    }

    std::vector<uint8_t> AsymmetricPrivkeyCtx::sign(const std::vector<uint8_t> &messageDigest)
    {
        size_t sigLen;
        SSL_SIGNATURE_DATA_Ptr signatureData;

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_keyPair.internal());
            _EVP_PKEY_sign_init(keyCtx.get());

            _setupSignatureOpenSSLCtx(keyCtx, OperationTypes::Sign);

            // This determines the buffer length
            _EVP_PKEY_sign(keyCtx.get(),
                           nullptr,
                           &sigLen,
                           reinterpret_cast<const unsigned char *>(messageDigest.data()),
                           messageDigest.size());

            signatureData.reset(static_cast<unsigned char *>(_OPENSSL_malloc(sigLen)));
            _EVP_PKEY_sign(keyCtx.get(),
                           signatureData.get(),
                           &sigLen,
                           reinterpret_cast<const unsigned char *>(messageDigest.data()),
                           messageDigest.size());

        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }

        return std::vector<uint8_t>(signatureData.get(), signatureData.get() + sigLen);
    }

    void AsymmetricCryptoCtx::_setupSignatureOpenSSLCtx(openssl::SSL_EVP_PKEY_CTX_Ptr &keyCtx,
                                                        const OperationTypes &op)
    {
        if (getKeyType() == AsymmetricKey::KeyTypes::RSA){
            if (_paddingMode == nullptr){
                throw mococrw::MoCOCrWException("When using a RSA key the RSAPadding context "
                                                "member needs to be set");
            }
            _paddingMode->prepareOpenSSLContext(keyCtx, op);
        }
        else if (getKeyType() == AsymmetricKey::KeyTypes::ECC){
            _EVP_PKEY_CTX_set_signature_md(keyCtx.get(),
                                           _getMDPtrFromDigestType(_eccMd));
        }
        else{
            throw MoCOCrWException("Asymmetric Key type Unsupported. Only ECC and RSA supported.");
        }
    }

    AsymmetricCryptoCtx::Builder& AsymmetricCryptoCtx::Builder::rsaPaddingMode(
            std::unique_ptr<RSAPadding> const& rsaPaddingMode)
    {
        _paddingMode = rsaPaddingMode->clone();
        return *this;
    }

    AsymmetricCryptoCtx::Builder& AsymmetricCryptoCtx::Builder::rsaPaddingMode(
            std::unique_ptr<RSAPadding>&& rsaPaddingMode)
    {
        _paddingMode = std::move(rsaPaddingMode);
        return *this;
    }

    AsymmetricCryptoCtx::Builder& AsymmetricCryptoCtx::Builder::eccMaskingFunction(
            openssl::DigestTypes const& eccMaskingFunction)
    {
        _eccMd = eccMaskingFunction;
        return *this;
    }

    AsymmetricPubkeyCtx AsymmetricCryptoCtx::Builder::build(const AsymmetricPublicKey& publicKey)
    {
        AsymmetricPubkeyCtx ctx(publicKey);
        _buildHelper(ctx);
        return ctx;
    }

    AsymmetricPubkeyCtx AsymmetricCryptoCtx::Builder::build(const X509Certificate& certificate)
    {
        return build(certificate.getPublicKey());
    }

    AsymmetricPrivkeyCtx AsymmetricCryptoCtx::Builder::build(const AsymmetricPrivateKey& privateKey)
    {
        AsymmetricPrivkeyCtx ctx(privateKey);
        _buildHelper(ctx);
        return ctx;
    }

    void AsymmetricCryptoCtx::Builder::_buildHelper(AsymmetricCryptoCtx &ctx)
    {
        ctx.setEccHashingFunction(_eccMd);

        if (_paddingMode != nullptr && ctx.getKeyType() == AsymmetricKey::KeyTypes::RSA)
            ctx.setRsaPaddingMode(_paddingMode);
    }
}
