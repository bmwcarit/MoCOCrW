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
#include "mococrw/signature.h"

#include "mococrw/error.h"
#include "mococrw/hash.h"
#include "mococrw/padding_mode.h"

namespace mococrw {

using namespace openssl;

// ECC
void SignatureUtils::setUpContext(EVP_PKEY_CTX *ctx,
                                  const OperationType &operation,
                                  const DigestTypes &digestType)
{
    if (operation == OperationType::Sign) {
        _EVP_PKEY_sign_init(ctx);
    } else {
        _EVP_PKEY_verify_init(ctx);
    }

    _EVP_PKEY_CTX_set_signature_md(ctx, _getMDPtrFromDigestType(digestType));
}

// RSA
void SignatureUtils::setUpContext(EVP_PKEY_CTX *ctx,
                                  const RSAPadding &padding,
                                  const OperationType &operation)
{
    if (operation == OperationType::Sign) {
        _EVP_PKEY_sign_init(ctx);
    } else {
        _EVP_PKEY_verify_init(ctx);
    }

    _EVP_PKEY_CTX_set_rsa_padding(ctx, static_cast<int>(padding.getPadding()));
    _EVP_PKEY_CTX_set_signature_md(ctx, _getMDPtrFromDigestType(getHashing(padding)));

    if (RSAPaddingMode::PSS == padding.getPadding()) {
        const auto padPSS = static_cast<const PSSPadding &>(padding);
        _EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, padPSS.getSaltLength());
        _EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, _getMDPtrFromDigestType(padPSS.getMaskingFunction()));
    }
}

void SignatureUtils::create(EVP_PKEY_CTX *ctx,
                            const std::vector<uint8_t> &messageDigest,
                            std::vector<uint8_t> &signedMessage)
{
    std::unique_ptr<unsigned char, SSLFree<unsigned char>> sig;
    size_t siglen;

    // This determines the buffer length
    _EVP_PKEY_sign(ctx,
                   nullptr,
                   &siglen,
                   reinterpret_cast<const unsigned char *>(messageDigest.data()),
                   messageDigest.size());

    sig.reset(static_cast<unsigned char *>(_OPENSSL_malloc(siglen)));
    _EVP_PKEY_sign(ctx,
                   sig.get(),
                   &siglen,
                   reinterpret_cast<const unsigned char *>(messageDigest.data()),
                   messageDigest.size());

    signedMessage = std::vector<uint8_t>(sig.get(), sig.get() + siglen);
}

void SignatureUtils::verify(EVP_PKEY_CTX *ctx,
                            const std::vector<uint8_t> &signature,
                            const std::vector<uint8_t> &messageDigest)
{
    _EVP_PKEY_verify(ctx,
                     reinterpret_cast<const unsigned char *>(signature.data()),
                     signature.size(),
                     reinterpret_cast<const unsigned char *>(messageDigest.data()),
                     messageDigest.size());
}

/*********************************** ECC specialization  ***********************************/
std::vector<uint8_t> SignatureUtils::ECC::create(AsymmetricPrivateKey &privateKey,
                                                 const DigestTypes &digestType,
                                                 const std::vector<uint8_t> &messageDigest)
{
    std::vector<uint8_t> signedMessage;

    try {
        const auto keyCtx = _EVP_PKEY_CTX_new(privateKey.internal());

        if (!keyCtx.get()) {
            throw MoCOCrWException("Context is empty");
        }

        SignatureUtils::setUpContext(keyCtx.get(), OperationType::Sign, digestType);
        SignatureUtils::create(keyCtx.get(), messageDigest, signedMessage);
    }
    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }

    return signedMessage;
}

void SignatureUtils::ECC::verify(AsymmetricPublicKey &publicKey,
                                 const std::vector<uint8_t> &signature,
                                 const DigestTypes &digestType,
                                 const std::vector<uint8_t> &messageDigest)
{
    try {
        const auto keyCtx = _EVP_PKEY_CTX_new(publicKey.internal());

        if (!keyCtx.get()) {
            throw MoCOCrWException("Context is empty");
        }

        SignatureUtils::setUpContext(keyCtx.get(), OperationType::Verify, digestType);
        SignatureUtils::verify(keyCtx.get(), signature, messageDigest);
    }
    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }
}

void SignatureUtils::ECC::verify(const X509Certificate &certificate,
                                 const std::vector<uint8_t> &signature,
                                 const DigestTypes &digestType,
                                 const std::vector<uint8_t> &messageDigest)
{
    auto key = certificate.getPublicKey();
    verify(key, signature, digestType, messageDigest);
}

/*********************************** RSA specialization  ***********************************/
std::vector<uint8_t> SignatureUtils::RSA::create(AsymmetricPrivateKey &privateKey,
                                                 const RSAPadding &padding,
                                                 const std::vector<uint8_t> &messageDigest)
{
    std::vector<uint8_t> signedMessage;

    if (privateKey.getType() != AsymmetricKey::KeyTypes::RSA) {
        throw MoCOCrWException("Functionality is only supported for RSA keys");
    }

    try {
        const auto keyCtx = _EVP_PKEY_CTX_new(privateKey.internal());

        if (!keyCtx.get()) {
            throw MoCOCrWException("Context is empty");
        }
        SignatureUtils::setUpContext(keyCtx.get(), padding, OperationType::Sign);
        SignatureUtils::create(keyCtx.get(), messageDigest, signedMessage);
    }
    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }

    return signedMessage;
}

void SignatureUtils::RSA::verify(AsymmetricPublicKey &publicKey,
                                 const RSAPadding &padding,
                                 const std::vector<uint8_t> &signature,
                                 const std::vector<uint8_t> &messageDigest)
{
    if(publicKey.getType() != AsymmetricKey::KeyTypes::RSA){
        throw MoCOCrWException("Functionality is only supported for RSA keys");
    }

    try {
        const auto keyCtx = _EVP_PKEY_CTX_new(publicKey.internal());

        if (!keyCtx.get()) {
            throw MoCOCrWException("Context is empty");
        }

        SignatureUtils::setUpContext(keyCtx.get(), padding, OperationType::Verify);
        SignatureUtils::verify(keyCtx.get(), signature, messageDigest);
    }

    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }
}

void SignatureUtils::RSA::verify(const X509Certificate &certificate,
                                 const RSAPadding &padding,
                                 const std::vector<uint8_t> &signature,
                                 const std::vector<uint8_t> &messageDigest)
{
    auto key = certificate.getPublicKey();
    verify(key, padding, signature, messageDigest);
}

DigestTypes SignatureUtils::getHashing(const RSAPadding &padding)
{
    const auto paddingMode = padding.getPadding();

    switch (paddingMode) {
    case RSAPaddingMode::PKCS1: {
        const auto pad = static_cast<const PKCSPadding &>(padding);
        return pad.getHashingFunction();
    }
    case RSAPaddingMode::PSS: {
        const auto pad = static_cast<const PSSPadding &>(padding);
        return pad.getHashingFunction();
    }
    default:
        throw MoCOCrWException("Padding mode not supported");
    }
}
} // namespace mococrw
