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

std::vector<uint8_t> SignatureUtils::create(AsymmetricPrivateKey &privateKey,
                                            const RSAPadding &padding,
                                            const std::string message)
{
    std::vector<uint8_t> messageDigest;

    if(privateKey.getType() != AsymmetricKey::KeyTypes::RSA){
        throw MoCOCrWException("Functionality is only supported for RSA keys");
    }

    try {
        messageDigest = digestMessage(message, getHashing(padding));
    }
    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }

    return create(privateKey, padding, messageDigest);
}

std::vector<uint8_t> SignatureUtils::create(AsymmetricPrivateKey &privateKey,
                                            const RSAPadding &padding,
                                            std::vector<uint8_t> messageDigest)
{
    std::vector<uint8_t> signature;
    const auto keyCtx = _EVP_PKEY_CTX_new(privateKey.internal());
    std::unique_ptr<unsigned char, SSLFree<unsigned char>> sig;
    size_t siglen;

    if(privateKey.getType() != AsymmetricKey::KeyTypes::RSA){
        throw MoCOCrWException("Functionality is only supported for RSA keys");
    }

    try {
        if (!keyCtx.get()) {
            throw MoCOCrWException("Context is empty");
        }
        _EVP_PKEY_sign_init(keyCtx.get());
        setUpContext(keyCtx.get(), padding);

        // This determines the buffer length
        _EVP_PKEY_sign(keyCtx.get(),
                       nullptr,
                       &siglen,
                       reinterpret_cast<const unsigned char *>(messageDigest.data()),
                       messageDigest.size());

        _CRYPTO_malloc_init();
        sig.reset(static_cast<unsigned char *>(_OPENSSL_malloc(siglen)));
        _EVP_PKEY_sign(keyCtx.get(),
                       sig.get(),
                       &siglen,
                       reinterpret_cast<const unsigned char *>(messageDigest.data()),
                       messageDigest.size());
    }
    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }

    return std::vector<uint8_t>(sig.get(), sig.get() + siglen);
}

void SignatureUtils::verify(AsymmetricPublicKey &publicKey,
                            const RSAPadding &padding,
                            const std::vector<uint8_t> signature,
                            const std::string message)
{
    std::vector<uint8_t> messageDigest;

    if(publicKey.getType() != AsymmetricKey::KeyTypes::RSA){
        throw MoCOCrWException("Functionality is only supported for RSA keys");
    }

    try {
        messageDigest = digestMessage(message, getHashing(padding));
        verify(publicKey, padding, signature, messageDigest);
    }
    catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }
}

void SignatureUtils::verify(AsymmetricPublicKey &publicKey,
                            const RSAPadding &padding,
                            const std::vector<uint8_t> signature,
                            const std::vector<uint8_t> messageDigest)
{
    const auto keyCtx = _EVP_PKEY_CTX_new(publicKey.internal());

    if(publicKey.getType() != AsymmetricKey::KeyTypes::RSA){
        throw MoCOCrWException("Functionality is only supported for RSA keys");
    }

    try {
        _EVP_PKEY_verify_init(keyCtx.get());
        setUpContext(keyCtx.get(), padding);

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

void SignatureUtils::verify(const X509Certificate &certificate,
                            const RSAPadding &padding,
                            const std::vector<uint8_t> signature,
                            const std::string message)
{
    auto key = certificate.getPublicKey();
    verify(key, padding, signature, message);
}

void SignatureUtils::verify(const X509Certificate &certificate,
                            const RSAPadding &padding,
                            const std::vector<uint8_t> signature,
                            const std::vector<uint8_t> messageDigest)
{
    auto key = certificate.getPublicKey();
    verify(key, padding, signature, messageDigest);
}

std::vector<uint8_t> SignatureUtils::digestMessage(const std::string message,
                                                   DigestTypes algorithm)
{
    switch (algorithm) {
    case DigestTypes::SHA256:
        return sha256(reinterpret_cast<const uint8_t *>(message.c_str()),
                      reinterpret_cast<size_t>(message.length()));
    case DigestTypes::SHA512:
        return sha512(reinterpret_cast<const uint8_t *>(message.c_str()),
                      reinterpret_cast<size_t>(message.length()));
    default:
        throw MoCOCrWException("Unknown digest type");
    }
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

void SignatureUtils::setUpContext(EVP_PKEY_CTX *ctx, const RSAPadding &padding)
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx, static_cast<int>(padding.getPadding()));
    _EVP_PKEY_CTX_set_signature_md(ctx, _getMDPtrFromDigestType(getHashing(padding)));

    if (RSAPaddingMode::PSS == padding.getPadding()) {
        const auto padPSS = static_cast<const PSSPadding &>(padding);
        _EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, padPSS.getSaltLength());
        _EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, _getMDPtrFromDigestType(padPSS.getMaskingFunction()));
    }
}

} // namespace mococrw
