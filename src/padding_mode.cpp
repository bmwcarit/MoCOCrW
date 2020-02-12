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

#include <boost/variant.hpp>

#include <openssl/evp.h>

#include <tuple>

#include "mococrw/padding_mode.h"
#include "mococrw/hash.h"

namespace mococrw {

using namespace openssl;

using SSL_RSA_OAEP_LABEL_Ptr = std::unique_ptr<uint8_t, SSLFree<uint8_t>>;

/*
 * Interface Destructors
 */

RSAEncryptionPadding::~RSAEncryptionPadding() = default;
RSASignaturePadding::~RSASignaturePadding() = default;

/*
 * NoPadding
 */

bool NoPadding::checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const
{
    size_t keySizeInBit = key.getKeySize();
    return messageSize*8 == keySizeInBit;
}

void NoPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    openssl::_EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::NONE));
}

/*
 * PKCSPadding
 */

bool PKCSPadding::checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const
{
    int remainingSize = key.getKeySize() - PKCS_MAX_SIZE_OVERHEAD*8;
    return remainingSize > 0 && messageSize*8 <= static_cast<size_t>(remainingSize);
}

void PKCSPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::PKCS1));
}

void PKCSPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                                                 openssl::DigestTypes hashFunction) const
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::PKCS1));
    _EVP_PKEY_CTX_set_signature_md(ctx.get(), _getMDPtrFromDigestType(hashFunction));
}

/*
 * MGF1
 */

MGF1::MGF1(openssl::DigestTypes hashFunction) : _hashFunction(hashFunction) {}

void MGF1::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const {
    _EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(),
                                  _getMDPtrFromDigestType(_hashFunction));
}

MGF1::~MGF1() = default;

/*
 * PSSPadding
 */

class PSSPadding::Impl {
public:
    Impl(std::shared_ptr<MaskGenerationFunction> maskGenerationFunction, boost::optional<int> saltLength)
        : maskGenerationFunction(std::move(maskGenerationFunction)), saltLength(std::move(saltLength)) {}

    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, openssl::DigestTypes hashFunction) const {

        _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::PSS));
        _EVP_PKEY_CTX_set_signature_md(ctx.get(), _getMDPtrFromDigestType(hashFunction));

        int saltLength;
        if (this->saltLength != boost::none) {
            saltLength = *(this->saltLength);
        } else {
            saltLength = Hash::getDigestSize(hashFunction);
        }

        _EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), saltLength);

        if (maskGenerationFunction != nullptr) {
            maskGenerationFunction->prepareOpenSSLContext(ctx);
        } else {
            MGF1(hashFunction).prepareOpenSSLContext(ctx);
        }
    }

    std::shared_ptr<MaskGenerationFunction> maskGenerationFunction;
    boost::optional<int> saltLength;
};

PSSPadding::PSSPadding(std::shared_ptr<MaskGenerationFunction> maskGenerationFunction,
                       boost::optional<int> saltLength)
    : _impl(std::make_unique<PSSPadding::Impl>(maskGenerationFunction, std::move(saltLength)))
{}

PSSPadding::PSSPadding(const PSSPadding& other)
    : _impl(std::make_unique<PSSPadding::Impl>(*(other._impl))) {}

PSSPadding& PSSPadding::operator=(const PSSPadding& other) {
    _impl = std::make_unique<PSSPadding::Impl>(*(other._impl));
    return *this;
}

PSSPadding::~PSSPadding() = default;

void PSSPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx,
                                       openssl::DigestTypes hashFunction) const
{
    _impl->prepareOpenSSLContext(ctx, hashFunction);
}

/*
 * OAEPPadding
 */

class OAEPPadding::Impl {
public:
    Impl(openssl::DigestTypes hashFunction, std::shared_ptr<MaskGenerationFunction> maskGenerationFunction, const std::string& label)
        : hashFunction(hashFunction), label(label) {
        if (maskGenerationFunction != nullptr) {
            this->maskGenerationFunction = maskGenerationFunction;
        } else {
            this->maskGenerationFunction = std::make_shared<MGF1>(hashFunction);
        }
    }

    openssl::DigestTypes hashFunction;
    std::string label;
    std::shared_ptr<MaskGenerationFunction> maskGenerationFunction;
};

OAEPPadding::OAEPPadding(openssl::DigestTypes hashFunction, std::shared_ptr<MaskGenerationFunction> maskGenerationFunction, const std::string& label)
    : _impl(std::make_unique<OAEPPadding::Impl>(hashFunction, maskGenerationFunction, label)) {}

OAEPPadding::OAEPPadding(const OAEPPadding& other) : _impl(std::make_unique<OAEPPadding::Impl>(*(other._impl))) {}

OAEPPadding& OAEPPadding::operator=(const OAEPPadding& other) {
    _impl = std::make_unique<OAEPPadding::Impl>(*(other._impl));
    return *this;
}

OAEPPadding::~OAEPPadding() = default;

bool OAEPPadding::checkMessageSize(const AsymmetricPublicKey &key, size_t messageSize) const
{
    int remainingSize = key.getKeySize() -
            (2 * openssl::_EVP_MD_size(_getMDPtrFromDigestType(_impl->hashFunction)))*8 - 2*8;
    return remainingSize > 0 && messageSize*8 <= static_cast<size_t>(remainingSize);
}

void OAEPPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    SSL_RSA_OAEP_LABEL_Ptr label_copy{nullptr};

    try {
        _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::OAEP));

        _EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(),
                                      _getMDPtrFromDigestType(_impl->hashFunction));

        _impl->maskGenerationFunction->prepareOpenSSLContext(ctx);

        if (!_impl->label.empty()) {

            /* Make a copy of the label, since the context takes ownership of it when calling
             * '_EVP_PKEY_CTX_set_rsa_oaep_label()' function */
            label_copy.reset(static_cast<uint8_t *>(
                                     _OPENSSL_malloc(_impl->label.size())));
            memcpy(label_copy.get(),
                   _impl->label.data(), _impl->label.size());

            _EVP_PKEY_CTX_set_rsa_oaep_label(ctx.get(),
                                             static_cast<unsigned char *>(label_copy.get()),
                                             static_cast<int>(_impl->label.size()));

            /* Release ownership from the unique_ptr since the function above takes ownership of
             * the label pointer unless it throws an exception*/
            std::ignore = label_copy.release();
        }
    } catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
    }
}

}

