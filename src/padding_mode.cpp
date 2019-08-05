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
 * Helper
 */

class PrepareOpenSSLContextVisitor {
public:
    PrepareOpenSSLContextVisitor(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) : ctx(ctx) {}

    void operator()(const MGF1& m) const {
        m.prepareOpenSSLContext(ctx);
    }

    openssl::SSL_EVP_PKEY_CTX_Ptr& ctx;
};

/*
 * NoPadding
 */

int NoPadding::getDataBlockSize(const AsymmetricPublicKey &key) const
{
    return key.getKeySize()/8;
}

void NoPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    openssl::_EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::NONE));
}

/*
 * PKCSEncryptionPadding
 */

void PKCSEncryptionPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::PKCS1));
}

int PKCSEncryptionPadding::getDataBlockSize(const AsymmetricPublicKey &key) const
{
    return key.getKeySize()/8 - c_pkcsMaxSizeSOverhead;
}

/*
 * RSASignaturePadding
 */

RSASignaturePadding::RSASignaturePadding(openssl::DigestTypes hashFunction) : _hashFunction(hashFunction) {}

openssl::DigestTypes RSASignaturePadding::getHashFunction() const
{
    return _hashFunction;
}

/*
 * PKCSSignaturePadding
 */

PKCSSignaturePadding::PKCSSignaturePadding(openssl::DigestTypes hashFunction)
        : RSASignaturePadding(hashFunction)
{
}

void PKCSSignaturePadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::PKCS1));
    _EVP_PKEY_CTX_set_signature_md(ctx.get(), _getMDPtrFromDigestType(_hashFunction));
}

/*
 * MGF1
 */

MGF1::MGF1(openssl::DigestTypes hashFunction) : _hashFunction(hashFunction) {}

void MGF1::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const {
    _EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(),
                                  _getMDPtrFromDigestType(_hashFunction));
}

/*
 * PSSPadding
 */

class PSSPadding::Impl {
public:
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const {
        boost::apply_visitor(PrepareOpenSSLContextVisitor(ctx), this->maskingFunction);
    }

    int saltLength;
    boost::variant<MGF1> maskingFunction;
};

PSSPadding::PSSPadding(openssl::DigestTypes hashFunction,
                       boost::optional<MGF1> maskGenerationFunction,
                       boost::optional<int> saltLength)
    : RSASignaturePadding(hashFunction),
     _impl(std::make_unique<PSSPadding::Impl>())
{
    if (maskGenerationFunction != boost::none) {
        _impl->maskingFunction = *maskGenerationFunction;
    } else {
        _impl->maskingFunction = MGF1(hashFunction);
    }

    if (saltLength != boost::none) {
        _impl->saltLength = *saltLength;
    } else {
        _impl->saltLength = Hash::getDigestSize(hashFunction);
    }
}

PSSPadding::PSSPadding(const PSSPadding& other)
    : RSASignaturePadding(other._hashFunction),
    _impl(std::make_unique<PSSPadding::Impl>(*(other._impl))) {}

PSSPadding& PSSPadding::operator=(const PSSPadding& other) {
    _hashFunction = other._hashFunction;
    _impl = std::make_unique<PSSPadding::Impl>(*(other._impl));
    return *this;
}

PSSPadding::~PSSPadding() = default;

void PSSPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::PSS));
    _EVP_PKEY_CTX_set_signature_md(ctx.get(), _getMDPtrFromDigestType(_hashFunction));
    _EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), _impl->saltLength);
    _impl->prepareOpenSSLContext(ctx);
}

/*
 * OAEPPadding
 */

class OAEPPadding::Impl {
public:
    Impl(openssl::DigestTypes hashFunction, const std::string& label) : hashFunction(hashFunction), label(label) {}
    void prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx) const {
        boost::apply_visitor(PrepareOpenSSLContextVisitor(ctx), this->maskingFunction);
    }

    openssl::DigestTypes hashFunction;
    std::string label;
    boost::variant<MGF1> maskingFunction;
};

OAEPPadding::OAEPPadding(openssl::DigestTypes hashFunction, boost::optional<MGF1> maskGenerationFunction, const std::string& label)
    : _impl(std::make_unique<OAEPPadding::Impl>(hashFunction, label))
{
    if (maskGenerationFunction != boost::none) {
        _impl->maskingFunction = *maskGenerationFunction;
    } else {
        _impl->maskingFunction = MGF1(hashFunction);
    }
}

OAEPPadding::OAEPPadding(const OAEPPadding& other) : _impl(std::make_unique<OAEPPadding::Impl>(*(other._impl))) {}

OAEPPadding& OAEPPadding::operator=(const OAEPPadding& other) {
    _impl = std::make_unique<OAEPPadding::Impl>(*(other._impl));
    return *this;
}

OAEPPadding::~OAEPPadding() = default;

int OAEPPadding::getDataBlockSize(const AsymmetricPublicKey &key) const
{
    return key.getKeySize()/8 -
            (2 * openssl::_EVP_MD_size(_getMDPtrFromDigestType(_impl->hashFunction))) - 2;
}

void OAEPPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx)
{
    SSL_RSA_OAEP_LABEL_Ptr label_copy{nullptr};

    try {
        _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(openssl::RSAPaddingMode::OAEP));

        _EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(),
                                      _getMDPtrFromDigestType(_impl->hashFunction));

        _impl->prepareOpenSSLContext(ctx);

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

