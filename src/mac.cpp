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

#include "mococrw/mac.h"
#include "mococrw/error.h"
#include "mococrw/openssl_wrap.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <boost/format.hpp>

namespace mococrw
{
MessageAuthenticationCode::~MessageAuthenticationCode() = default;

/* HMAC */

class HMAC::Impl
{
public:
    Impl(openssl::DigestTypes hashFunction, const std::vector<uint8_t> &key)
    {

        if (key.empty()) {
            throw MoCOCrWException("Key for HMAC is empty.");
        }

        openssl::OSSL_LIB_CTX_Ptr library_context = openssl::_OSSL_LIB_CTX_new();
        openssl::EVP_MAC_Ptr mac = openssl::_EVP_MAC_fetch(library_context.get(), "HMAC");

        _ctx = openssl::_EVP_MAC_CTX_new(mac.get());

        std::array<OSSL_PARAM, 4> ossl_params = openssl::_getOSSLParamFromDigestType(hashFunction);
        OSSL_PARAM params[4];
        std::copy(std::begin(ossl_params), std::end(ossl_params), std::begin(params));

        openssl::_EVP_MAC_init(_ctx.get(), key, params);

    }

    ~Impl() = default;

    Impl(Impl &&) = default;

    void update(const std::vector<uint8_t> &message)
    {
        if (_isFinished) {
            throw MoCOCrWException("update() can't be called after finish()");
        }
        openssl::_EVP_MAC_update(_ctx.get(), message);
    }

    std::vector<uint8_t> finish()
    {
        if (_isFinished) {
            throw MoCOCrWException("finish() can't be called twice.");
        }

        _sult = openssl::_EVP_MAC_final(_ctx.get());

        _isFinished = true;

        return _result;
    }

    void verify(const std::vector<uint8_t> &hmacValue)
    {
        if (!_isFinished) {
            finish();
        }

        if (hmacValue.size() != _result.size()) {
            throw MoCOCrWException("HMAC verification failed. Length differs.");
        }

        if (CRYPTO_memcmp(hmacValue.data(), _result.data(), hmacValue.size())) {
            throw MoCOCrWException(
                    "HMAC verification failed. Calculated value: " + utility::toHex(_result) +
                    ". Received value: " + utility::toHex(hmacValue));
        }
    }

private:
    openssl::EVP_MAC_CTX_Ptr _ctx = nullptr;
    bool _isFinished = false;
    std::vector<uint8_t> _result;
};

HMAC::HMAC(mococrw::openssl::DigestTypes hashFunction, const std::vector<uint8_t> &key)
{
    _impl = std::make_unique<HMAC::Impl>(hashFunction, key);
}

HMAC::~HMAC() = default;

HMAC::HMAC(HMAC &&other) = default;

HMAC &HMAC::operator=(HMAC &&other) = default;

void HMAC::update(const std::vector<uint8_t> &message) { _impl->update(message); }

std::vector<uint8_t> HMAC::finish() { return _impl->finish(); }

void HMAC::verify(const std::vector<uint8_t> &hmacValue) { _impl->verify(hmacValue); }

/* CMAC */

class CMAC::Impl
{
public:
    Impl(openssl::CmacCipherTypes cipherType, const std::vector<uint8_t> &key)
    {
        const EVP_CIPHER *cipher = openssl::_getCipherPtrFromCmacCipherType(cipherType);

        size_t expectedKeySize = openssl::_EVP_CIPHER_key_length(cipher);
        if (key.size() != expectedKeySize) {
            auto cipherName = openssl::_EVP_CIPHER_name(cipher);
            auto formatter = boost::format(
                    "Invalid key size for %s: Expected %d bytes but got key with %d bytes.");
            formatter % cipherName % expectedKeySize % key.size();
            throw MoCOCrWException(formatter.str());
        }

        _ctx = openssl::_CMAC_CTX_new();
        openssl::_CMAC_Init(_ctx.get(), key, cipher, nullptr);
    }

    ~Impl() = default;

    Impl(Impl &&) = default;

    void update(const std::vector<uint8_t> &message)
    {
        if (_isFinished) {
            throw MoCOCrWException("update() can't be called after finish()");
        }
        openssl::_CMAC_Update(_ctx.get(), message);
    }

    std::vector<uint8_t> finish()
    {
        if (_isFinished) {
            throw MoCOCrWException("finish() can't be called twice.");
        }

        _result = openssl::_CMAC_Final(_ctx.get());

        _isFinished = true;

        return _result;
    }

    void verify(const std::vector<uint8_t> &cmacValue)
    {
        if (!_isFinished) {
            finish();
        }

        if (cmacValue.size() != _result.size()) {
            throw MoCOCrWException("CMAC verification failed. Length differs.");
        }

        if (CRYPTO_memcmp(cmacValue.data(), _result.data(), cmacValue.size())) {
            throw MoCOCrWException(
                    "CMAC verification failed. Calculated value: " + utility::toHex(_result) +
                    ". Received value: " + utility::toHex(cmacValue));
        }
    }

private:
    openssl::SSL_CMAC_CTX_Ptr _ctx = nullptr;
    bool _isFinished = false;
    std::vector<uint8_t> _result;
};

CMAC::CMAC(mococrw::openssl::CmacCipherTypes cipherType, const std::vector<uint8_t> &key)
        : _impl(std::make_unique<CMAC::Impl>(cipherType, key))
{
}

CMAC::~CMAC() = default;

CMAC::CMAC(CMAC &&other) = default;

CMAC &CMAC::operator=(CMAC &&other) = default;

void CMAC::update(const std::vector<uint8_t> &message) { _impl->update(message); }

std::vector<uint8_t> CMAC::finish() { return _impl->finish(); }

void CMAC::verify(const std::vector<uint8_t> &cmacValue) { _impl->verify(cmacValue); }

}  // namespace mococrw
