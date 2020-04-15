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

#include <openssl/hmac.h>
#include <openssl/crypto.h>

namespace mococrw
{

MessageAuthenticationCode::~MessageAuthenticationCode() = default;

class HMAC::Impl
{
public:
    Impl(openssl::DigestTypes hashFunction, const std::vector<uint8_t> &key)
    {
        const EVP_MD* digestFn = _getMDPtrFromDigestType(hashFunction);

        if (key.empty()) {
            throw MoCOCrWException("Key for HMAC is empty.");
        }

        _ctx = openssl::_HMAC_CTX_new();
        openssl::_HMAC_Init_ex(_ctx.get(), key, digestFn, NULL);
    }

    ~Impl() = default;

    Impl(Impl&&) = default;

    void update(const std::vector<uint8_t> &message)
    {
        if (_isFinished) {
            throw MoCOCrWException("update() can't be called after finish()");
        }
        openssl::_HMAC_Update(_ctx.get(), message);
    }

    std::vector<uint8_t> finish()
    {
        if (_isFinished) {
            throw MoCOCrWException("finish() can't be called twice.");
        }

        _result = openssl::_HMAC_Final(_ctx.get());

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
            throw MoCOCrWException("HMAC verification failed. Calculated value: " + utility::toHex(_result)
                                   + ". Received value: " + utility::toHex(hmacValue));
        }
    }

private:
    openssl::SSL_HMAC_CTX_SharedPtr _ctx = nullptr;
    bool _isFinished = false;
    std::vector<uint8_t> _result;
};

HMAC::HMAC(mococrw::openssl::DigestTypes hashFunction, const std::vector<uint8_t> &key)
{
    _impl = std::make_unique<HMAC::Impl>(hashFunction, key);
}

HMAC::~HMAC() = default;

HMAC::HMAC(HMAC&& other) = default;

HMAC& HMAC::operator=(HMAC&& other) {
    this->_impl = std::move(other._impl);
    return *this;
}

void HMAC::update(const std::vector<uint8_t> &message)
{
    _impl->update(message);
}

std::vector<uint8_t> HMAC::finish()
{
    return _impl->finish();
}

void HMAC::verify(const std::vector<uint8_t> &hmacValue)
{
    _impl->verify(hmacValue);
}

}
