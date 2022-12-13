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
#include "mococrw/kdf.h"
#include "mococrw/openssl_wrap.h"

namespace mococrw
{
KeyDerivationFunction::~KeyDerivationFunction() = default;

class PBKDF2::Impl
{
public:
    Impl(openssl::DigestTypes hashFunction, uint32_t iterations)
            : _hashFunction(hashFunction), _iterations(iterations)
    {
    }

    ~Impl() = default;

    std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password,
                                   const size_t outputLength,
                                   const std::vector<uint8_t> &salt)
    {
        std::vector<uint8_t> derivedKey(outputLength);
        const EVP_MD *digestFn = openssl::_getMDPtrFromDigestType(_hashFunction);
        openssl::_PKCS5_PBKDF2_HMAC(password, salt, _iterations, digestFn, derivedKey);

        return derivedKey;
    }

private:
    openssl::DigestTypes _hashFunction;
    uint32_t _iterations;
};

PBKDF2::PBKDF2(openssl::DigestTypes hashFunction, uint32_t iterations)
{
    _impl = std::make_unique<PBKDF2::Impl>(hashFunction, iterations);
}

PBKDF2::~PBKDF2() = default;

std::vector<uint8_t> PBKDF2::deriveKey(const std::vector<uint8_t> &password,
                                       const size_t outputLength,
                                       const std::vector<uint8_t> &salt)
{
    return _impl->deriveKey(password, outputLength, salt);
}

PBKDF2::PBKDF2(PBKDF2 &&other) = default;

PBKDF2 &PBKDF2::operator=(PBKDF2 &&other)
{
    this->_impl = std::move(other._impl);
    return *this;
}

PBKDF2::PBKDF2(const PBKDF2 &other) : _impl(std::make_unique<PBKDF2::Impl>(*other._impl)) {}

PBKDF2 &PBKDF2::operator=(const PBKDF2 &other)
{
    this->_impl = std::make_unique<PBKDF2::Impl>(*other._impl);
    return *this;
}

class X963KDF::Impl
{
public:
    Impl(openssl::DigestTypes hashFunction) : _hashFunction(hashFunction) {}

    ~Impl() = default;

    std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password,
                                   const size_t outputLength,
                                   const std::vector<uint8_t> &salt)
    {
        std::vector<uint8_t> derivedKey(outputLength);
        const EVP_MD *digestFn = openssl::_getMDPtrFromDigestType(_hashFunction);
        openssl::_ECDH_KDF_X9_63(derivedKey, password, salt, digestFn);
        return derivedKey;
    }

private:
    openssl::DigestTypes _hashFunction;
};

X963KDF::X963KDF(openssl::DigestTypes hashFunction)
{
    _impl = std::make_unique<X963KDF::Impl>(hashFunction);
}

X963KDF::~X963KDF() = default;

std::vector<uint8_t> X963KDF::deriveKey(const std::vector<uint8_t> &password,
                                        const size_t outputLength,
                                        const std::vector<uint8_t> &salt)
{
    return _impl->deriveKey(password, outputLength, salt);
}

X963KDF::X963KDF(X963KDF &&other) = default;

X963KDF::X963KDF(const X963KDF &other) : _impl(std::make_unique<X963KDF::Impl>(*other._impl)) {}

X963KDF &X963KDF::operator=(X963KDF &&other)
{
    this->_impl = std::move(other._impl);
    return *this;
}

X963KDF &X963KDF::operator=(const X963KDF &other)
{
    this->_impl = std::make_unique<X963KDF::Impl>(*other._impl);
    return *this;
}

}  // namespace mococrw
