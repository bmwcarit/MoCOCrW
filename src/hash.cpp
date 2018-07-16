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
#include "mococrw/hash.h"
#include "mococrw/util.h"
#include "mococrw/error.h"

namespace mococrw
{
using namespace openssl;

static const std::string SHA256 = "sha256";
static const std::string SHA512 = "sha512";

std::vector<uint8_t> sha256(const uint8_t* message, size_t length) {
   return Hash::sha256().update(message, length).digest();
}

std::vector<uint8_t> sha256(const std::string &message) {
    return Hash::sha256().update(message).digest();
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &message) {
    return Hash::sha256().update(message).digest();
}

std::vector<uint8_t> sha512(const uint8_t* message, size_t length) {
    return Hash::sha512().update(message, length).digest();
}

std::vector<uint8_t> sha512(const std::string &message) {
    return Hash::sha512().update(message).digest();
}

std::vector<uint8_t> sha512(const std::vector<uint8_t> &message) {
    return Hash::sha512().update(message).digest();
}

const std::map<DigestTypes, size_t> Hash::lengthInBytes = {
    { DigestTypes::SHA256, 256 / 8 },
    { DigestTypes::SHA512, 512 / 8 }
};

Hash::Hash(const DigestTypes digestType) : _digestType(digestType) {
    const EVP_MD* digestFn = _getMDPtrFromDigestType(digestType);
    _digestCtx = _EVP_MD_CTX_create();
    _EVP_MD_CTX_init(_digestCtx.get());
    _EVP_DigestInit_ex(_digestCtx.get(), digestFn, NULL);
}

Hash Hash::sha256() {
    return Hash{DigestTypes::SHA256};
}

Hash Hash::sha512() {
    return Hash{DigestTypes::SHA512};
}

std::vector<uint8_t> Hash::digest() {
    if (_finalDigestValue.empty()) {
        _finalDigestValue.resize(Hash::lengthInBytes.at(_digestType));
        _EVP_DigestFinal_ex(_digestCtx.get(), _finalDigestValue.data(), NULL);
    }
    return _finalDigestValue;
}

Hash& Hash::update(const std::string &chunk) {
    return update(reinterpret_cast<const uint8_t*>(chunk.c_str()), chunk.length());
}

Hash& Hash::update(const std::vector<uint8_t> &chunk) {
    return update(chunk.data(), chunk.size());
}

Hash& Hash::update(const uint8_t* chunk, size_t length) {
    if(!_finalDigestValue.empty()) {
        throw MoCOCrWException("update method cannot be called after digest was called");
    }
    _EVP_DigestUpdate(_digestCtx.get(), chunk, length);
    return *this;
}

}