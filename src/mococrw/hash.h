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
#pragma once
#include <vector>
#include <map>

#include "mococrw/openssl_wrap.h"

namespace mococrw
{

std::vector<uint8_t> sha1(const std::vector<uint8_t> &message);
std::vector<uint8_t> sha1(const std::string &message);
std::vector<uint8_t> sha1(const uint8_t* message, size_t messageLength);

std::vector<uint8_t> sha256(const std::vector<uint8_t> &message);
std::vector<uint8_t> sha256(const std::string &message);
std::vector<uint8_t> sha256(const uint8_t* message, size_t messageLength);

std::vector<uint8_t> sha384(const std::vector<uint8_t> &message);
std::vector<uint8_t> sha384(const std::string &message);
std::vector<uint8_t> sha384(const uint8_t* message, size_t messageLength);

std::vector<uint8_t> sha512(const std::vector<uint8_t> &message);
std::vector<uint8_t> sha512(const std::string &message);
std::vector<uint8_t> sha512(const uint8_t* message, size_t messageLength);

std::vector<uint8_t> sha1(const std::vector<uint8_t> &message);
std::vector<uint8_t> sha1(const uint8_t *message, size_t messageLength);

class Hash
{
public:
    static Hash sha1();
    static Hash sha256();
    static Hash sha384();
    static Hash sha512();
    static Hash sha1();
    std::vector<uint8_t> digest();
    Hash& update(const std::vector<uint8_t> &chunk);
    Hash& update(const std::string &chunk);
    Hash& update(const uint8_t* chunk, size_t length);
private:
    Hash(const openssl::DigestTypes _digestType);
    static const std::map<openssl::DigestTypes, size_t> lengthInBytes;
    openssl::SSL_EVP_MD_CTX_Ptr _digestCtx;
    std::vector<uint8_t> _finalDigestValue;
    openssl::DigestTypes _digestType;
};

}
