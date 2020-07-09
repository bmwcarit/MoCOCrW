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

#include <boost/program_options.hpp>
#include <mococrw/symmetric_crypto.h>

using namespace mococrw;
namespace po = boost::program_options;

struct AesData {
    SymmetricCipherMode operationMode;
    SymmetricCipherPadding padding;
    std::shared_ptr<const po::variables_map> vm;
    std::vector<uint8_t> data;
    std::vector<uint8_t> secretKey;
    std::vector<uint8_t> iv;
    boost::optional<std::vector<uint8_t>> authData;
    boost::optional<std::vector<uint8_t>> authTag;
    boost::optional<size_t> authTagLength;

    bool chaining;
    AesData(std::shared_ptr<const po::variables_map> vm) : vm(vm), chaining(false)
    {}
};

void aesEncrypt(const AesData &aesData);

void aesDecrypt(const AesData &aesData);
