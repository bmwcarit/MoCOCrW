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
#pragma once

#include <mococrw/key.h>
#include <mococrw/padding_mode.h>

#include <boost/program_options.hpp>

using namespace mococrw;
namespace po = boost::program_options;

struct RsaData {
    std::shared_ptr<RSAEncryptionPadding> padding;
    std::shared_ptr<AsymmetricPrivateKey> privKey;
    std::shared_ptr<AsymmetricPublicKey> pubKey;
    std::vector<uint8_t> data;
    std::shared_ptr<const po::variables_map> vm;
    bool chaining;
    RsaData() : padding(nullptr), privKey(nullptr), pubKey(nullptr), vm(nullptr), chaining(false)
    {}
};

void encrypt_rsa(const struct RsaData &rsaData);
void decrypt_rsa(const struct RsaData &rsaData);
