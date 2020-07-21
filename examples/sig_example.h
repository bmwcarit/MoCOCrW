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

#include <boost/program_options.hpp>
#include <mococrw/padding_mode.h>
#include <mococrw/key.h>
#include <mococrw/asymmetric_crypto_ctx.h>

using namespace mococrw;
namespace po = boost::program_options;

struct SigData {
    std::shared_ptr<RSASignaturePadding> rsaPadding;
    ECDSASignatureFormat sigFormat;
    std::shared_ptr<AsymmetricPrivateKey> privKey;
    std::shared_ptr<AsymmetricPublicKey> pubKey;
    DigestTypes digestType;
    std::vector<uint8_t> message;
    std::vector<uint8_t> signature;
    std::shared_ptr<const po::variables_map> vm;
    bool chaining;
    SigData(std::shared_ptr<const po::variables_map> vm) : rsaPadding(nullptr), digestType(DigestTypes::NONE), vm(vm),
        chaining(false)
    {}
};

void sign(const struct SigData &sigData);
void verify(const struct SigData &sigData);
