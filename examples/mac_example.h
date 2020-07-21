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

#include <mococrw/openssl_wrap.h>
#include <boost/program_options.hpp>

using namespace mococrw;
namespace po = boost::program_options;

struct MacData {
    std::vector<uint8_t> message;
    std::vector<uint8_t> key;
    DigestTypes digestType;
    std::vector<uint8_t> authenticationTag;
    bool chaining;
    bool verify;
    std::shared_ptr<const po::variables_map> vm;
    MacData(std::shared_ptr<const po::variables_map> vm) : chaining(false), verify(false), vm(vm)
    {}
};

void verify(const struct MacData &macData);
void calculate(const struct MacData &macData);
