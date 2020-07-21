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

#include <mococrw/kdf.h>
#include <boost/program_options.hpp>

using namespace mococrw;
namespace po = boost::program_options;

struct KdfData {
    std::vector<uint8_t> password;
    size_t outputLength;
    std::vector<uint8_t> salt;
    DigestTypes digestType;
    uint32_t iterations;
    bool pbkdf2;
    std::shared_ptr<const po::variables_map> vm;
    KdfData(std::shared_ptr<const po::variables_map> vm) : pbkdf2(false), vm(vm)
    {}

};


void pbkdf2(const struct KdfData &kdfData);
void x963kdf(const struct KdfData &kdfData);
