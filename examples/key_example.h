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
#include <mococrw/openssl_wrap.h>
namespace po = boost::program_options;
using namespace mococrw;

struct KeyData {
    std::string outFile;
    std::string password;
    bool rsa;
    bool pubOut;
    boost::optional<std::string> pubOutFile;
    uint keySize;
    openssl::ellipticCurveNid curve;
    std::shared_ptr<const po::variables_map> vm;
    KeyData(std::shared_ptr<const po::variables_map> vm) : rsa(false), vm(vm)
    {}
};

void createKey(const struct KeyData &keyData);
