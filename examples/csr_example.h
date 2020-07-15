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

#include <mococrw/csr.h>
#include "mococrw/private/parsingUtils.h"

using namespace mococrw;

struct CsrData {
    std::shared_ptr<DistinguishedName> certDetails;
    std::shared_ptr<AsymmetricPrivateKey> privKey;
    openssl::DigestTypes digestType;
    std::shared_ptr<const pt::ptree> config;
    std::shared_ptr<const po::variables_map> vm;
    CsrData(std::shared_ptr<const pt::ptree> config, std::shared_ptr<const po::variables_map> vm)
        : config(config), vm(vm)
    {}
};

std::shared_ptr<CertificateSigningRequest> createSigningRequest(const struct CsrData &csrData);
