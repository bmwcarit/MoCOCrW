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
#include <mococrw/ca.h>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace mococrw;
namespace po = boost::program_options;
namespace pt = boost::property_tree;

struct CaData {
    std::shared_ptr<CertificateSigningParameters> signParams;
    std::shared_ptr<DistinguishedName> certDetails;
    std::shared_ptr<AsymmetricPrivateKey> privKey;
    std::shared_ptr<X509Certificate> rootCert;
    std::shared_ptr<CertificateSigningRequest> csr;
    std::shared_ptr<const pt::ptree> config;
    std::shared_ptr<const po::variables_map> vm;
    CaData(std::shared_ptr<const pt::ptree> config, std::shared_ptr<const po::variables_map> vm)
        : config(config), vm(vm)
    {}
};

std::shared_ptr<CertificateAuthority> getCa(const struct CaData &caData);
std::shared_ptr<X509Certificate> createRootCertificate(const struct CaData &caData);
std::shared_ptr<X509Certificate> signCsr(const struct CaData &caData);
