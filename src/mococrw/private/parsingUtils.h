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

#include <mococrw/hash.h>
#include <mococrw/openssl_wrap.h>
#include <mococrw/key_usage.h>
#include <mococrw/distinguished_name.h>
#include <mococrw/sign_params.h>
#include <mococrw/basic_constraints.h>

#include <boost/property_tree/ptree.hpp>
#include <boost/program_options.hpp>

namespace pt = boost::property_tree;
namespace po = boost::program_options;
namespace mococrw {

DigestTypes getDigestType(std::string digestString);
openssl::ellipticCurveNid getEllipticCurveNid(const std::string &curveString, bool &success);

std::shared_ptr<DistinguishedName> getCertDetails(pt::ptree certDetails);
void readJsonConfigFile(pt::ptree &propertyTree, const po::variables_map &vm);

}

