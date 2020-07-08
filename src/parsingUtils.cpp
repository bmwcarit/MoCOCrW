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
#include "mococrw/private/parsingUtils.h"

#include <iostream>
#include <unordered_map>
#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>



namespace mococrw {

static std::unordered_map<std::string, openssl::DigestTypes> const digestConversionMap = {
    {"SHA256", openssl::DigestTypes::SHA256},
    {"SHA384", openssl::DigestTypes::SHA384},
    {"SHA512", openssl::DigestTypes::SHA512},
    {"SHA3-256", openssl::DigestTypes::SHA3_256},
    {"SHA3-384", openssl::DigestTypes::SHA3_384},
    {"SHA3-512", openssl::DigestTypes::SHA3_512}
};

openssl::DigestTypes getDigestType(std::string digestTypeString)
{
    auto it = digestConversionMap.find(boost::to_upper_copy<std::string>(digestTypeString));
    if (it != digestConversionMap.end()) {
        return it->second;
    }

    return openssl::DigestTypes::NONE;
}

static std::unordered_map<std::string, openssl::ellipticCurveNid> const ellipticCurveConversionMap = {
    {"PRIME_192v1", openssl::ellipticCurveNid::PRIME_192v1},
    {"PRIME_256v1", openssl::ellipticCurveNid::PRIME_256v1},
    {"SECP_224r1", openssl::ellipticCurveNid::SECP_224r1},
    {"SECP_384r1", openssl::ellipticCurveNid::SECP_384r1},
    {"SECP_521r1", openssl::ellipticCurveNid::SECP_521r1},
    {"SECT_283k1", openssl::ellipticCurveNid::SECT_283k1},
    {"SECT_283r1", openssl::ellipticCurveNid::SECT_283r1},
    {"SECT_409k1", openssl::ellipticCurveNid::SECT_409k1},
    {"SECT_409r1", openssl::ellipticCurveNid::SECT_409r1},
    {"SECT_571k1", openssl::ellipticCurveNid::SECT_571k1},
    {"SECT_571r1", openssl::ellipticCurveNid::SECT_571r1},
    {"Ed448", openssl::ellipticCurveNid::Ed448},
    {"Ed25519", openssl::ellipticCurveNid::Ed25519}
};

openssl::ellipticCurveNid getEllipticCurveNid(const std::string &curveString, bool &success)
{
    success = true;
    auto it = ellipticCurveConversionMap.find(curveString);
    if (it != ellipticCurveConversionMap.end()) {
        return it->second;
    }

    success = false;
    return openssl::ellipticCurveNid::PRIME_256v1;

}

template <class Builder, class Type>
Builder invokeIfNotEmpty(Builder b, std::function<Builder ( Type )> func, Type val)
{
    if (val.empty()) {
        return b;
    }
    return func(val);
}

#define addCertDetailIfSet(func, str)  \
    detailsBuilder = invokeIfNotEmpty<DistinguishedName::Builder, std::string>( \
        detailsBuilder, \
        std::bind(&DistinguishedName::Builder::func<std::string>, detailsBuilder, std::placeholders::_1), \
        certDetails.get(str, "") \
    )

std::shared_ptr<DistinguishedName> getCertDetails(pt::ptree certDetails)
{
    auto detailsBuilder = DistinguishedName::Builder{};

    addCertDetailIfSet(commonName, "commonName");
    addCertDetailIfSet(countryName, "countryName");
    addCertDetailIfSet(localityName, "localityName");
    addCertDetailIfSet(stateOrProvinceName, "stateOrProvinceName");
    addCertDetailIfSet(organizationName, "organizationName");
    addCertDetailIfSet(organizationalUnitName, "organizationalUnitName");
    addCertDetailIfSet(pkcs9EmailAddress, "pkcs9EmailAddress");
    addCertDetailIfSet(givenName, "givenName");
    addCertDetailIfSet(userId, "title");
    addCertDetailIfSet(title, "userId");

    return std::make_shared<DistinguishedName>(detailsBuilder.build());
}
#undef addCertDetailIfSet


void readJsonConfigFile(pt::ptree &propertyTree, const po::variables_map &vm)
{
    std::string filePath = vm["config-file"].as<std::string>();
    try {
        pt::json_parser::read_json(filePath, propertyTree);
    }  catch (boost::property_tree::json_parser::json_parser_error &e) {
        std::cerr << "Failure parsing json file." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

}
