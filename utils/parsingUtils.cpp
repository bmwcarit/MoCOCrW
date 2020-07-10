#include "parsingUtils.h"

#include <iostream>
#include <unordered_map>
#include <string>
#include <boost/algorithm/string.hpp>


namespace mococrw {

static std::unordered_map<std::string, openssl::DigestTypes> const digestConversionMap = {
    {"SHA256", openssl::DigestTypes::SHA256},
    {"SHA384", openssl::DigestTypes::SHA384},
    {"SHA512", openssl::DigestTypes::SHA512},
    {"SHA3-256", openssl::DigestTypes::SHA3_256},
    {"SHA3-384", openssl::DigestTypes::SHA3_384},
    {"SHA3-512", openssl::DigestTypes::SHA3_512}
};

openssl::DigestTypes getDigest(std::string digestString)
{
    auto it = digestConversionMap.find(boost::to_upper_copy<std::string>(digestString));
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

}
