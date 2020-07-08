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

}
