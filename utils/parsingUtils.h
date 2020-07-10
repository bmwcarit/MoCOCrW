#include <mococrw/hash.h>
#include <mococrw/openssl_wrap.h>

namespace mococrw {

DigestTypes getDigest(std::string digestString);
openssl::ellipticCurveNid getEllipticCurveNid(const std::string &curveString, bool &success);
}

