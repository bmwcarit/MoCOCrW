/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <gtest/gtest.h>

#include "csr.cpp"

using namespace mococrw;
using namespace mococrw::openssl;

TEST(CSRTest, createCSR)
{
    auto dn = DistinguishedName::Builder()
                      .commonName("ImATeapot")
                      .countryName("DE")
                      .organizationName("BMW")
                      .organizationalUnitName("Linux Support")
                      .pkcs9EmailAddress("support@linux.bmwgroup.com")
                      .localityName("oben")
                      .stateOrProvinceName("nebenan")
                      .serialNumber("ECU-UID:08E36DD501941432358AFE8256BC6EFD")
                      .build();
    CertificateSigningRequest csr{dn};
    auto pemString = csr.toPem();
    auto keypair = csr.getKeypair();
    // Smoke test to verify that a realistic amount of output
    // is generated
    ASSERT_GE(pemString.size(), 1024);

    ASSERT_GE(1024, keypair.publicKeyToPem().size());
}
