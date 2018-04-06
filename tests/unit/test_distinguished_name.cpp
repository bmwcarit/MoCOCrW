/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mococrw/distinguished_name.h"
#include "mococrw/openssl_wrap.h"

using namespace mococrw;
using namespace mococrw::openssl;

class DistinguishedNameTest : public ::testing::Test
{
public:
    void SetUp() override;
    void TearDown() override;
protected:
    DistinguishedName _dn;
    SSL_X509_NAME_Ptr _x509Name = nullptr;
};

void DistinguishedNameTest::SetUp()
{
    auto builder = DistinguishedName::Builder();
    builder.commonName("ImATeapot")
            .countryName("DE")
            .organizationName("Linux AG")
            .organizationalUnitName("Linux Support")
            .pkcs9EmailAddress("support@example.com")
            .localityName("oben")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD");
    builder.stateOrProvinceName("nebenan");
    _dn = builder.build();
    _x509Name = _X509_NAME_new();
}

void DistinguishedNameTest::TearDown()
{
    /* intentionally empty */
}

TEST_F(DistinguishedNameTest, createDistinguishedName)
{
    ASSERT_EQ(_dn.commonName(), "ImATeapot");
    ASSERT_EQ(_dn.countryName(), "DE");
    ASSERT_EQ(_dn.organizationName(), "Linux AG");
    ASSERT_EQ(_dn.organizationalUnitName(), "Linux Support");
    ASSERT_EQ(_dn.pkcs9EmailAddress(), "support@example.com");
    ASSERT_EQ(_dn.stateOrProvinceName(), "nebenan");
    ASSERT_EQ(_dn.serialNumber(), "08E36DD501941432358AFE8256BC6EFD");
    ASSERT_EQ(_dn.localityName(), "oben");
}

TEST_F(DistinguishedNameTest, errorHandlingInDistinguishedName)
{
    auto builder = DistinguishedName::Builder();
    ASSERT_NO_THROW(builder.commonName("ImATeapot"));
    ASSERT_THROW(builder.countryName("DES"), std::runtime_error);
    ASSERT_NO_THROW(builder.countryName("DE"));
}

TEST_F(DistinguishedNameTest, testThatEqualityWorks)
{
    auto dn = DistinguishedName::Builder().commonName("a").build();
    auto dn2 = DistinguishedName::Builder().organizationName("a").build();

    /*
     * Invoke the operators explicitly so that we can be sure
     * of which code-paths are tested specifically (matchers
     * may use various boolean-logic statements that we do not
     * see).
     */
    ASSERT_FALSE(dn == dn2);
    ASSERT_TRUE(dn != dn2);

    dn2 = DistinguishedName::Builder().commonName("a").build();
    ASSERT_TRUE(dn == dn2);
}

TEST_F(DistinguishedNameTest, testThatDistinguishedNameIsPopulatedCorrectly)
{
    using ::testing::Eq;
    _dn.populateX509Name(_x509Name);
    auto dn = DistinguishedName::fromX509Name(_x509Name.get());

    ASSERT_THAT(dn, Eq(_dn));
}
