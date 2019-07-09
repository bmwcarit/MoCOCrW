/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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

TEST_F(DistinguishedNameTest, testThatOldBuilderKeepsOldOrder) {
    auto builder = DistinguishedName::Builder();
    builder.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("oben")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan")
            .countryName("US")
            .countryName("CH");
    auto dn = builder.build();
    auto x509Name = _X509_NAME_new();
    dn.populateX509Name(x509Name);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::CommonName)[0], 0);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::CountryName)[0], 1);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::LocalityName)[0], 2);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::StateOrProvinceName)[0], 3);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::OrganizationalUnitName)[0], 4);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::OrganizationName)[0], 5);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::Pkcs9EmailAddress)[0], 6);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::SerialNumber)[0], 7);
    auto entry = _X509_NAME_get_entry(x509Name.get(), 1);
    auto name = _X509_NAME_ENTRY_get_data(entry);
    ASSERT_EQ(name, "CH");
}

TEST_F(DistinguishedNameTest, testThatCustomAttributeOrderWorks) {
    auto builder = DistinguishedName::CustomOrderBuilder();
    builder.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("oben")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn = builder.build();
    auto x509Name = _X509_NAME_new();
    dn.populateX509Name(x509Name);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::CommonName)[0], 0);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::CountryName)[0], 1);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::Pkcs9EmailAddress)[0], 2);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::OrganizationalUnitName)[0], 3);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::LocalityName)[0], 4);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::SerialNumber)[0], 5);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::OrganizationName)[0], 6);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::StateOrProvinceName)[0], 7);
}

TEST_F(DistinguishedNameTest, testThatCustomAttributeWithDuplicatesWorks) {
    auto builder = DistinguishedName::CustomOrderBuilder();
    builder.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("oben")
            .localityName("links")
            .localityName("rechts")
            .localityName("unten")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn = builder.build();
    auto x509Name = _X509_NAME_new();
    dn.populateX509Name(x509Name);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::CommonName)[0], 0);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::CountryName)[0], 1);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::Pkcs9EmailAddress)[0], 2);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::OrganizationalUnitName)[0], 3);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::LocalityName)[0], 4);
    ASSERT_EQ(_X509_NAME_ENTRY_get_data(_X509_NAME_get_entry(x509Name.get(), 4)), "oben");
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::LocalityName)[1], 5);
    ASSERT_EQ(_X509_NAME_ENTRY_get_data(_X509_NAME_get_entry(x509Name.get(), 5)), "links");
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::LocalityName)[2], 6);
    ASSERT_EQ(_X509_NAME_ENTRY_get_data(_X509_NAME_get_entry(x509Name.get(), 6)), "rechts");
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::LocalityName)[3], 7);
    ASSERT_EQ(_X509_NAME_ENTRY_get_data(_X509_NAME_get_entry(x509Name.get(), 7)), "unten");
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::SerialNumber)[0], 8);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::OrganizationName)[0], 9);
    ASSERT_EQ(_X509_NAME_get_index_by_NID(x509Name.get(), openssl::ASN1_NID::StateOrProvinceName)[0], 10);
}

TEST_F(DistinguishedNameTest, testThatComparsionWorksWithOldBuilder) {
    auto builder1 = DistinguishedName::Builder();
    builder1.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("unten")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn1 = builder1.build();
    auto builder2 = DistinguishedName::Builder();
    builder2.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("unten")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn2 = builder2.build();
    // same order and same data so expect equal
    ASSERT_EQ(dn1, dn2);
    auto builder3 = DistinguishedName::Builder();
    builder3.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .localityName("unten")
            .organizationalUnitName("Linux Support")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn3 = builder3.build();
    // order has changed still expect equal
    ASSERT_EQ(dn2, dn3);
}

TEST_F(DistinguishedNameTest, testThatComparsionWorksWithCustomOrderBuilder) {
    auto builder1 = DistinguishedName::CustomOrderBuilder();
    builder1.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("unten")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn1 = builder1.build();
    auto builder2 = DistinguishedName::CustomOrderBuilder();
    builder2.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .organizationalUnitName("Linux Support")
            .localityName("unten")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn2 = builder2.build();
    // same order and same data so expect equal
    ASSERT_EQ(dn1, dn2);
    auto builder3 = DistinguishedName::CustomOrderBuilder();
    builder3.commonName("ImATeapot")
            .countryName("DE")
            .pkcs9EmailAddress("support@example.com")
            .localityName("unten")
            .organizationalUnitName("Linux Support")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .organizationName("Linux AG")
            .stateOrProvinceName("nebenan");
    auto dn3 = builder3.build();
    // order has changed so expect not equal
    ASSERT_NE(dn2, dn3);
}


TEST_F(DistinguishedNameTest, testThatComparsionWorksWithMixedBuilders) {
    auto builder1 = DistinguishedName::CustomOrderBuilder();
    builder1.countryName("DE")
            .commonName("ImATeapot");
    auto dn1 = builder1.build();
    auto builder2 = DistinguishedName::Builder();
    builder2.commonName("ImATeapot")
            .countryName("DE");
    auto dn2 = builder2.build();
    ASSERT_EQ(dn1 != dn2, dn2 != dn1);
}
