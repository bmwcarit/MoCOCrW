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

#include <fstream>

#include <cstdio>

#include "csr.cpp"

using namespace mococrw;
using namespace mococrw::openssl;

class CSRTest : public ::testing::Test
{
public:
    void SetUp() override;
    void TearDown() override;
protected:
    std::unique_ptr<DistinguishedName> _distinguishedName;
    std::unique_ptr<AsymmetricKeypair> _keypair;

    constexpr static auto _pemFile = "csr.pem";
};

void CSRTest::SetUp()
{
    _distinguishedName = std::make_unique<DistinguishedName>(DistinguishedName::Builder()
                                        .commonName("ImATeapot")
                                        .countryName("DE")
                                        .organizationName("Linux AG")
                                        .organizationalUnitName("Linux Support")
                                        .pkcs9EmailAddress("support@example.com")
                                        .localityName("oben")
                                        .stateOrProvinceName("nebenan")
                                        .serialNumber("08E36DD501941432358AFE8256BC6EFD")
                                        .build());
    _keypair = std::make_unique<AsymmetricKeypair>(AsymmetricKeypair::generateRSA());
}

void CSRTest::TearDown()
{
    std::remove(_pemFile);
}

TEST_F(CSRTest, testCreateCSR)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};
    auto pemString = csr.toPem();
    auto pubKey = csr.getPublicKey();
    // Smoke test to verify that a realistic amount of output
    // is generated
    ASSERT_GE(pemString.size(), 1024);

    ASSERT_GE(1024, pubKey.publicKeyToPem().size());
}

TEST_F(CSRTest, testGetName)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};
    auto name = csr.getSubjectName();

    EXPECT_EQ(name, *_distinguishedName);
}

TEST_F(CSRTest, testCreateCsrFromPem)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};
    auto pemString = csr.toPem();
    auto pubKey = csr.getPublicKey();
    auto name = csr.getSubjectName();

    CertificateSigningRequest csrCheck = CertificateSigningRequest::fromPEM(pemString);
    auto pemStringCheck = csrCheck.toPem();
    auto pubKeyCheck = csrCheck.getPublicKey();
    auto nameCheck = csrCheck.getSubjectName();

    EXPECT_EQ(pemString, pemStringCheck);
    EXPECT_EQ(pubKey.publicKeyToPem(), pubKeyCheck.publicKeyToPem());
    EXPECT_EQ(name, nameCheck);
    EXPECT_EQ(*_distinguishedName, nameCheck);
}


TEST_F(CSRTest, testCreateCsrFromPemFile)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};
    auto pemString = csr.toPem();
    auto pubKey = csr.getPublicKey();
    auto name = csr.getSubjectName();

    std::ofstream of(_pemFile);
    of << csr.toPem();
    of.close();

    CertificateSigningRequest csrCheck = CertificateSigningRequest::fromPEMFile(_pemFile);
    auto pemStringCheck = csrCheck.toPem();
    auto pubKeyCheck = csrCheck.getPublicKey();
    auto nameCheck = csrCheck.getSubjectName();

    EXPECT_EQ(pemString, pemStringCheck);
    EXPECT_EQ(pubKey.publicKeyToPem(), pubKeyCheck.publicKeyToPem());
    EXPECT_EQ(name, nameCheck);
    EXPECT_EQ(*_distinguishedName, nameCheck);
    EXPECT_NO_THROW(csrCheck.verify());
}

TEST_F(CSRTest, testCreateCsrFromNonExistingPemFileThrows)
{
    ASSERT_THROW(CertificateSigningRequest::fromPEMFile(_pemFile), openssl::OpenSSLException);
}

TEST_F(CSRTest, testCreateCsrFromNonPemFileThrows)
{
    std::ofstream of(_pemFile);
    of << "This is most certainly no PEM";
    of.close();

    ASSERT_THROW(CertificateSigningRequest::fromPEMFile(_pemFile), openssl::OpenSSLException);
}

TEST_F(CSRTest, testVerifyCsrSuccess)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};

    EXPECT_NO_THROW(csr.verify());
}

TEST_F(CSRTest, testVerifyCsrFromPemSuccess)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};

    std::string pemString = csr.toPem();

    CertificateSigningRequest csrFromPem = CertificateSigningRequest::fromPEM(pemString);

    EXPECT_NO_THROW(csrFromPem.verify());
}

TEST_F(CSRTest, testVerifyCsrFail)
{
    CertificateSigningRequest csr{*_distinguishedName, *_keypair};

    std::string pemString = csr.toPem();
    auto idx = pemString.find_first_of('1');
    pemString.replace(idx, 1, "2");

    CertificateSigningRequest csrFromPem = CertificateSigningRequest::fromPEM(pemString);
    EXPECT_THROW(csrFromPem.verify(), MoCOCrWException);
}
