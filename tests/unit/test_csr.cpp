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


/// \brief Structure to hold a private/public key pair
struct keyWithSize {
    AsymmetricKeypair keypair;
    unsigned int keySize;
};

class CSRTest : public ::testing::Test,
                public ::testing::WithParamInterface<keyWithSize>
{
public:
    static void SetUpTestCase();
    void TearDown() override;
    static std::vector<keyWithSize> _asymmetricKeys;

protected:
    static std::unique_ptr<DistinguishedName> _distinguishedName;
    static std::unique_ptr<AsymmetricKeypair> _rsaKeypair;
    static std::unique_ptr<AsymmetricKeypair> _eccKeypair;
    constexpr static auto _pemFile = "csr.pem";
};

std::vector<keyWithSize> CSRTest::_asymmetricKeys
{
    {AsymmetricKeypair::generateRSA(), 1024},
    {AsymmetricKeypair::generateECC(), 256}
};
std::unique_ptr<DistinguishedName> CSRTest::_distinguishedName;

void CSRTest::SetUpTestCase()
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
}

void CSRTest::TearDown()
{
    std::remove(_pemFile);
}

TEST_P(CSRTest, testCreateCSR)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    auto pemString = csr.toPem();
    auto pubKey = csr.getPublicKey();
    // Smoke test to verify that a realistic amount of output
    // is generated
    ASSERT_GE(pemString.size(), data.keySize);

    ASSERT_GE(data.keySize, pubKey.publicKeyToPem().size());
}

TEST_P(CSRTest, testGetName)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};
    auto name = csr.getSubjectName();

    EXPECT_EQ(name, *_distinguishedName);
}

TEST_P(CSRTest, testCreateCsrFromPem)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};
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

TEST_P(CSRTest, testCreateCsrFromPemFile)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};
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

TEST_P(CSRTest, testVerifyCsrSuccess)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    EXPECT_NO_THROW(csr.verify());
}

TEST_P(CSRTest, testVerifyCsrFromPemSuccess)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    std::string pemString = csr.toPem();

    CertificateSigningRequest csrFromPem = CertificateSigningRequest::fromPEM(pemString);

    EXPECT_NO_THROW(csrFromPem.verify());
}

TEST_P(CSRTest, testVerifyCsrFail)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    std::string pemString = csr.toPem();
    auto idx = pemString.find_first_of('1');
    pemString.replace(idx, 1, "2");

    CertificateSigningRequest csrFromPem = CertificateSigningRequest::fromPEM(pemString);
    EXPECT_THROW(csrFromPem.verify(), MoCOCrWException);
}

INSTANTIATE_TEST_CASE_P(CSRTest, CSRTest,
                        testing::ValuesIn(CSRTest::_asymmetricKeys));