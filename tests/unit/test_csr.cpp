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
#include <tuple>

#include <cstdio>

#include "csr.cpp"

#include "ExecUtil.h"

using namespace mococrw;
using namespace mococrw::openssl;
using namespace std::literals::string_literals;

/// \brief Structure to hold a private/public key pair
struct keyWithSize
{
    AsymmetricKeypair keypair;
    unsigned int keySize;
};

class CSRTest : public ::testing::Test, public ::testing::WithParamInterface<keyWithSize>
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
    constexpr static auto _derFile = "csr.der";
};

std::vector<keyWithSize> CSRTest::_asymmetricKeys{{AsymmetricKeypair::generateRSA(), 1024},
                                                  {AsymmetricKeypair::generateECC(), 256},
                                                  {AsymmetricKeypair::generateEd448(), 456},
                                                  {AsymmetricKeypair::generateEd25519(), 253}};
std::unique_ptr<DistinguishedName> CSRTest::_distinguishedName;

void CSRTest::SetUpTestCase()
{
    _distinguishedName = std::make_unique<DistinguishedName>(
            DistinguishedName::Builder()
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
    std::remove(_derFile);
}

TEST_P(CSRTest, testCreateCSR)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    auto pemString = csr.toPEM();
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
    auto pemString = csr.toPEM();
    auto pubKey = csr.getPublicKey();
    auto name = csr.getSubjectName();

    CertificateSigningRequest csrCheck = CertificateSigningRequest::fromPEM(pemString);
    auto pemStringCheck = csrCheck.toPEM();
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
    auto pemString = csr.toPEM();
    auto pubKey = csr.getPublicKey();
    auto name = csr.getSubjectName();

    std::ofstream of(_pemFile);
    of << csr.toPEM();
    of.close();

    CertificateSigningRequest csrCheck = CertificateSigningRequest::fromPEMFile(_pemFile);
    auto pemStringCheck = csrCheck.toPEM();
    auto pubKeyCheck = csrCheck.getPublicKey();
    auto nameCheck = csrCheck.getSubjectName();

    EXPECT_EQ(pemString, pemStringCheck);
    EXPECT_EQ(pubKey.publicKeyToPem(), pubKeyCheck.publicKeyToPem());
    EXPECT_EQ(name, nameCheck);
    EXPECT_EQ(*_distinguishedName, nameCheck);
    EXPECT_NO_THROW(csrCheck.verify());
}

TEST_P(CSRTest, testCreateCsrFromDerFile)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};
    auto derData = csr.toDER();
    auto pubKey = csr.getPublicKey();
    auto name = csr.getSubjectName();

    std::ofstream of(_derFile);
    of.write(reinterpret_cast<const char *>(derData.data()), derData.size());
    of.close();

    CertificateSigningRequest csrCheck = CertificateSigningRequest::fromDERFile(_derFile);
    auto pubKeyCheck = csrCheck.getPublicKey();
    auto nameCheck = csrCheck.getSubjectName();

    EXPECT_EQ(pubKey.publicKeyToPem(), pubKeyCheck.publicKeyToPem());
    EXPECT_EQ(name, nameCheck);
    EXPECT_EQ(*_distinguishedName, nameCheck);
    EXPECT_NO_THROW(csrCheck.verify());
}

TEST_F(CSRTest, testCreateCsrFromNonExistingPemFileThrows)
{
    ASSERT_THROW(CertificateSigningRequest::fromPEMFile(_pemFile), openssl::OpenSSLException);
}

TEST_F(CSRTest, testCreateCsrFromNonExistingDerFileThrows)
{
    ASSERT_THROW(CertificateSigningRequest::fromDERFile(_derFile), openssl::OpenSSLException);
}

TEST_F(CSRTest, testCreateCsrFromNonPemFileThrows)
{
    std::ofstream of(_pemFile);
    of << "This is most certainly no PEM";
    of.close();

    ASSERT_THROW(CertificateSigningRequest::fromPEMFile(_pemFile), openssl::OpenSSLException);
}

TEST_F(CSRTest, testCreateCsrFromNonDerFileThrows)
{
    std::ofstream of(_pemFile);
    of << "This is most certainly no DER";
    of.close();

    ASSERT_THROW(CertificateSigningRequest::fromDERFile(_pemFile), openssl::OpenSSLException);
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

    std::string pemString = csr.toPEM();

    CertificateSigningRequest csrFromPem = CertificateSigningRequest::fromPEM(pemString);

    EXPECT_NO_THROW(csrFromPem.verify());
}

TEST_P(CSRTest, testVerifyCsrFromDerSuccess)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    auto derData = csr.toDER();

    CertificateSigningRequest csrFromDer = CertificateSigningRequest::fromDER(derData);

    EXPECT_NO_THROW(csrFromDer.verify());
}

TEST_P(CSRTest, testVerifyCsrFail)
{
    auto data = GetParam();
    CertificateSigningRequest csr{*_distinguishedName, data.keypair};

    std::string pemString = csr.toPEM();
    auto idx = pemString.find_first_of('1');
    pemString.replace(idx, 1, "2");

    CertificateSigningRequest csrFromPem = CertificateSigningRequest::fromPEM(pemString);
    EXPECT_THROW(csrFromPem.verify(), MoCOCrWException);
}

TEST_P(CSRTest, testCsrSignatureDigest)
{
    static const auto hashAlgorithms = std::vector<std::tuple<DigestTypes, std::string>>{
            {DigestTypes::SHA256, "sha256"},
            {DigestTypes::SHA384, "sha384"},
            {DigestTypes::SHA512, "sha512"},
    };
    auto data = GetParam();
    if (data.keypair.getType() == AsymmetricKey::KeyTypes::ECC_ED) {
        /* those support only fixed hashes right now
         * Nothing to be tested
         */
        return;
    }

    for (const auto &hashAlgo : hashAlgorithms) {
        CertificateSigningRequest csr{*_distinguishedName, data.keypair, std::get<0>(hashAlgo)};
        std::ofstream of(_pemFile, std::ios::trunc);
        of << csr.toPEM();
        of.close();

        std::string openSSLCmdline =
                "openssl req -config /dev/null -in "s + _pemFile + " -noout -text";
        auto output = exec(openSSLCmdline.c_str());

        auto sigAlgoPos = output.find("Signature Algorithm:");
        ASSERT_NE(sigAlgoPos, std::string::npos);
        auto sigAlgoEndlinePos = output.find("\n", sigAlgoPos);
        ASSERT_NE(sigAlgoEndlinePos, std::string::npos);
        auto algoLine = output.substr(sigAlgoPos, sigAlgoEndlinePos - sigAlgoPos);
        std::transform(algoLine.begin(), algoLine.end(), algoLine.begin(), [](auto c) {
            return std::tolower(c);
        });
        auto digestPos = algoLine.find(std::get<1>(hashAlgo));
        EXPECT_NE(digestPos, std::string::npos);
    }
}

INSTANTIATE_TEST_SUITE_P(CSRTest, CSRTest, testing::ValuesIn(CSRTest::_asymmetricKeys));
