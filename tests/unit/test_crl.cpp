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
#include <fstream>
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mococrw/crl.h"
#include "mococrw/ca.h"
#include "mococrw/basic_constraints.h"
#include "mococrw/key_usage.h"

using namespace std::string_literals;

using namespace mococrw;
using namespace mococrw::openssl;

std::string corruptPEM(const std::string &pem)
{
    std::vector<char> tokenBytes{pem.cbegin(), pem.cend()};
    if (tokenBytes.size() < 64) {
        throw std::runtime_error("Could not corrupt token. String is too short");
    }
    tokenBytes.at(63) ^= 0xff;
    return std::string{tokenBytes.cbegin(), tokenBytes.cend()};
}

template<class T>
std::vector<T> bytesFromFile(const std::string &filename)
{
    static_assert(sizeof(T) == sizeof(char), "bytesFromFile only works with 1 byte data types");

    std::ifstream file{filename};
    if (!file.good()) {
        std::string errorMsg{"Cannot load certificate from file "};
        errorMsg = errorMsg + filename;
        throw std::runtime_error(errorMsg);
    }

    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<T> buffer;
    buffer.resize(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

template<class Res, Res(Func)(const std::string&)>
auto openSSLObjectFromFile(const std::string &filename)
{
    auto buffer = bytesFromFile<char>(filename);
    return Func({buffer.data(), buffer.size()});
}

X509Certificate loadCertFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<X509Certificate, X509Certificate::fromPEM>(filename);
}

CertificateRevocationList loadCrlFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<CertificateRevocationList,
        CertificateRevocationList::fromPEM>(filename);
}

CertificateRevocationList loadCrlFromDERFile(const std::string &filename)
{
    auto buffer = bytesFromFile<uint8_t>(filename);
    return CertificateRevocationList::fromDER(buffer);
}

class CRLTest : public ::testing::Test
{
public:
    void SetUp() override;

protected:
    std::unique_ptr<CertificateRevocationList> rootCrl;
    std::unique_ptr<CertificateRevocationList> rootCrlWithInvalidSignature;
    std::unique_ptr<X509Certificate> rootCert;
    std::unique_ptr<X509Certificate> subCACert;

    static const std::string invalidCrlPem;
};

using namespace std::string_literals;

const std::string CRLTest::invalidCrlPem{R"(-----BEGIN X509 CRL-----
MIIBxTCBrgIBATANBgkqhkiG9w0BAQUFADBIMRYwFAYDVQQDDA1DUkwgUm9vdCBD
QSAxMQswCQYDVQQGEwJERTETMBEGA1UECwwKQk1XIENhciBJVDEMMAoGA1UECgwD
Qk1XFw0xODAxMTYwOTMyMTBaFw0yMDAxMTYwOTMyMTBaMCIwIAIBARcNMTgwMTE2
MDkzMTQ0WjAMMAoGA1UdFQQDCgEBoA4wDDAKBgNVHRQEAwIBAzANBgkqhkiG9w0B
AQUFAAOCAQEATzVMWpr4Qk3I9afSQI99IS4UcLY699sIVQZPLN+lhVrLTAQoYBZD
ym6kpmq/kfkxwOcFv2lJSEWJAlRSE0SpG0AyvsQ8LOfKzvgno1a150JzZnszLuuK
nYFJlQJNSc9LKVsn7nMjAqRsPBfcvdLgvQIxrv7IbArlzpJe7Dmz0guUsRkoPLgA
n0OgWYUWNTyEBw5k30+/4fpnyFjK0v+ed49hHKGrr3vIC30TM9IoBAvbTS41AEi7
xMXkycw4+LeLOPhYtS5visTc/zvJ70Wr26KnCbt8RrifqDtKckAyUrIzwrkUrv8E
KwI7L3ne8waohqAL6l7lOVsHdohLGd610g==
-----BLA X509 CRL-----)"};

void CRLTest::SetUp()
{
    rootCert = std::make_unique<X509Certificate>(loadCertFromFile("root3.pem"));
    subCACert = std::make_unique<X509Certificate>(loadCertFromFile("root3.int1.pem"));
    rootCrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.crl.pem"));
    rootCrlWithInvalidSignature =
            std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.crl_invalidsignature.pem"));
}

TEST_F(CRLTest, testHasCorrectValues)
{
    EXPECT_EQ(rootCert->getSubjectDistinguishedName(), rootCrl->getIssuerName());

    // Last update: Feb  2 10:35:56 2018 GMT
    EXPECT_EQ(rootCrl->getLastUpdateAsn1(),  Asn1Time::fromString("20180202103556Z"));

    // Next update: Jan  9 10:35:56 2118 GMT
    EXPECT_EQ(rootCrl->getNextUpdateAsn1(),  Asn1Time::fromString("21180109103556Z"));
}

TEST_F(CRLTest, testThatParsingInvalidPEMFails)
{
    EXPECT_THROW(CertificateRevocationList::fromPEM(invalidCrlPem), OpenSSLException);
}

TEST_F(CRLTest, testLoadingPEMDirectlyFromFile)
{
    EXPECT_NO_THROW(CertificateRevocationList::fromPEMFile("root3.crl.pem"));
}

TEST_F(CRLTest, testLoadingDER)
{
    EXPECT_NO_THROW(loadCrlFromDERFile("root3.crl.der"));
}

TEST_F(CRLTest, testLoadingDERDirectlyFromFile)
{
    EXPECT_NO_THROW(CertificateRevocationList::fromDERFile("root3.crl.der"));
}

TEST_F(CRLTest, testVerifyingGoodSignatureSucceeds)
{
    EXPECT_NO_THROW(rootCrl->verify(*rootCert));
}

TEST_F(CRLTest, testVerifyingChangedSignatureFails)
{
    EXPECT_THROW(rootCrlWithInvalidSignature->verify(*rootCert), MoCOCrWException);
}

TEST_F(CRLTest, testVerifyingWithWrongCertificateFails)
{
    EXPECT_THROW(rootCrl->verify(*subCACert), MoCOCrWException);
}

TEST_F(CRLTest, testConvertionFromAndToPEMIsNoOp)
{
    EXPECT_EQ(CertificateRevocationList::fromPEM(rootCrl->toPEM()).toPEM(), rootCrl->toPEM());
}
