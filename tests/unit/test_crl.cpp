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
    static const std::string crlPemChain;
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


const std::string CRLTest::crlPemChain{R"(-----BEGIN X509 CRL-----
MIIB0jCBuwIBATANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJQVDEOMAwGA1UE
CAwFUG9ydG8xDjAMBgNVBAcMBVBvcnRvMRkwFwYDVQQKDBBUZXN0T3JnYW5pemF0
aW9uMRQwEgYDVQQLDAtUZXN0T3JnTmFtZTEXMBUGA1UEAwwOVGVzdENvbW1vbk5h
bWUXDTE4MDkwNjE2MDI0MVoYDzIxMDAxMDI2MTYwMjQxWqAOMAwwCgYDVR0UBAMC
AQUwDQYJKoZIhvcNAQELBQADggEBAGNz3yHWB6pOpoEi4obVCFHofiVsiC7cjAxv
Yn3Hf2+JrfuJ/61kCWSXlOsbMYyfdMJCW8sSs3y58LgHsf2M/vF9bcGMSA5FZiLA
aGNKoji4MDEZS53H3n5j5pYc5CygOMtoVlLVOyMMIW18D/NlWGKUqjbZn5+Cbhi7
vPLmaOskoTy2DGGiJLMXFW2TJzV80vo6xJryEohxkZ7td1ZMlYI4gu/FG2jb9E12
hA9yWP4qIre+D0+puJwtkWCTYrsDwJ33s4oIPJM6TUElFKayKdYXcJuadm1HCceE
QOFZM6i06ACRSXsFIWqTWfVbyu20se4prAkoNoFgZo3de04Bi9Y=
-----END X509 CRL-----
-----BEGIN X509 CRL-----
MIIBxzCBsAIBATANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJQVDEPMA0GA1UE
CAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xETAPBgNVBAoMCFRlc3RPcmcyMREw
DwYDVQQLDAhPcmdVbml0MjEVMBMGA1UEAwwMYUNvbW1vbk5hbWUyFw0xODA5MDYx
NTU3NDVaGA8yMTAwMTAyNjE1NTc0NVqgDjAMMAoGA1UdFAQDAgEEMA0GCSqGSIb3
DQEBCwUAA4IBAQAJ+yKsrs3zehQUBdsSI+MHCtd8uWd1vpoOppduMaRfheOoCDhJ
J2n36sCfm6RTZgDrRnJJ0codj9eOM6sTjeD9PSqyJXVGHhLyOJ3bnTYlEWA5yTF5
OGTsLEpqAHyH/VNBUteKUnZesCoQ5kaAoNqDP40Idr0C4Xt7p1+6qZD4VtwWj8BI
J7AAvylVGnVoL+qjILNKEWuC5ZzYPikquGuEpPaKBjrJ7dIkHQpKaK9eK5FUkGpG
kUbmhxAOrcOMYERH1sO1LTIJVjF/UAyE3sce5euUAL8FnO+NrPXuh+cOs8+iyPTy
P/Cqr2wxM6XEl7ozmvHKU5Wr9Sc50WSSN6Hb
-----END X509 CRL-----)"};

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

TEST_F(CRLTest, testLoadCrlPemChain)
{
    auto crlList = mococrw::util::loadCrlPEMChain(crlPemChain);

    //Issuer:C = PT,ST = Porto,L = Porto,O = TestOrganization,OU = TestOrgName,CN = TestCommonName
    auto issuerName =crlList.at(0).getIssuerName();
    EXPECT_EQ("TestCommonName", issuerName.commonName());
    EXPECT_EQ("PT", issuerName.countryName());
    EXPECT_EQ("Porto", issuerName.localityName());
    EXPECT_EQ("Porto", issuerName.stateOrProvinceName());
    EXPECT_EQ("TestOrganization", issuerName.organizationName());
    EXPECT_EQ("TestOrgName", issuerName.organizationalUnitName());

    //Issuer: C = PT, ST = Lisbon, L = Lisbon, O = TestOrg2, OU = OrgUnit2, CN = aCommonName2
    issuerName =crlList.at(1).getIssuerName();
    EXPECT_EQ("PT", issuerName.countryName());
    EXPECT_EQ("TestOrg2", issuerName.organizationName());
    EXPECT_EQ("OrgUnit2", issuerName.organizationalUnitName());
    EXPECT_EQ("Lisbon", issuerName.localityName());
    EXPECT_EQ("Lisbon", issuerName.stateOrProvinceName());
    EXPECT_EQ("aCommonName2", issuerName.commonName());

}