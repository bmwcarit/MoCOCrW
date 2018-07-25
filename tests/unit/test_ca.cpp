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

#include <string>
#include <fstream>
#include <cstdio>

#include "mococrw/basic_constraints.h"
#include "mococrw/ca.h"
#include "mococrw/error.h"
#include "mococrw/key_usage.h"

using namespace mococrw;
using namespace std::string_literals;

class CATest : public ::testing::Test
{

public:
    void SetUp() override;
protected:
    std::unique_ptr<AsymmetricKeypair> _rootKey;

    std::unique_ptr<DistinguishedName> _certDetails;

    std::unique_ptr<DistinguishedName> _secondaryCertDetails;

    std::unique_ptr<DistinguishedName> _rootCertDetails;

    std::unique_ptr<X509Certificate> _rootCert;

    std::unique_ptr<KeyUsageExtension> _exampleUsage;

    std::unique_ptr<BasicConstraintsExtension> _exampleConstraints;

    CertificateSigningParameters _signParams;

    CertificateSigningParameters _caSignParams;

    std::unique_ptr<CertificateAuthority> _ca;

    Asn1Time _rootCertSignPoint = Asn1Time::fromTimeT(0);

};

void CATest::SetUp()
{
    _rootKey = std::make_unique<AsymmetricKeypair>(AsymmetricKeypair::generate());

    _certDetails = std::make_unique<DistinguishedName>(DistinguishedName::Builder{}
                 .organizationalUnitName("Car IT")
                 .organizationName("BMW")
                 .countryName("DE")
                 .commonName("BMW internal CA Certificate").build());

    _secondaryCertDetails = std::make_unique<DistinguishedName>(DistinguishedName::Builder{}
                 .organizationalUnitName("Car IT")
                 .organizationName("BMW")
                 .countryName("DE")
                 .commonName("BMW internal secondary Certificate").build());

    _rootCertDetails = std::make_unique<DistinguishedName>(DistinguishedName::Builder{}
            .commonName("ImATeapot")
            .countryName("DE")
            .organizationName("Linux AG")
            .organizationalUnitName("Linux Support")
            .pkcs9EmailAddress("support@example.com")
            .localityName("oben")
            .stateOrProvinceName("nebenan")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .build());

    _exampleConstraints = std::make_unique<BasicConstraintsExtension>(false, 0);
    _exampleUsage = std::make_unique<KeyUsageExtension>(KeyUsageExtension::Builder{}.digitalSignature()
                                               .keyCertSign().cRLSign().build());

    BasicConstraintsExtension caConstraint{true, 1};

    _signParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .notBeforeAsn1(Asn1Time::now())
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(*_exampleConstraints)
            .addExtension(*_exampleUsage)
            .build();

    _caSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(caConstraint)
            .addExtension(*_exampleUsage)
            .build();

    _rootCert = std::make_unique<X509Certificate>(CertificateAuthority::createRootCertificate(
                                                      *_rootKey,
                                                      *_rootCertDetails,
                                                      0,
                                                      _caSignParams));
    _rootCertSignPoint = Asn1Time::now();

    _ca = std::make_unique<CertificateAuthority>(_signParams, 1, *_rootCert, *_rootKey);
}


std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != NULL) {
               result += buffer.data();
        }

    }
    return result;
}

void testValiditySpan(const X509Certificate &cert,
                      Asn1Time::Seconds validitySpan,
                      Asn1Time certificationTime)
{
    // Check that (notAfter - notBefore = validitySpan) and (notBefore = certificationTime),
    // the last one with allowances for 2 second accuracy
    EXPECT_EQ(cert.getNotAfterAsn1() - cert.getNotBeforeAsn1(), validitySpan);
    EXPECT_LT(certificationTime - cert.getNotBeforeAsn1(), Asn1Time::Seconds(2));
    EXPECT_LT(cert.getNotBeforeAsn1() - certificationTime, Asn1Time::Seconds(2));
}

TEST_F(CATest, testAddExtensionWithSharedPointer)
{
    std::shared_ptr<ExtensionBase> extensionPtr =
            std::make_shared<BasicConstraintsExtension>(true, 1);

    EXPECT_NO_THROW(CertificateSigningParameters::Builder{}
                .certificateValidity(Asn1Time::Seconds(120))
                .notBeforeAsn1(Asn1Time::now())
                .digestType(openssl::DigestTypes::SHA256)
                .addExtension(extensionPtr)
                .build());
}

TEST_F(CATest, testBuildSignParamsWithExtensions)
{
    //one extension
    EXPECT_NO_THROW(CertificateSigningParameters::Builder{}
                .certificateValidity(Asn1Time::Seconds(120))
                .notBeforeAsn1(Asn1Time::now())
                .digestType(openssl::DigestTypes::SHA256)
                .addExtension(*_exampleConstraints)
                .build());

    //Two extensions
    EXPECT_NO_THROW(CertificateSigningParameters::Builder{}
                .certificateValidity(Asn1Time::Seconds(120))
                .notBeforeAsn1(Asn1Time::now())
                .digestType(openssl::DigestTypes::SHA256)
                .addExtension(*_exampleConstraints)
                .addExtension(*_exampleUsage)
                .build());
}

TEST_F(CATest, testRequestNotExistingExtension)
{
    CertificateSigningParameters cert = CertificateSigningParameters::Builder{}
                    .certificateValidity(Asn1Time::Seconds(120))
                    .notBeforeAsn1(Asn1Time::now())
                    .digestType(openssl::DigestTypes::SHA256)
                    .addExtension(*_exampleConstraints)
                    .build();

    EXPECT_THROW(cert.extension<KeyUsageExtension>(), MoCOCrWException);
}

TEST_F(CATest, testBuildSignParamsOneExtensionTwice)
{
    BasicConstraintsExtension constraint{true, 1};
    //an existing extension is overwritten and not added twice
    CertificateSigningParameters params = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .notBeforeAsn1(Asn1Time::now())
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(*_exampleConstraints)
            .addExtension(*_exampleUsage)
            .addExtension(constraint)
            .build();

    EXPECT_EQ(params.extensionMap().size(), 2);
    auto basicConstraints = params.extension<BasicConstraintsExtension>();
    EXPECT_EQ(constraint.getConfigurationString(), basicConstraints->getConfigurationString());

}

TEST_F(CATest, testIterateOnExtensionMap)
{
    std::map<openssl::X509Extension_NID, std::string> compareStringMap{
        {openssl::X509Extension_NID::BasicConstraints,
                    _exampleConstraints->getConfigurationString()},
        {openssl::X509Extension_NID::KeyUsage, _exampleUsage->getConfigurationString()}};

    for (auto &it : _signParams.extensionMap()) {
        EXPECT_EQ(it.second.get()->getConfigurationString(), compareStringMap[it.first]);
    }

    EXPECT_EQ(2, _signParams.extensionMap().size());
}

TEST_F(CATest, testCreateRootCertificate)
{
    testValiditySpan(*_rootCert, _signParams.certificateValidity(),
                     _rootCertSignPoint);
    EXPECT_EQ(*_rootCertDetails, _rootCert->getIssuerDistinguishedName());
    EXPECT_EQ(*_rootCertDetails, _rootCert->getSubjectDistinguishedName());
    EXPECT_EQ(*_rootKey, _rootCert->getPublicKey());
    EXPECT_NO_THROW(_rootCert->verify({*_rootCert}, {}));
}

TEST_F(CATest, testCAContents)
{
    EXPECT_EQ(_rootCert->toPEM(), _ca->getRootCertificate().toPEM());
    EXPECT_EQ(_signParams, _ca->getSignParams());
}

TEST_F(CATest, testSignedCSRHasCorrectFields)
{
    CertificateSigningRequest csr{*_certDetails, AsymmetricKeypair::generate()};
    X509Certificate cert = _ca->signCSR(csr);
    testValiditySpan(cert, _signParams.certificateValidity(), Asn1Time::now());
    EXPECT_EQ(csr.getPublicKey(), cert.getPublicKey());
    EXPECT_EQ(*_certDetails, cert.getSubjectDistinguishedName());
    EXPECT_EQ(_rootCert->getSubjectDistinguishedName(), cert.getIssuerDistinguishedName());
    EXPECT_NO_THROW(cert.verify({*_rootCert}, {}));
}

TEST_F(CATest, testCanSignCACertificates)
{
    //Adjust CA to generate CA certificates
    _ca = std::make_unique<CertificateAuthority>(_caSignParams, 0, *_rootCert, *_rootKey);

    auto keypair = AsymmetricKeypair::generate();
    CertificateSigningRequest csr{*_certDetails, keypair};
    X509Certificate cert = _ca->signCSR(csr);
    CertificateAuthority newCA(_signParams, 0, cert, keypair);
    csr = CertificateSigningRequest{*_secondaryCertDetails, AsymmetricKeypair::generate()};
    X509Certificate secondaryCert = newCA.signCSR(csr);
    ASSERT_NO_THROW(secondaryCert.verify({*_rootCert}, {cert}));
}

TEST_F(CATest, testSignedNoCACertificatesCantSignOtherCertificates)
{
    auto keypair = AsymmetricKeypair::generate();
    CertificateSigningRequest csr{*_certDetails, keypair};
    X509Certificate cert = _ca->signCSR(csr);
    // The newly created certificate has CA=false
    CertificateAuthority newCA(_signParams, 0, cert, keypair);
    csr = CertificateSigningRequest{*_certDetails, AsymmetricKeypair::generate()};
    // The signing fails because the certificate has CA=false
    ASSERT_THROW(newCA.signCSR(csr), MoCOCrWException);
}

TEST_F(CATest, testInitializeCAWithNonMatchingKey)
{
    EXPECT_THROW(CertificateAuthority(_signParams, 0, *_rootCert, AsymmetricKeypair::generate()),
                 MoCOCrWException);
}

TEST_F(CATest, testVerifyCAAgainstPureOpenSslOutput)
{
    auto keypair = AsymmetricKeypair::generate();
    CertificateSigningRequest csr{*_certDetails, keypair};
    X509Certificate cert = _ca->signCSR(csr);

    std::string tmpfile = std::tmpnam(nullptr);
    std::ofstream file(tmpfile);
    ASSERT_TRUE(file.good()) << "Cannot open tmpfile to write certificate for openssl inspection";
    file << cert.toPEM();
    ASSERT_TRUE(file.good()) << "Writing of certificate for openssl inspection failed";
    file.close();

    std::string opensslCommandline = "openssl x509 -in "s + tmpfile + " -noout -text";
    std::string output = exec(opensslCommandline.c_str());
    std::remove(tmpfile.c_str());

    EXPECT_NE(output.find("Issuer: CN=ImATeapot, C=DE, L=oben, ST=nebenan, OU=Linux Support"),
              std::string::npos);

    EXPECT_NE(output.find("Subject: CN=BMW internal CA Certificate, C=DE, OU=Car IT, O=BMW"),
              std::string::npos);

    EXPECT_NE(output.find("X509v3 Key Usage: critical"), std::string::npos);
    EXPECT_NE(output.find("Digital Signature, Certificate Sign, CRL Sign"), std::string::npos);
    EXPECT_NE(output.find("X509v3 Basic Constraints: critical"), std::string::npos);
    EXPECT_NE(output.find("CA:FALSE"), std::string::npos);

    remove("cert.pem");
}

TEST_F(CATest, testIssueLongLivedCertificate)
{
    // Certificate shall be valid for 1000 years
    Asn1Time::Seconds validityTime(60l * 60 * 24 * 365 * 1000);
    _signParams = CertificateSigningParameters::Builder{}
            .certificateValidity(validityTime)
            .notBeforeAsn1(Asn1Time::now())
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(*_exampleConstraints)
            .addExtension(*_exampleUsage)
            .build();

    _ca = std::make_unique<CertificateAuthority>(_signParams, 0, *_rootCert, *_rootKey);

    X509Certificate cert = _ca->signCSR(CertificateSigningRequest{*_certDetails,
                                                       AsymmetricKeypair::generate()});

    testValiditySpan(cert, validityTime, Asn1Time::now());

}

// This test requires the ability to set the time for which a certificate is verified.
TEST_F(CATest, DISABLED_testIssueCertificateInFarFuture)
{
    // Certificate shall be valid in 1000 years
    Asn1Time validFrom = Asn1Time::now() + Asn1Time::Seconds(60l * 60 * 24 * 365 * 1000);
    Asn1Time::Seconds validityTime(120);
    _signParams = CertificateSigningParameters::Builder{}
            .certificateValidity(validityTime)
            .notBeforeAsn1(validFrom)
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(*_exampleConstraints)
            .addExtension(*_exampleUsage)
            .build();

    _ca = std::make_unique<CertificateAuthority>(_signParams, 0, *_rootCert, *_rootKey);

    X509Certificate cert = _ca->signCSR(CertificateSigningRequest{*_certDetails,
                                                       AsymmetricKeypair::generate()});

    testValiditySpan(cert, validityTime, validFrom);

}
