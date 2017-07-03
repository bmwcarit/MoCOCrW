/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <gtest/gtest.h>

#include "mococrw/ca.h"
#include "mococrw/error.h"

using namespace mococrw;

class CATest : public ::testing::Test
{

public:
    void SetUp() override;
protected:
    std::unique_ptr<AsymmetricKeypair> _rootKey;

    std::unique_ptr<DistinguishedName> _certDetails;

    std::unique_ptr<DistinguishedName> _rootCertDetails;

    std::unique_ptr<X509Certificate> _rootCert;

    CertificateSigningParameters _signParams;

    std::unique_ptr<CertificateAuthority> _ca;

    std::chrono::system_clock::time_point _rootCertSignPoint;

};

void CATest::SetUp()
{
    _rootKey = std::make_unique<AsymmetricKeypair>(AsymmetricKeypair::generate());

    _certDetails = std::make_unique<DistinguishedName>(DistinguishedName::Builder{}
                 .organizationalUnitName("Car IT")
                 .organizationName("BMW")
                 .countryName("DE")
                 .commonName("BMW internal CA Certificate").build());

    _rootCertDetails = std::make_unique<DistinguishedName>(DistinguishedName::Builder{}
            .commonName("ImATeapot")
            .countryName("DE")
            .organizationName("BMW")
            .organizationalUnitName("Linux Support")
            .pkcs9EmailAddress("support@linux.bmwgroup.com")
            .localityName("oben")
            .stateOrProvinceName("nebenan")
            .serialNumber("ECU-UID:08E36DD501941432358AFE8256BC6EFD")
            .build());

    _signParams = CertificateSigningParameters::Builder{}
            .certificateValidity(std::chrono::seconds(120))
            .digestType(openssl::DigestTypes::SHA256).build();

    _rootCert = std::make_unique<X509Certificate>(CertificateAuthority::createRootCertificate(
                                                      *_rootKey,
                                                      *_rootCertDetails,
                                                      _signParams));
    _rootCertSignPoint = std::chrono::system_clock::now();

    _ca = std::make_unique<CertificateAuthority>(_signParams, *_rootCert, *_rootKey);
}

void testValiditySpan(const X509Certificate &cert,
                      std::chrono::system_clock::duration validitySpan,
                      std::chrono::system_clock::time_point certificationTime)
{
    // Check that (notAfter - notBefore = validitySpan) and (notBefore = certificationTime),
    // the last one with allowances for 1 second accuracy
    EXPECT_EQ(cert.getNotAfter() - cert.getNotBefore(), validitySpan);
    EXPECT_LT(certificationTime - cert.getNotBefore(), std::chrono::seconds(1));
    EXPECT_LT(cert.getNotBefore() - certificationTime, std::chrono::seconds(1));
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
    testValiditySpan(cert, _signParams.certificateValidity(), std::chrono::system_clock::now());
    EXPECT_EQ(csr.getPublicKey(), cert.getPublicKey());
    EXPECT_EQ(*_certDetails, cert.getSubjectDistinguishedName());
    EXPECT_EQ(_rootCert->getSubjectDistinguishedName(), cert.getIssuerDistinguishedName());
    EXPECT_NO_THROW(cert.verify({*_rootCert}, {}));
}

TEST_F(CATest, testInitializeCAWithNonMatchingKey)
{
    EXPECT_THROW(CertificateAuthority(_signParams, *_rootCert, AsymmetricKeypair::generate()),
                 MoCOCrWException);
}
