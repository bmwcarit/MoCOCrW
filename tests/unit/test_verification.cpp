/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <fstream>
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "IOUtils.h"

#include "mococrw/error.h"
#include "mococrw/x509.h"

using namespace std::string_literals;

using namespace mococrw;
using namespace mococrw::openssl;

class VerificationTest : public ::testing::Test
{
public:
    void SetUp() override;
protected:
    std::unique_ptr<X509Certificate> _root1;
    std::unique_ptr<X509Certificate> _root1_cert1;
    std::unique_ptr<X509Certificate> _root1_future;
    std::unique_ptr<X509Certificate> _root1_expired;
    std::unique_ptr<X509Certificate> _root1_int1;
    std::unique_ptr<X509Certificate> _root1_int1_cert1;
    std::unique_ptr<X509Certificate> _root1_int1_int11;
    std::unique_ptr<X509Certificate> _root1_int1_int11_cert1;
    std::unique_ptr<X509Certificate> _root1_int1_int11_cert2;
    std::unique_ptr<X509Certificate> _root1_int2;
    std::unique_ptr<X509Certificate> _root1_int2_int21;
    std::unique_ptr<X509Certificate> _root1_int2_int21_cert1;

    std::unique_ptr<X509Certificate> _root2;
    std::unique_ptr<X509Certificate> _root2_int1;
    std::unique_ptr<X509Certificate> _root2_int1_cert1;

};

void VerificationTest::SetUp()
{
    _root1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.pem"));
    _root1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.cert1.pem"));
    _root1_future = std::make_unique<X509Certificate>(loadCertFromFile("root1.future.pem"));
    _root1_expired = std::make_unique<X509Certificate>(loadCertFromFile("root1.expired.pem"));
    _root1_int1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.pem"));
    _root1_int1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.cert1.pem"));
    _root1_int1_int11 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.int11.pem"));
    _root1_int1_int11_cert1 =
        std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.int11.cert1.pem"));
    _root1_int1_int11_cert2 =
        std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.int11.cert2.pem"));
    _root1_int2 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int2.pem"));
    _root1_int2_int21 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int2.int21.pem"));
    _root1_int2_int21_cert1 =
        std::make_unique<X509Certificate>(loadCertFromFile("root1.int2.int21.cert1.pem"));

    _root2 = std::make_unique<X509Certificate>(loadCertFromFile("root2.pem"));
    _root2_int1 = std::make_unique<X509Certificate>(loadCertFromFile("root2.int1.pem"));
    _root2_int1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root2.int1.cert1.pem"));
}

TEST_F(VerificationTest, testSimpleCertValidation)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testExpiredCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_expired->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testFutureCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_future->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testSimpleCertValidationWorksForSubCA)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testVerificationsFailsWithEmptyTrustRoot)
{
    std::vector<X509Certificate> trustStore{};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWorksWithIntermediateInTruststore)
{
    std::vector<X509Certificate> trustStore{*_root1_int1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testChainVerificationLen1Works)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get()};

    ASSERT_NO_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testChainVerificationFailsWithWrongIntermediate)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int2.get()};

    ASSERT_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testVerficationsFailsWithEmptyTruststoreButRootAsIntermediate)
{
    std::vector<X509Certificate> trustStore{};
    std::vector<X509Certificate> intermediateCAs{*_root1.get()};

    ASSERT_THROW(_root1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationFailsForTheRootCAWhenTruststoreIsEmpty)
{
    std::vector<X509Certificate> trustStore{};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testChainVerificationLen2Works)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get(), *_root1_int1_int11.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root1_int1_int11_cert2->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testChainVerificationLen2WorksWithOtherOrderForIntermediates)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1_int11.get(), *_root1_int1.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
}

/* We want to see that the verifcation respects the path len constraint in CA certificates
 * Towards this purpose we wake _root1_int2 which has a pathlen of 0.
 * This means that it can issue certificates but these certificates can
 * not be used to sign themselves again.
 * For testing purposes, _root1_int2_int21 is a certificate with CA flag. We used it to sign
 * _root1_int2_int21_cert1. However, this cert violates the path len constraint of root1_int2.
 * Consequently, verification should fail here.
 */
TEST_F(VerificationTest, testIfCAPathLenIsRespected)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int2.get(), *_root1_int2_int21.get()};

    ASSERT_THROW(_root1_int2_int21_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testCompleteChainVerificationFailsWithWrongRoot)
{
    std::vector<X509Certificate> trustStore{*_root2.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1.get(), *_root1_int1.get(), *_root1_int1_int11.get()};

    ASSERT_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testOpenSSLPartialVerificationWithIntermediateInTruststoreWorks)
{
    std::vector<X509Certificate> trustStore{*_root1_int1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1_int11.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testVerificationWorksWithUnusedElementsInChainParam)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1_int11.get(), *_root1_int1.get(),
                                                 *_root1_int2.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testVerificationWorksWithBothRootsInTruststore)
{
    std::vector<X509Certificate> trustStore{*_root1.get(), *_root2.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root2_int1->verify(trustStore, intermediateCAs));
}

/*
 * We want to see if we can use verification for two roots and different chains
 * if we put all the necessary information in truststore and intermediates.
 */
TEST_F(VerificationTest, testVerificationWorksWithBothRootsInTrustStoreComplexChains)
{
    std::vector<X509Certificate> trustStore{*_root1.get(), *_root2.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get(), *_root2_int1.get()};

    (_root1_int1_cert1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root2_int1_cert1->verify(trustStore, intermediateCAs));
}
