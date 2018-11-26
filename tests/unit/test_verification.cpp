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

    std::unique_ptr<CertificateRevocationList> _root3_crl;
    std::unique_ptr<CertificateRevocationList> _root3_invalidCrl;
    std::unique_ptr<CertificateRevocationList> _root3_emptycrl;
    std::unique_ptr<CertificateRevocationList> _root3_expiredcrl;
    std::unique_ptr<X509Certificate> _root3;
    std::unique_ptr<CertificateRevocationList> _root3_int1_crl;
    std::unique_ptr<CertificateRevocationList> _root3_int1_emptycrl;
    std::unique_ptr<CertificateRevocationList> _root3_int1_otherEntryCrl;
    std::unique_ptr<X509Certificate> _root3_int1;
    std::unique_ptr<X509Certificate> _root3_int1_int11;
    std::unique_ptr<CertificateRevocationList> _root3_int1_int11_emptycrl;
    std::unique_ptr<X509Certificate> _root3_int1_cert12;

    std::unique_ptr<X509Certificate> _eccRoot;
    std::unique_ptr<X509Certificate> _eccIntermediate;
    std::unique_ptr<X509Certificate> _eccUser;
    std::unique_ptr<X509Certificate> _eccExpiredCert;
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

    _root3 = std::make_unique<X509Certificate>(loadCertFromFile("root3.pem"));
    _root3_crl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.crl.pem"));
    _root3_invalidCrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.crl_invalidsignature.pem"));
    _root3_emptycrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.crl_empty.pem"));
    _root3_expiredcrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.crl_expired.pem"));
    _root3_int1 = std::make_unique<X509Certificate>(loadCertFromFile("root3.int1.pem"));
    _root3_int1_crl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.int1.crl.pem"));
    _root3_int1_emptycrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.int1.crl_empty.pem"));
    _root3_int1_otherEntryCrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.int1.crl_otherentry.pem"));
    _root3_int1_int11 = std::make_unique<X509Certificate>(loadCertFromFile("root3.int1.int11.pem"));
    _root3_int1_int11_emptycrl = std::make_unique<CertificateRevocationList>(loadCrlFromFile("root3.int1.int11.crl_empty.pem"));
    _root3_int1_cert12 = std::make_unique<X509Certificate>(loadCertFromFile("root3.int1.cert12.pem"));

    _eccRoot = std::make_unique<X509Certificate>(loadCertFromFile("eccRootCertificate.pem"));
    _eccIntermediate = std::make_unique<X509Certificate>(loadCertFromFile("eccIntermediateCertificate.pem"));
    _eccUser = std::make_unique<X509Certificate>(loadCertFromFile("eccUserCertificate.pem"));

    _eccExpiredCert = std::make_unique<X509Certificate>(loadCertFromFile("eccExpiredcertificate.pem"));
}

using VerificationContext = mococrw::X509Certificate::VerificationContext;

TEST_F(VerificationTest, testSimpleCertValidation)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testSimpleCertValidationEcc)
{
    std::vector<X509Certificate> trustStore{*_eccRoot.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_eccIntermediate->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testExpiredCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_expired->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testExpiredEccCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_eccRoot.get()};
    std::vector<X509Certificate> intermediateCAs{};
    EXPECT_THROW({
        try {
            _eccExpiredCert->verify(trustStore, intermediateCAs);
        }
        catch (const MoCOCrWException &e) {
            EXPECT_STREQ("certificate has expired", e.what());
                throw;
        }
    }, MoCOCrWException);
}

TEST_F(VerificationTest, testPastCertValidationSucceedsWithTimeSetAccordingly)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1_expired.get())
       .setVerificationCheckTime(_root1_expired->getNotBeforeAsn1() + Asn1Time::Seconds(1));

    ASSERT_NO_THROW(_root1_expired->verify(ctx));
}

TEST_F(VerificationTest, testPastCertValidationFailsWithTimeSetToNow)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1_expired.get())
       .setVerificationCheckTime(Asn1Time::now());

    ASSERT_THROW(_root1_expired->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testFutureCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_future->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testFutureCertValidationFailsWithTimeSetToNow)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1.get())
       .setVerificationCheckTime(Asn1Time::now());

    ASSERT_THROW(_root1_future->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testFutureCertValidationSucceedsWithTimeSetAccordingly)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1_future.get())
       .setVerificationCheckTime(_root1_future->getNotBeforeAsn1() + Asn1Time::Seconds(1));

    _root1_future->verify(ctx);
}

TEST_F(VerificationTest, testCertValidationFailsWithTimeInFuture)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1.get())
       .setVerificationCheckTime(_root1->getNotAfterAsn1() + Asn1Time::Seconds(1));

    ASSERT_THROW(_root1->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testCertValidationFailsWithTimeInPast)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1.get())
       .setVerificationCheckTime(_root1->getNotBeforeAsn1() - Asn1Time::Seconds(1));

    ASSERT_THROW(_root1->verify(ctx), MoCOCrWException);
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

TEST_F(VerificationTest, testVerificationWorksWithIntermediateInTruststoreEcc)
{
    std::vector<X509Certificate> trustStore{*_eccIntermediate.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_eccUser->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testChainVerificationLen1Works)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get()};

    ASSERT_NO_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testChainVerificationLen1WorksEcc)
{
    std::vector<X509Certificate> trustStore{*_eccRoot.get()};
    std::vector<X509Certificate> intermediateCAs{*_eccIntermediate.get()};

    ASSERT_NO_THROW(_eccUser->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testChainVerificationFailsWithWrongIntermediate)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int2.get()};

    ASSERT_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(VerificationTest, testChainVerificationFailsWithWrongIntermediateEcc)
{
    std::vector<X509Certificate> trustStore{*_eccRoot.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int2.get()};

    ASSERT_THROW(_eccUser->verify(trustStore, intermediateCAs), MoCOCrWException);
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

TEST_F(VerificationTest, testCompleteChainVerificationFailsWithWrongRootEcc)
{
    std::vector<X509Certificate> trustStore{*_root2.get()};
    std::vector<X509Certificate> intermediateCAs{*_eccRoot.get(), *_eccIntermediate.get()};

    ASSERT_THROW(_eccUser->verify(trustStore, intermediateCAs), MoCOCrWException);
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

TEST_F(VerificationTest, testVerificationWorksWithUnusedElementsInChainParamEcc)
{
    std::vector<X509Certificate> trustStore{*_eccRoot.get()};
    std::vector<X509Certificate> intermediateCAs{*_eccIntermediate.get(), *_root1_int1.get(),
                                                 *_root1_int2.get()};

    ASSERT_NO_THROW(_eccUser->verify(trustStore, intermediateCAs));
}

TEST_F(VerificationTest, testVerificationWorksWithBothRootsInTruststore)
{
    std::vector<X509Certificate> trustStore{*_root1.get(), *_root2.get(), *_eccRoot.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root2_int1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_eccIntermediate->verify(trustStore, intermediateCAs));
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

TEST_F(VerificationTest, testVerificationFailsWithNonSelfSignedRootAndFlag)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root1_int1.get())
       .enforceSelfSignedRootCertificate();

    ASSERT_THROW(_root1_int1_cert1->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationFailsWithNonSelfSignedRootAndFlagEcc)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_eccIntermediate.get())
            .enforceSelfSignedRootCertificate();

    ASSERT_THROW(_eccUser->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testSimpleVerificationOfRevokedCertificateFails)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get());

    ASSERT_NO_THROW(_root3_int1->verify(ctx));

    ctx.addCertificateRevocationList(*_root3_crl.get());
    ASSERT_THROW(_root3_int1->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWithEmptyCrlSucceeds)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addCertificateRevocationList(*_root3_emptycrl.get());
    ASSERT_NO_THROW(_root3_int1->verify(ctx));
}

TEST_F(VerificationTest, testVerificationWithInvalidCrlFails)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addCertificateRevocationList(*_root3_invalidCrl.get());
    ASSERT_THROW(_root3_int1->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWithRevokedEndCertificateFails)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_int1_crl.get());
    ASSERT_THROW(_root3_int1_int11->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWithoutRootCACrlSucceeds)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_int1_emptycrl.get());
    ASSERT_NO_THROW(_root3_int1_int11->verify(ctx));
}

TEST_F(VerificationTest, testVerificationWithRevokedIntermediateCertificateSucceedsWithoutFlag)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_crl.get())
       .addCertificateRevocationList(*_root3_int1_emptycrl.get());
    ASSERT_NO_THROW(_root3_int1_int11->verify(ctx));
}

TEST_F(VerificationTest, testVerificationWithRevokedIntermediateCertificateFailsWithSetFlag)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_crl.get())
       .addCertificateRevocationList(*_root3_int1_emptycrl.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();
    ASSERT_THROW(_root3_int1_int11->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWithCrlWithOtherEntrySucceeds)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_emptycrl.get())
       .addCertificateRevocationList(*_root3_int1_otherEntryCrl.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();
    ASSERT_NO_THROW(_root3_int1_int11->verify(ctx));
}

TEST_F(VerificationTest, testVerificationWithMissingCrlFails)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_int1_emptycrl.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();
    ASSERT_THROW(_root3_int1_int11->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWithExpiredCrlFails)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addCertificateRevocationList(*_root3_expiredcrl.get());
    ASSERT_THROW(_root3_int1->verify(ctx), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationWithAdditionalCertificatesSucceeds)
{
    VerificationContext ctx;
    ctx.addTrustedCertificates({*_root3.get(), *_root2.get()})
       .addIntermediateCertificates({*_root3_int1.get(), *_root1_int1.get()})
       .addCertificateRevocationList(*_root3_emptycrl.get())
       .addCertificateRevocationList(*_root3_int1_emptycrl.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();
    ASSERT_NO_THROW(_root3_int1_int11->verify(ctx));
}

TEST_F(VerificationTest, testVerificationWithAdditionalCrlSucceeds)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3_int1.get())
       .addCertificateRevocationList(*_root3_emptycrl.get())
       .addCertificateRevocationList(*_root3_int1_emptycrl.get())
       .addCertificateRevocationList(*_root3_int1_int11_emptycrl.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();
    ASSERT_NO_THROW(_root3_int1_cert12->verify(ctx));
}

MATCHER(PemEq, "") {
  return std::get<0>(arg).toPEM() == std::get<1>(arg).toPEM();
}

TEST_F(VerificationTest, testThatLValueVectorsAreCopiedToContext)
{
    std::vector<X509Certificate> certs{*_root3.get(), *_root1.get()};
    std::vector<X509Certificate> expectedCerts = certs;

    VerificationContext ctx;
    ctx.addTrustedCertificates(certs);
    EXPECT_THAT(certs, testing::Pointwise(PemEq(), expectedCerts));

    EXPECT_NO_THROW(_root3->verify(ctx));
    EXPECT_NO_THROW(_root1->verify(ctx));
}

TEST_F(VerificationTest, testThatLValueInitializerListsAreCopiedToContext)
{
    std::initializer_list<X509Certificate> certs{*_root3.get(), *_root1.get()};
    std::initializer_list<X509Certificate> expectedCerts = certs;

    VerificationContext ctx;
    ctx.addTrustedCertificates(certs);
    EXPECT_THAT(certs, testing::Pointwise(PemEq(), expectedCerts));

    EXPECT_NO_THROW(_root3->verify(ctx));
    EXPECT_NO_THROW(_root1->verify(ctx));
}

void putCertsInContext(std::initializer_list<X509Certificate>& certs)
{
    VerificationContext ctx;
    ctx.addTrustedCertificates(certs);
}

TEST_F(VerificationTest, testThatLValueInitializerListsAreCopiedToContextAndDontExpireWithIt)
{
    std::initializer_list<X509Certificate> certs{*_root3.get(), *_root1.get()};
    std::initializer_list<X509Certificate> expectedCerts{*_root3.get(), *_root1.get()};

    putCertsInContext(certs);

    EXPECT_THAT(certs, testing::Pointwise(PemEq(), expectedCerts));

    {
        VerificationContext ctx;
        ctx.addTrustedCertificates(certs);
    }

    EXPECT_THAT(certs, testing::Pointwise(PemEq(), expectedCerts));
}

TEST_F(VerificationTest, testThatRvalueVectorIsPassedToContext)
{
    std::vector<X509Certificate> certs{*_root3.get(), *_root1.get()};

    VerificationContext ctx;
    ctx.addTrustedCertificates(std::move(certs));

    EXPECT_NO_THROW(_root3->verify(ctx));
    EXPECT_NO_THROW(_root1->verify(ctx));
}

TEST_F(VerificationTest, testThatRvalueInitializerListIsPassedToContext)
{
    std::initializer_list<X509Certificate> certs{*_root3.get(), *_root1.get()};

    VerificationContext ctx;
    ctx.addTrustedCertificates(std::move(certs));

    EXPECT_NO_THROW(_root3->verify(ctx));
    EXPECT_NO_THROW(_root1->verify(ctx));
}

TEST_F(VerificationTest, testVerificationContextWithCrlsIsValid)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3.get())
       .addCertificateRevocationList(*_root3_emptycrl.get());

    EXPECT_NO_THROW(ctx.validityCheck());
}

TEST_F(VerificationTest, testVerificationContextWithSelfSignedRootIsValid)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3.get())
       .enforceSelfSignedRootCertificate();

    EXPECT_NO_THROW(ctx.validityCheck());
}

TEST_F(VerificationTest, testVerificationContextWithCrlCheckAllAndSelfSignedRootAndCrlsIsValid)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3.get())
       .addCertificateRevocationList(*_root3_emptycrl.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();

    EXPECT_NO_THROW(ctx.validityCheck());
}

TEST_F(VerificationTest, testVerificationContextWithCrlCheckAllWithoutSelfSignedRootIsNotValid)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3.get())
       .addCertificateRevocationList(*_root3_emptycrl.get())
       .enforceCrlsForAllCAs();

    EXPECT_THROW(ctx.validityCheck(), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationContextWithCrlCheckAllWithoutCrlsIsNotValid)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3.get())
       .enforceCrlsForAllCAs()
       .enforceSelfSignedRootCertificate();

    EXPECT_THROW(ctx.validityCheck(), MoCOCrWException);
}

TEST_F(VerificationTest, testVerificationContextWithCrlCheckAllWithoutSelfSignedRootOrCrlsIsNotValid)
{
    VerificationContext ctx;
    ctx.addTrustedCertificate(*_root3.get())
       .addIntermediateCertificate(*_root3.get())
       .enforceCrlsForAllCAs();

    EXPECT_THROW(ctx.validityCheck(), MoCOCrWException);
}
