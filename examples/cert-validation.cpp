/*
 * #%L
 * %%
 * Copyright (C) 2022 BMW Car IT GmbH
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
#include <iostream>

#include <mococrw/x509.h>

using namespace mococrw;

int main()
{
    X509Certificate rootCA = X509Certificate::fromPEMFile("root3.pem");
    X509Certificate intermediateCA = X509Certificate::fromPEMFile("root3.int1.pem");
    X509Certificate intermediateCA_1 = X509Certificate::fromPEMFile("root3.int1.int11.pem");

    CertificateRevocationList rootCRL = CertificateRevocationList::fromPEMFile("root3.crl.pem");
    CertificateRevocationList intermediateCRL = CertificateRevocationList::fromPEMFile("root3.int1.crl_otherentry.pem");

    X509Certificate cert = X509Certificate::fromPEMFile("root3.int1.cert.pem");
    X509Certificate cert_from_other_chain = X509Certificate::fromPEMFile("root1.cert1.pem");

   /* Certificate chain is constructed as follows:
    *    _______           _______           ______
    *   |       |  signs  |       |  signs  |      |
    *   |root CA|-------->|int CA |-------->| cert |
    *   |_______|         |_______|         |______|
    *
    *  These artifacts are taken from `tests` folder in the repo
    *  for demonstration purposes.
    */

    /*
     *   Basic certificate validation using X509Certificate::verify() against
     *   issuing CA
     */
    {
        std::cout << "Validating certificate against an issuing CA" << std::endl;
        try {
            cert.verify({intermediateCA}, {});
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed to validate certificate. OpenSSL error: " << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
        std::cout << "Certificate successfully validated\n---" << std::endl;
    }

    /*
     *   Basic certificate validation using X509Certificate::verify() against
     *   issuing certificate chain. X509Certificate::verify() method can accept
     *   a vector of trusted root CAs or a vector of intermediate CAs where
     *   not all of them have to be used in a validation process.
     */
    {
        std::cout << "Validating certificate against certificate chain" << std::endl;
        try {
            cert.verify({rootCA}, {intermediateCA});
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed to validate certificate. OpenSSL error: " << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
        std::cout << "Certificate successfully validated\n---" << std::endl;
    }

    /*
     *   Basic positive case - CA -> cert validation using VerificationContext class.
     *   VerificationContext is a class that can be used to define the "environment"
     *   in which x509 certificates are validated. This makes it easy to setup custom
     *   validation rules upfront and then validate the certificates according to the
     *   rules.
     *
     *   If validation fails, MoCOCrW exception is thrown that contains error
     *   message from the underlying openssl library.
     */
    std::cout << "\n*** Certificate validation examples using VerificationContext ***\n" << std::endl;
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(intermediateCA);
        std::cout << "Validating certificate against an issuing CA" << std::endl;
        try {
            cert.verify(ctx);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed to validate certificate. OpenSSL error: " << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
        std::cout << "Certificate successfully validated\n---" << std::endl;
    }

    /*
     *   Basic positive case - cert validation within certificate chain using
     *   VerificationContext
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(rootCA)
           .addIntermediateCertificate(intermediateCA);
        std::cout << "Validating certificate against certificate chain" << std::endl;
        try {
            cert.verify(ctx);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed to validate certificate. OpenSSL error: " << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
        std::cout << "Certificate inside certificate chain successfully validated\n---" << std::endl;
    }

    /*
     *   Negative case - Validation attempt of the certificate issued by other CAs.
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(rootCA)
           .addIntermediateCertificate(intermediateCA);
        std::cout << "Verifying certificate that is issued from other CAs" << std::endl;
        try {
            cert_from_other_chain.verify(ctx);
            std::cerr << "Exception should be thrown. Something's wrong." << std::endl;
            exit(EXIT_FAILURE);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed as expected. OpenSSL error: " << e.what() << std::endl;
        }
        std::cout << "---" << std::endl;
    }

    /*
     *   Enforce self signed root certificate in VerificationContext using
     *   enforceSelfSignedRootCertificate(). In this case root CA certificate
     *   is self-signed so exception is not expected.
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(rootCA)
           .addIntermediateCertificate(intermediateCA)
           .enforceSelfSignedRootCertificate();
        std::cout << "Checking if root certificate is self signed" << std::endl;
        try {
            cert.verify(ctx);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Root certificate probably not self signed. OpenSSL error: " << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
        std::cout << "Root certificate is self signed\n---" << std::endl;
    }

    /*
     *   Enforce self signed root certificate in VerificationContext using
     *   enforceSelfSignedRootCertificate(). In this case intermediate CA
     *   certificate is not self-signed so exception is expected.
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(intermediateCA)
           .enforceSelfSignedRootCertificate();
        std::cout << "Checking if intermediate certificate is self signed" << std::endl;
        try {
            rootCA.verify(ctx);
            std::cerr << "Exception should be thrown. Something's wrong." << std::endl;
            exit(EXIT_FAILURE);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed as expected. OpenSSL error: " << e.what() << std::endl;
        }
        std::cout << "---" << std::endl;
    }

    /*
     *   Add CRL to VerificationContext for intermediate CA which has
     *   ceritificate stored in variable `cert` revoked (serial number 0x1002).
     *   CRLs are added with addCertificateRevocationList() method.
     *   Exception is thrown because validated certificate is a part of
     *   root CA's CRL.
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(rootCA)
           .addIntermediateCertificate(intermediateCA)
           .addCertificateRevocationList(intermediateCRL);
        std::cout << "Checking if certificate is revoked" << std::endl;
        try {
            cert.verify(ctx);
            std::cerr << "Exception should be thrown. Something's wrong." << std::endl;
            exit(EXIT_FAILURE);
        } catch (const MoCOCrWException &e) {
            std::cout << "Failed as expected. OpenSSL error: " << e.what() << std::endl;
        }
        std::cout << "---" << std::endl;
    }

    /*
     *   Intermediate CA is missing CRL but enforceCrlsForAllCAs is set.
     *   Exception is expected.
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(rootCA)
           .addIntermediateCertificate(intermediateCA)
           .addCertificateRevocationList(rootCRL)
           .enforceCrlsForAllCAs()
           .enforceSelfSignedRootCertificate();
        std::cout << "Checking enforcement of CRLs" << std::endl;
        try {
            cert.verify(ctx);
            std::cerr << "Exception should be thrown. Something's wrong." << std::endl;
            exit(EXIT_FAILURE);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed as expected. OpenSSL error: " << e.what() << std::endl;
        }
        std::cout << "---" << std::endl;
    }

    /*
     *   Adding custom time in VerificationContext. The VerificationContext also allows
     *   the caller to specify a specific time (and date) that should be used for
     *   certificate validation instead of the current system time.
     */
    {
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificate(rootCA)
           .addIntermediateCertificate(intermediateCA)
           .addCertificateRevocationList(rootCRL)
           .addCertificateRevocationList(intermediateCRL)
           .enforceCrlsForAllCAs()
           .enforceSelfSignedRootCertificate()
           .setVerificationCheckTime(Asn1Time::max());
        std::cout << "Validating certificate in future when stuff is expired" << std::endl;
        try {
            cert.verify(ctx);
            std::cerr << "Exception should be thrown. Something's wrong." << std::endl;
            exit(EXIT_FAILURE);
        } catch (const MoCOCrWException &e) {
            std::cerr << "Failed as expected. OpenSSL error: " << e.what() << std::endl;
        }
    }

    return EXIT_SUCCESS;
}
