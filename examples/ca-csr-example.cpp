/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
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

#include <mococrw/x509.h>
#include <mococrw/ca.h>
#include <mococrw/key.h>
#include <mococrw/basic_constraints.h>
#include <mococrw/asn1time.h>
#include <mococrw/key_usage.h>
#include <mococrw/sign_params.h>
#include <mococrw/csr.h>

#include <iostream>

using namespace mococrw;

// Digest type to used by all examples
static const DigestTypes digestType = DigestTypes::SHA512;

/******************* Root CA *******************/
/***********************************************/


CertificateAuthority getRootCa(const X509Certificate &rootCaCert,
                               const AsymmetricKeypair &rootCaKey)
{
    /* This basic constraints extension will be part of the signed certificate
     * Set CA to true and path length to 0 (only one intermediate CA)
     * Remark: This will be the X509 content of intermediate CAs not of the root CA itself
     */
    BasicConstraintsExtension rootCertSignConstraints{true, 0};

    // "Allow" certificate and certificate revocation list signing
    const auto rootCaKeyUsage = KeyUsageExtension::Builder{}.keyCertSign().cRLSign().build();

    auto rootCaSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .digestType(digestType)
            .addExtension(rootCertSignConstraints)
            .addExtension(rootCaKeyUsage)
            .build();

    return CertificateAuthority(
                rootCaSignParams,
                // next serial number
                1,
                rootCaCert,
                rootCaKey);
}

CertificateAuthority getIntermediateCa(const X509Certificate &intermediateCaCert,
                                       const AsymmetricKeypair &intermediateCaKey)
{
    auto intermediateCaKeyUsage = KeyUsageExtension::Builder{}.digitalSignature().keyEncipherment().build();
    // Set CA = false for leaf certificates. Path length is ignored then.
    BasicConstraintsExtension intermediateCaSigningConstraints(false, 0);

    auto intermediateCaSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .notBeforeAsn1(Asn1Time::now() - std::chrono::seconds{1})
            .digestType(digestType)
            .addExtension(intermediateCaSigningConstraints)
            .addExtension(intermediateCaKeyUsage)
            .build();

    return CertificateAuthority(
                intermediateCaSignParams,
                // next serial number
                1,
                intermediateCaCert,
                intermediateCaKey);
}

X509Certificate createRootCertificate(const AsymmetricKeypair &rootEccKey)
{
    // Set the CA to true and path length to 1 (only one intermediate CA)
    // This will be the actual X509 content of the root CA certificate
    BasicConstraintsExtension rootCertConstraint{true, 1};

    // "Allow" certificate and certificate revocation list signing
    const auto rootCaKeyUsage = KeyUsageExtension::Builder{}.keyCertSign().cRLSign().build();

    auto rootCaSelfSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .digestType(digestType)
            .addExtension(rootCertConstraint)
            .addExtension(rootCaKeyUsage)
            .build();

    // These are all X509 cert details supported by mococrw
    auto rootCertDetails = DistinguishedName::Builder{}
            .commonName("ImATeapot")
            .countryName("DE")
            .organizationName("Linux AG")
            .organizationalUnitName("Linux Support")
            .pkcs9EmailAddress("support@example.com")
            .localityName("oben")
            .stateOrProvinceName("nebenan")
            .serialNumber("08E36DD501941432358AFE8256BC6EFD")
            .givenName("Hot Teapot")
            .userId("1000")
            .title("Teapots contain tea")
            .build();

    return CertificateAuthority::createRootCertificate(
                rootEccKey,
                rootCertDetails,
                // serial number
                0,
                rootCaSelfSignParams);
}

X509Certificate signCertificateWithRootCa(const X509Certificate &signingCert,
                                          const AsymmetricKeypair &signingKey,
                                          const CertificateSigningRequest &csr)
{
    auto ca = getRootCa(signingCert, signingKey);
    try {
        return ca.signCSR(csr);
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Error reading CSR in PEM format. Please validate your CSR." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Reason:
         * - sanity checks of the certificate failed */
        std::cerr << "Failed to create certificate." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

X509Certificate signCertificateWithIntermediateCa(const X509Certificate &signingCert,
                                                  const AsymmetricKeypair &signingKey,
                                                  const CertificateSigningRequest &csr)
{

    auto ca = getIntermediateCa(signingCert, signingKey);
    try {
        return ca.signCSR(csr);
    } catch (const openssl::OpenSSLException &e) {
        /* low level OpenSSL failure */
        std::cerr << "Error reading CSR in PEM format. Please validate your CSR." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (const MoCOCrWException &e) {
        /* Reason:
         * - sanity checks of the certificate failed */
        std::cerr << "Failed to create certificate." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

X509Certificate createIntermediateCaCertificate(const AsymmetricKeypair &intermediateCaKey,
                                                const AsymmetricKeypair &rootCaKey,
                                                const X509Certificate &rootCert)
{
    auto intermediateCaCertDetails = DistinguishedName::Builder{}
            .organizationalUnitName("ezcode")
            .organizationName("eazz")
            .countryName("DE")
            .commonName("Common secondary certificate")
            .build();

    auto csr = CertificateSigningRequest(intermediateCaCertDetails,
                                         intermediateCaKey,
                                         digestType);
    auto intermediateCaCert = signCertificateWithRootCa(rootCert, rootCaKey, csr);

    return intermediateCaCert;
}


CertificateSigningRequest createClientCsr(const AsymmetricKeypair &clientKey)
{
    auto clientCertDetails = DistinguishedName::Builder{}
            .organizationalUnitName("ez-code")
            .organizationName("flamingo")
            .countryName("DE")
            .commonName("Client certificate")
            .build();

    /* Create the CSR. This CSR is then send to the CA for signing (here: signClientCsr()) */
    return CertificateSigningRequest(
                clientCertDetails,
                clientKey,
                digestType
                );

}

X509Certificate signClientCsr(const CertificateSigningRequest &clientCsr,
                              const AsymmetricKeypair &signingCaKey,
                              const X509Certificate &signingCaCert)
{
    /* Sign the CSR */
    return signCertificateWithIntermediateCa(signingCaCert, signingCaKey, clientCsr);
}

int main(void)
{
    auto rootCaEccKey = AsymmetricKeypair::generateECC();
    auto rootCaCert = createRootCertificate(rootCaEccKey);
    std::cout << rootCaCert.toPEM() << std::endl << std::endl;

    auto intermediateCaEccKey = AsymmetricKeypair::generateECC();
    auto intermediateCaCert = createIntermediateCaCertificate(intermediateCaEccKey, rootCaEccKey, rootCaCert);
    std::cout << intermediateCaCert.toPEM() << std::endl << std::endl;

    auto clientKey = AsymmetricKeypair::generateECC();
    auto clientCsr = createClientCsr(clientKey);
    auto clientCert = signClientCsr(clientCsr, intermediateCaEccKey, intermediateCaCert);
    std::cout << clientCert.toPEM() << std::endl;

    return 0;
}
