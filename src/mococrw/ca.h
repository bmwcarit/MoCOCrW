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
#pragma once

#include "sign_params.h"
#include "csr.h"
#include "x509.h"

namespace mococrw
{

/**
 * This class represents a Certificate Authority. A CA consists of a certificate,
 * the corresponding private key, and some default values on how to sign certificates.
 */
class CertificateAuthority
{
public:
    /**
     * Creates a new CA.
     * @param defaultParams the default parameters for signing certificates.
     * @param nextSerialNumber the serial number which this CA should its first generated
     *                         certificate.
     * @param rootCertificate the certificate of the CA.
     * @param privateKey the certificate's private key.
     * @throw MoCOCrWException if the key doesn't match the certificate.
     */
    CertificateAuthority(CertificateSigningParameters defaultParams,
                         uint64_t nextSerialNumber,
                         X509Certificate rootCertificate,
                         AsymmetricKeypair privateKey);

    /**
     * Creates a new root (self-signed) certificate.
     * @param privateKey the key that should be used for signing the certificate. The public part
     *                   of the key will become the certificate's public key.
     * @param dn the distinguished name of the new certificate.
     * @param serialNumber the serial number of the new certificate.
     * @param signParams the signing parameters for signing the new certificate.
     * @return a new root certificate.
     */
    static X509Certificate createRootCertificate(const AsymmetricKeypair &privateKey,
                                                 const DistinguishedName &dn,
                                                 uint64_t serialNumber,
                                                 const CertificateSigningParameters &signParams);

    /**
     * Creates a new Certificate that matches the given CSR and signs it using this CA's default
     * signing parameters.
     * @param request the CSR on which the new certificate should be based.
     * @return a new Certificate with the CSR's issuer name and public key that was signed by this
     *         CA's root certificate.
     */
    inline X509Certificate signCSR(const CertificateSigningRequest &request)
    {
        return _signCSR(request, _defaultSignParams);
    }

    /**
     * @return This CA's root certificate.
     */
    X509Certificate getRootCertificate() const;

    /**
     * @return This CA's default signing parameters.
     */
    CertificateSigningParameters getSignParams() const;

    /**
     * @return the serial number which this CA will assign to the next generated certificate.
     */
    uint64_t getNextSerialNumber() const;

private:

    /**
     * Creates a new Certificate that matches the given CSR and signs it.
     * @param request the CSR on which the new certificate should be based.
     * @param signParams the parameters for signing the new certificate.
     * @return a new Certificate with the CSR's issuer name and public key that was signed by this
     *         CA's root certificate.
     */
    X509Certificate _signCSR(const CertificateSigningRequest &request,
                            const CertificateSigningParameters &signParams);

    /// Signs a certificate with a private key using the given signing parameters.
    static void _signCertificate(X509* certificate,
                                const AsymmetricKeypair &privateKey,
                                const CertificateSigningParameters &signParams);

    /// The default signing parameters.
    CertificateSigningParameters _defaultSignParams;

    /// The serial number that the next generated certificate will receive.
    uint64_t _nextSerialNumber;

    /// The CA certificate.
    X509Certificate _rootCert;

    /// The CA certificate's corresponding private key.
    AsymmetricKeypair _privateKey;

    /// The version of created certificates.
    /// This is zero-based, so 2 = X509v3 certificates
    static constexpr int certificateVersion = 2;
};

} //::mococrw
