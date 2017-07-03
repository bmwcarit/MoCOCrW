/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
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
     * @param rootCertificate the certificate of the CA.
     * @param privateKey the certificate's private key.
     * @throw MoCOCrWException if the key doesn't match the certificate.
     */
    CertificateAuthority(CertificateSigningParameters defaultParams,
                         X509Certificate rootCertificate,
                         AsymmetricKeypair privateKey);

    /**
     * Creates a new root (self-signed) certificate.
     * @param privateKey the key that should be used for signing the certificate. The public part
     *                   of the key will become the certificate's public key.
     * @param dn the distinguished name of the new certificate.
     * @param signParams the signing parameters for signing the new certificate.
     * @return a new root certificate.
     */
    static X509Certificate createRootCertificate(const AsymmetricKeypair &privateKey,
                                                 const DistinguishedName &dn,
                                                 const CertificateSigningParameters &signParams);

    /**
     * Creates a new Certificate that matches the given CSR and signs it using this CA's default
     * signing parameters.
     * @param request the CSR on which the new certificate should be based.
     * @return a new Certificate with the CSR's issuer name and public key that was signed by this
     *         CA's root certificate.
     */
    inline X509Certificate signCSR(const CertificateSigningRequest &request) const
    {
        return signCSR(request, _defaultSignParams);
    }

    /**
     * @return This CA's root certificate.
     */
    X509Certificate getRootCertificate() const;

    /**
     * @return This CA's default signing parameters.
     */
    CertificateSigningParameters getSignParams() const;

private:

    /**
     * Creates a new Certificate that matches the given CSR and signs it.
     * @param request the CSR on which the new certificate should be based.
     * @param signParams the parameters for signing the new certificate.
     * @return a new Certificate with the CSR's issuer name and public key that was signed by this
     *         CA's root certificate.
     */
    X509Certificate signCSR(const CertificateSigningRequest &request,
                            const CertificateSigningParameters &signParams) const;

    /// Signs a certificate with a private key using the given signing parameters.
    static void signCertificate(X509* certificate,
                                const AsymmetricKeypair &privateKey,
                                const CertificateSigningParameters &signParams);

    /// The default signing parameters.
    CertificateSigningParameters _defaultSignParams;

    /// The CA certificate.
    X509Certificate _rootCert;

    /// The CA certificate's corresponding private key.
    AsymmetricKeypair _privateKey;
};

} //::mococrw
