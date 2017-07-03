/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#pragma once

#include "openssl_wrap.h"

#include "key.h"
#include "distinguished_name.h"

namespace mococrw
{

class CertificateSigningRequest
{
public:

    /**
     * Construct a new CertificateSigningRequest for the given distinguished name.
     * The given public key is integrated in the CSR whereas the given private key
     * is used to sign the CertificateSigningRequest.
     */
    explicit CertificateSigningRequest(const DistinguishedName &distinguishedName,
                                       const AsymmetricKeypair &key);

    /**
     * Return the PEM for this CSR as a string.
     */
    std::string toPem() const;

    /**
     * Convert a CSR in PEM format to a CertificateSigningRequest.
     */
    static CertificateSigningRequest fromPEM(const std::string &pem);

    /**
     * Convert a CSR in PEM format from a file to a CertificateSigningRequest.
     */
    static CertificateSigningRequest fromPEMFile(const std::string &filename);

    /**
     * Get the public key for this CertificateSigningRequest.
     */
    AsymmetricPublicKey getPublicKey() const;

    /**
     * Get the distinguished name of this CertificateSigningRequest's subject.
     */
    DistinguishedName getSubjectName() const;

    /**
     * Verify that the signature of this CertificateSigningRequest is valid.
     *
     * @throw MoCOCrWException if the verification fails.
     */
    void verify() const;

private:
    CertificateSigningRequest(openssl::SSL_X509_REQ_Ptr req);

    openssl::SSL_X509_REQ_Ptr _req;
};

}
