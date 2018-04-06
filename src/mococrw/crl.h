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

#include "openssl_wrap.h"

#include "asn1time.h"
#include "distinguished_name.h"

namespace mococrw
{
class X509Certificate;

/**
 * This class represents a certificate revocation list (CRL).
 *
 * A CRL is a statement made by a CA that specific certificates that were issued by this CA
 * should no longer be considered valid. The CRL is signed with the private key of this CA
 * to guarantee the CRL's authenticity.
 */
class CertificateRevocationList
{
public:
    /**
     * Returns the subject name of the certificate that issued this CRL.
     */
    DistinguishedName getIssuerName() const;

    /**
     * Returns the time from when this CRL is valid as ASN1 time.
     */
    Asn1Time getLastUpdateAsn1() const;

    /**
     * Returns the time until when this CRL is valid as ASN1 time.
     */
    Asn1Time getNextUpdateAsn1() const;

    /**
     * Verifies this CRL's signature.
     * @param signer the certificate that issued this CRL (and therefore signed it).
     * @throw MoCOCrWException if the verification failed.
     */
    void verify(const X509Certificate& signer) const;

    /**
     * Creates a PEM representation of this CRL.
     */
    std::string toPEM() const;

    /**
     * Creates a CertificateRevocationList from a PEM representation.
     * @throw openssl::OpenSSLException if the PEM was invalid.
     */
    static CertificateRevocationList fromPEM(const std::string& pem);

    /**
     * Creates a CertificateRevocationList from a PEM representation in a file.
     * @throw openssl::OpenSSLException if the PEM was invalid or the file could not be read.
     */
    static CertificateRevocationList fromPEMFile(const std::string& filename);

    /**
     * Creates a CertificateRevocationList from a DER representation.
     * @throw openssl::OpenSSLException if the DER was invalid.
     */
    static CertificateRevocationList fromDER(const std::vector<uint8_t> &derData);

    /**
     * Creates a CertificateRevocationList from a DER representation in a file.
     * @throw openssl::OpenSSLException if the DER was invalid or the file could not be read.
     */
    static CertificateRevocationList fromDERFile(const std::string& filename);

    /**
     * Grants access to the internal OpenSSL object that is wrapped by this class.
     */
    X509_CRL* internal();

    /**
     * Grants access to the internal OpenSSL object that is wrapped by this class.
     */
    const X509_CRL* internal() const;

private:
    CertificateRevocationList(openssl::SSL_X509_CRL_Ptr crl) : _crl{std::move(crl)} {}

    openssl::SSL_X509_CRL_SharedPtr _crl;

};

namespace util
{

/**
 * Read a chain of multiple concatenated CRLs in PEM format.
 *
 * @param pemChain A string with PEM CRLs just concatenated. They may be
 *                 in multiple lines or in just one line.
 * @return A vector with the loaded CRLs in the order they occured in the
 *         PEM string
 * @throw MoCOCrWException if the input or one of the included CRLs is invalid
 */
std::vector<CertificateRevocationList> loadCrlPEMChain(const std::string &pemChain);

}

}
