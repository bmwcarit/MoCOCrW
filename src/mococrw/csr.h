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
