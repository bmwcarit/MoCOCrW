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
    explicit CertificateSigningRequest(const DistinguishedName &distinguishedName);
    explicit CertificateSigningRequest(const DistinguishedName &distinguishedName,
                                       const AsymmetricKeypair &keyPair);
    std::string toPem() const;
    const AsymmetricKeypair &getKeypair() const;

private:
    AsymmetricKeypair _keypair;
    openssl::SSL_X509_REQ_Ptr _req;
};

}
