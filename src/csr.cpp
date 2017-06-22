/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include "mococrw/bio.h"
#include "mococrw/csr.h"
#include "mococrw/key.h"

namespace mococrw
{
using namespace openssl;


CertificateSigningRequest::CertificateSigningRequest(const DistinguishedName &dn)
        : CertificateSigningRequest{dn, AsymmetricKeypair::generate()}
{
}

CertificateSigningRequest::CertificateSigningRequest(const DistinguishedName &dn,
                                                     const AsymmetricKeypair &keypair)
        : _keypair{keypair}, _req{openssl::_X509_REQ_new()}
{
    /* setup x509 version number */
    _X509_REQ_set_version(_req.get(), 0L);

    auto subject = _X509_NAME_new();
    dn.populateX509Name(subject);
    _X509_REQ_set_subject_name(_req.get(), subject.get());

    _X509_REQ_set_pubkey(_req.get(), _keypair.internal());

    auto mctx = _EVP_MD_CTX_create();

    _EVP_DigestSignInit(mctx.get(), DigestTypes::SHA256, _keypair.internal());

    _X509_REQ_sign_ctx(_req.get(), mctx.get());
}

const AsymmetricKeypair &CertificateSigningRequest::getKeypair() const
{
    return _keypair;
}

std::string CertificateSigningRequest::toPem() const
{
    BioObject bio{BioObject::Types::MEM};
    _PEM_write_bio_X509_REQ(bio.internal(), _req.get());
    return bio.flushToString();
}

}  // ::mococrw
