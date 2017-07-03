/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include "mococrw/bio.h"
#include "mococrw/csr.h"
#include "mococrw/key.h"
#include "mococrw/error.h"

namespace mococrw
{
using namespace openssl;

CertificateSigningRequest::CertificateSigningRequest(const DistinguishedName &dn,
                                                     const AsymmetricKeypair &keypair)
        : _req{openssl::_X509_REQ_new()}
{
    /* setup x509 version number */
    _X509_REQ_set_version(_req.get(), 0L);

    auto subject = _X509_NAME_new();
    dn.populateX509Name(subject);
    _X509_REQ_set_subject_name(_req.get(), subject.get());

    _X509_REQ_set_pubkey(_req.get(), const_cast<EVP_PKEY*>(keypair.internal()));

    auto mctx = _EVP_MD_CTX_create();

    _EVP_DigestSignInit(mctx.get(), DigestTypes::SHA256, const_cast<EVP_PKEY*>(keypair.internal()));

    _X509_REQ_sign_ctx(_req.get(), mctx.get());
}

AsymmetricPublicKey CertificateSigningRequest::getPublicKey() const
{
    auto pubkey = _X509_REQ_get_public_key(_req.get());
    return AsymmetricPublicKey(std::move(pubkey));
}

void CertificateSigningRequest::verify() const
{
    auto pubkey = _X509_REQ_get_public_key(_req.get());

    try {
        _X509_REQ_verify(_req.get(), pubkey.get());
    } catch (const OpenSSLException &error) {
        throw MoCOCrWException(error.what());
    }
}

std::string CertificateSigningRequest::toPem() const
{
    BioObject bio{BioObject::Types::MEM};
    _PEM_write_bio_X509_REQ(bio.internal(), _req.get());
    return bio.flushToString();
}

DistinguishedName CertificateSigningRequest::getSubjectName() const
{
    auto internalSubjectName = _X509_REQ_get_subject_name(_req.get());
    return DistinguishedName::fromX509Name(internalSubjectName);
}

CertificateSigningRequest CertificateSigningRequest::fromPEM(const std::string &pem)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(pem);
    return CertificateSigningRequest{_PEM_read_bio_X509_REQ(bio.internal())};
}

CertificateSigningRequest CertificateSigningRequest::fromPEMFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::TEXT};
    return CertificateSigningRequest{_PEM_read_bio_X509_REQ(bio.internal())};
}

CertificateSigningRequest::CertificateSigningRequest(SSL_X509_REQ_Ptr req)
    : _req{std::move(req)}
{
}

}  // ::mococrw
