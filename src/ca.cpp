/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include "mococrw/ca.h"

#include "mococrw/openssl_wrap.h"

#include "mococrw/error.h"

namespace mococrw
{

using namespace openssl;

CertificateAuthority::CertificateAuthority(CertificateSigningParameters defaultParams,
                                           X509Certificate rootCertificate,
                                           AsymmetricKeypair privateKey)
    : _defaultSignParams{std::move(defaultParams)}, _rootCert{std::move(rootCertificate)},
      _privateKey{std::move(privateKey)}
{
    if (_privateKey != _rootCert.getPublicKey()) {
        throw MoCOCrWException{"Tried to initialize CA but private key didn't match certificate"};
    }
}

X509Certificate CertificateAuthority::createRootCertificate(const AsymmetricKeypair &privateKey,
                                          const DistinguishedName &dn,
                                          const CertificateSigningParameters &signParams)
{
    auto cert = createManagedOpenSSLObject<SSL_X509_Ptr>();

    auto internalName = _X509_NAME_new();
    dn.populateX509Name(internalName);
    _X509_set_issuer_name(cert.get(), internalName.get());
    _X509_set_subject_name(cert.get(), internalName.get());
    _X509_set_pubkey(cert.get(), const_cast<EVP_PKEY*>(privateKey.internal()));

    signCertificate(cert.get(), privateKey, signParams);
    return X509Certificate{std::move(cert)};
}

X509Certificate CertificateAuthority::signCSR(const CertificateSigningRequest &csr,
                            const CertificateSigningParameters &signParams) const
{
    auto subjectName = _X509_NAME_new();
    csr.getSubjectName().populateX509Name(subjectName);
    auto publicKey = csr.getPublicKey();

    auto newCertificate = createManagedOpenSSLObject<SSL_X509_Ptr>();
    _X509_set_subject_name(newCertificate.get(), subjectName.get());
    _X509_set_pubkey(newCertificate.get(), publicKey.internal());

    auto rootCertName = _X509_NAME_new();
    _rootCert.getSubjectDistinguishedName().populateX509Name(rootCertName);
    _X509_set_issuer_name(newCertificate.get(), rootCertName.get());

    signCertificate(newCertificate.get(), _privateKey, signParams);
    return X509Certificate{std::move(newCertificate)};

}

void CertificateAuthority::signCertificate(X509* cert,
                         const AsymmetricKeypair &privateKey,
                         const CertificateSigningParameters &signParams)
{
    _X509_set_notBefore(cert, std::chrono::system_clock::now());
    _X509_set_notAfter(cert,
                       std::chrono::system_clock::now() + signParams.certificateValidity());
    _X509_sign(cert,
               const_cast<EVP_PKEY*>(privateKey.internal()),
               signParams.digestType());
}

X509Certificate CertificateAuthority::getRootCertificate() const
{
    return _rootCert;
}

CertificateSigningParameters CertificateAuthority::getSignParams() const
{
    return _defaultSignParams;
}
} //::mococrw
