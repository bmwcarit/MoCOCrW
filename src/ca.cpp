/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include "mococrw/ca.h"

#include "mococrw/openssl_wrap.h"

#include "mococrw/error.h"

#include "mococrw/basic_constraints.h"

namespace mococrw
{

using namespace openssl;

CertificateAuthority::CertificateAuthority(CertificateSigningParameters defaultParams,
                                           uint64_t nextSerialNumber,
                                           X509Certificate rootCertificate,
                                           AsymmetricKeypair privateKey)
    : _defaultSignParams{std::move(defaultParams)},
      _nextSerialNumber{nextSerialNumber},
      _rootCert{std::move(rootCertificate)},
      _privateKey{std::move(privateKey)}
{
    if (_privateKey != _rootCert.getPublicKey()) {
        throw MoCOCrWException{"Tried to initialize CA but private key didn't match certificate"};
    }
}

X509Certificate CertificateAuthority::createRootCertificate(const AsymmetricKeypair &privateKey,
                                          const DistinguishedName &dn,
                                          uint64_t serialNumber,
                                          const CertificateSigningParameters &signParams)
{
    auto basicConstraints = signParams.extension<BasicConstraintsExtension>();
    if (basicConstraints == nullptr) {
        throw MoCOCrWException("Signing parameters for a CA must include X509v3 basic extension");
    }
    if (!basicConstraints->isCA()) {
        throw MoCOCrWException("Signing parameters are not set for CA certificates");
    }
    auto cert = createManagedOpenSSLObject<SSL_X509_Ptr>();

    auto internalName = _X509_NAME_new();
    dn.populateX509Name(internalName);
    _X509_set_issuer_name(cert.get(), internalName.get());
    _X509_set_subject_name(cert.get(), internalName.get());
    _X509_set_pubkey(cert.get(), const_cast<EVP_PKEY*>(privateKey.internal()));
    _X509_set_serialNumber(cert.get(), serialNumber);

    X509_set_version(cert.get(), certificateVersion);

    signCertificate(cert.get(), privateKey, signParams);
    return X509Certificate{std::move(cert)};
}

X509Certificate CertificateAuthority::signCSR(const CertificateSigningRequest &csr,
                            const CertificateSigningParameters &signParams)
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

    _X509_set_serialNumber(newCertificate.get(), _nextSerialNumber);

    X509_set_version(newCertificate.get(), certificateVersion);

    signCertificate(newCertificate.get(), _privateKey, signParams);

    //Sanity check: certificate must be verifiable now
    try {
        auto cert = X509Certificate{std::move(newCertificate)};
        cert.verify({_rootCert}, {});
        _nextSerialNumber++;
        return cert;
    } catch (const MoCOCrWException &e) {
        throw MoCOCrWException(
                std::string("Certificate creation failed: the generated certificate is invalid: ") + e.what()
                );
    }

}

void CertificateAuthority::signCertificate(X509* cert,
                         const AsymmetricKeypair &privateKey,
                         const CertificateSigningParameters &signParams)
{
    _X509_set_notBefore(cert, signParams.notBefore());
    _X509_set_notAfter(cert, signParams.notBefore() + signParams.certificateValidity());

    X509V3_CTX ctx;
    _X509V3_set_ctx_nodb(&ctx);
    _X509V3_set_ctx(&ctx, nullptr, cert);

    for (auto &it : signParams.extensionMap()) {
        auto extension = it.second.get()->buildExtension(&ctx);
        _X509_add_ext(cert, extension.get());
    }

    _X509_sign(cert, const_cast<EVP_PKEY*>(privateKey.internal()), signParams.digestType());
}

X509Certificate CertificateAuthority::getRootCertificate() const
{
    return _rootCert;
}

CertificateSigningParameters CertificateAuthority::getSignParams() const
{
    return _defaultSignParams;
}

uint64_t CertificateAuthority::getNextSerialNumber() const
{
    return _nextSerialNumber;
}

} //::mococrw
