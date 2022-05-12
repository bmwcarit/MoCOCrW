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
        : _defaultSignParams{std::move(defaultParams)}
        , _nextSerialNumber{nextSerialNumber}
        , _rootCert{std::move(rootCertificate)}
        , _privateKey{std::move(privateKey)}
{
    if (_privateKey != _rootCert.getPublicKey()) {
        throw MoCOCrWException{"Tried to initialize CA but private key didn't match certificate"};
    }
}

X509Certificate CertificateAuthority::createRootCertificate(
        const AsymmetricKeypair &privateKey,
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
    _X509_set_pubkey(cert.get(), const_cast<EVP_PKEY *>(privateKey.internal()));
    _X509_set_serialNumber(cert.get(), serialNumber);

    X509_set_version(cert.get(), certificateVersion);

    _signCertificate(cert.get(), privateKey, signParams);
    return X509Certificate{std::move(cert)};
}

X509Certificate CertificateAuthority::_signCSR(const CertificateSigningRequest &csr,
                                               const CertificateSigningParameters &signParams)
{
    /* OpenSSL internally dups X509_NAMEs when assigning them to a new
     * cert. No special memory management needed.
     * We copy X509_NAMEs directly to avoid a detour via our DistinguishedName
     * object that currently isn't order-aware for distinguished names.
     */
    auto subjectName = _X509_REQ_get_subject_name(csr.internal());
    auto publicKey = csr.getPublicKey();

    auto newCertificate = createManagedOpenSSLObject<SSL_X509_Ptr>();
    _X509_set_subject_name(newCertificate.get(), subjectName);
    _X509_set_pubkey(newCertificate.get(), publicKey.internal());

    auto rootCertName = _X509_get_subject_name(_rootCert.internal());
    _X509_set_issuer_name(newCertificate.get(), rootCertName);

    _X509_set_serialNumber(newCertificate.get(), _nextSerialNumber);

    X509_set_version(newCertificate.get(), certificateVersion);

    _signCertificate(newCertificate.get(), _privateKey, signParams);

    // Sanity check: certificate must be verifiable now
    try {
        auto cert = X509Certificate{std::move(newCertificate)};
        // CA's notBefore can't be smaller than issued cert's notBefore i.e. CA can't
        // issue a certificate older than CA itself
        if (_rootCert.getNotBeforeAsn1() > cert.getNotBeforeAsn1()) {
            throw MoCOCrWException(
                    "CSR: Issued certificate can not be valid before issuing "
                    "certificate (CA's cert)");
        }
        // CA's notAfter has to be bigger than Cert's notAfter.
        if (_rootCert.getNotAfterAsn1() < cert.getNotAfterAsn1()) {
            throw MoCOCrWException(
                    "CSR: Certificate's validity period should not exceed the "
                    "validity bounds of the issuing certificate (CA's cert).");
        }
        X509Certificate::VerificationContext ctx;
        ctx.addTrustedCertificates({_rootCert})
                .addIntermediateCertificates({})
                .setVerificationCheckTime(cert.getNotBeforeAsn1());
        cert.verify(ctx);
        // OpenSSL wants context verification time strictly earlier than notAfter. See check in
        // x509_check_cert_time that fails if X509_cmp_time returns -1 (notAfter <= ctx verification
        // time)
        ctx.setVerificationCheckTime(cert.getNotAfterAsn1() - Asn1Time::Seconds(1));
        cert.verify(ctx);
        _nextSerialNumber++;
        return cert;
    } catch (const MoCOCrWException &e) {
        throw MoCOCrWException(
                std::string("Certificate creation failed: the generated certificate is invalid: ") +
                e.what());
    }
}

void CertificateAuthority::_signCertificate(X509 *cert,
                                            const AsymmetricKeypair &privateKey,
                                            const CertificateSigningParameters &signParams)
{
    auto notBefore = signParams.notBeforeAsn1();
    auto notAfter = notBefore + signParams.certificateValidity();
    _X509_set_notBefore_ASN1(cert, notBefore.internal());
    _X509_set_notAfter_ASN1(cert, notAfter.internal());

    X509V3_CTX ctx;
    _X509V3_set_ctx_nodb(&ctx);
    _X509V3_set_ctx(&ctx, nullptr, cert);

    for (auto &it : signParams.extensionMap()) {
        auto extension = it.second.get()->buildExtension(&ctx);
        _X509_add_ext(cert, extension.get());
    }

    _X509_sign(cert, const_cast<EVP_PKEY *>(privateKey.internal()), signParams.digestType());
}

X509Certificate CertificateAuthority::getRootCertificate() const { return _rootCert; }

CertificateSigningParameters CertificateAuthority::getSignParams() const
{
    return _defaultSignParams;
}

uint64_t CertificateAuthority::getNextSerialNumber() const { return _nextSerialNumber; }

}  // namespace mococrw
