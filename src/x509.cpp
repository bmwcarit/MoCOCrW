/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include "mococrw/x509.h"
#include "mococrw/bio.h"
#include "mococrw/error.h"
#include "mococrw/stack_utils.h"

#include "format_utils.h"

using namespace std::string_literals;

namespace mococrw
{
using namespace openssl;

X509Certificate X509Certificate::fromPEM(const std::string &pem)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(pem);
    auto cert = _PEM_read_bio_X509(bio.internal());
    return X509Certificate{std::move(cert)};
}

X509Certificate X509Certificate::fromPEMFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::TEXT};
    auto cert = _PEM_read_bio_X509(bio.internal());
    return X509Certificate{std::move(cert)};
}

X509Certificate X509Certificate::fromDER(const std::vector<uint8_t> &derData)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(derData);
    auto cert = _d2i_X509_bio(bio.internal());
    return X509Certificate{std::move(cert)};
}

X509Certificate X509Certificate::fromDERFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::BINARY};
    auto cert = _d2i_X509_bio(bio.internal());
    return X509Certificate{std::move(cert)};
}

std::string X509Certificate::toPEM() const
{
    BioObject bio{BioObject::Types::MEM};
    _PEM_write_bio_X509(bio.internal(), const_cast<X509*>(internal()));
    return bio.flushToString();
}

void X509Certificate::VerificationContext::validityCheck() const
{
    if (_enforceCrlForWholeChain && !_enforceSelfSignedRootCertificate) {
        throw MoCOCrWException("OpenSSL doesn't support CRL check for all CAs when the trusted"
                               "certificate isn't self signed");
    }

    if (_enforceCrlForWholeChain && _crls.empty()) {
        throw MoCOCrWException("CRL check for all certificates requested, but no CRLs present");
    }
}

void X509Certificate::verify(const std::vector<X509Certificate> &trustStore,
                const std::vector<X509Certificate> &intermediateCAs) const
{
    VerificationContext ctx;
    ctx.addTrustedCertificates(trustStore)
       .addIntermediateCertificates(intermediateCAs);
    verify(ctx);
}

void X509Certificate::verify(const X509Certificate::VerificationContext &ctx) const
{
    ctx.validityCheck();

    auto caStore = createManagedOpenSSLObject<SSL_X509_STORE_Ptr>();
    for (auto &cert : ctx._trustedCerts) {
        _X509_STORE_add_cert(caStore.get(), const_cast<X509*>(cert.internal()));
    }
    auto intermediateStack = utility::buildStackFromContainer<SSL_STACK_X509_Ptr>(
                ctx._intermediateCerts);

    auto verifyCtx = createManagedOpenSSLObject<SSL_X509_STORE_CTX_Ptr>();
    // we need to cast the internal ptr to non-const because openssl const correctness is
    // just broken
    _X509_STORE_CTX_init(verifyCtx.get(),
                         caStore.get(),
                         const_cast<X509*>(internal()),
                         intermediateStack.get());

    auto param = _X509_STORE_CTX_get0_param(verifyCtx.get());

    unsigned long flags = 0;

    if (!ctx._enforceSelfSignedRootCertificate) {
        flags |= X509VerificationFlags::PARTIAL_CHAIN;
    }

    // We enable CRL checking if a CRL has been specified or the user requested a full CRL check.
    if (!ctx._crls.empty() || ctx._enforceCrlForWholeChain) {
        flags |= X509VerificationFlags::CRL_CHECK;
    }

    if (ctx._enforceCrlForWholeChain) {
        flags |= X509VerificationFlags::CRL_CHECK_ALL;
    }

    _X509_VERIFY_PARAM_set_flags(param, flags);

    // This variable must be out of the if scope since it must not be destroyed
    // until after the verification.
    SSL_STACK_X509_CRL_Ptr crlStack;

    if (!ctx._crls.empty()) {

        crlStack = utility::buildStackFromContainer<SSL_STACK_X509_CRL_Ptr>(ctx._crls);

        _X509_STORE_CTX_set0_crls(verifyCtx.get(),
                                  crlStack.get());
    }

    try {
        _X509_verify_cert(verifyCtx.get());
    } catch (const OpenSSLException &error) {
        throw MoCOCrWException(error.what());
    }
}

DistinguishedName X509Certificate::getSubjectDistinguishedName() const
{
    /* OpenSSL's const-correctness is totally broken. */
    auto x509NamePtr = _X509_get_subject_name(const_cast<X509*>(internal()));
    return DistinguishedName::fromX509Name(x509NamePtr);
}

DistinguishedName X509Certificate::getIssuerDistinguishedName() const
{
    /* OpenSSL's const-correctness is totally broken. */
    auto x509NamePtr = _X509_get_issuer_name(const_cast<X509*>(internal()));
    return DistinguishedName::fromX509Name(x509NamePtr);
}

AsymmetricPublicKey X509Certificate::getPublicKey() const
{
    /* const correctness still broken in openssl */
    auto pubkey = _X509_get_pubkey(const_cast<X509*>(internal()));
    return AsymmetricPublicKey(std::move(pubkey));
}

std::chrono::system_clock::time_point X509Certificate::getNotBefore() const
{
    /* OpenSSL's const-correctness is totally broken. */
    return _X509_get_notBefore(const_cast<X509*>(internal()));
}

std::chrono::system_clock::time_point X509Certificate::getNotAfter() const
{
    /* OpenSSL's const-correctness is totally broken. */
    return _X509_get_notAfter(const_cast<X509*>(internal()));
}

Asn1Time X509Certificate::getNotBeforeAsn1() const
{
    /* OpenSSL's const-correctness is totally broken. */
    return Asn1Time{_X509_get_notBefore_ASN1(const_cast<X509*>(internal()))};
}

Asn1Time X509Certificate::getNotAfterAsn1() const
{
    /* OpenSSL's const-correctness is totally broken. */
    return Asn1Time{_X509_get_notAfter_ASN1(const_cast<X509*>(internal()))};
}

uint64_t X509Certificate::getSerialNumber() const
{
    return _X509_get_serialNumber(const_cast<X509*>(internal()));
}

std::string X509Certificate::getSerialNumberDecimal() const
{
    /* OpenSSL's const-correctness is totally broken. */
    return _X509_get_serialNumber_dec(const_cast<X509*>(internal()));
}

std::vector<uint8_t> X509Certificate::getSerialNumberBinary() const
{
    /* OpenSSL's const-correctness is totally broken. */
    return _X509_get_serialNumber_bin(const_cast<X509*>(internal()));
}


namespace util {

std::vector<X509Certificate> loadPEMChain(const std::string &pemChain)
{
    const auto beginMarker = "-----BEGIN CERTIFICATE-----"s;
    const auto endMarker = "-----END CERTIFICATE-----"s;

    auto pemList = splitPEMChain(pemChain, beginMarker, endMarker);

    std::vector<X509Certificate> certChain;
    std::transform(pemList.begin(), pemList.end(), std::back_inserter(certChain),
                   X509Certificate::fromPEM);

    return certChain;
}

}

}  // ::mococrw
