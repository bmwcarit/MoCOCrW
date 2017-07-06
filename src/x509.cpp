/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include "mococrw/x509.h"
#include "mococrw/bio.h"
#include "mococrw/error.h"
#include "mococrw/stack_utils.h"

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

void X509Certificate::verify(const std::vector<X509Certificate> &trustStore,
                const std::vector<X509Certificate> &intermediateCAs) const
{
    auto caStore = createManagedOpenSSLObject<SSL_X509_STORE_Ptr>();
    for (auto &cert : trustStore) {
        _X509_STORE_add_cert(caStore.get(), const_cast<X509*>(cert.internal()));
    }
    auto intermediateStack = utility::buildStackFromContainer<SSL_STACK_X509_Ptr>(intermediateCAs);

    auto verifyCtx = createManagedOpenSSLObject<SSL_X509_STORE_CTX_Ptr>();
    // we need to cast the internal ptr to non-const because openssl const correctness is
    // just broken
    _X509_STORE_CTX_init(verifyCtx.get(), caStore.get(), const_cast<X509*>(internal()),
                         intermediateStack.get());

    // set to partial chain verification, otherwise openssl does not accept CAs in the trust store
    // that are not self-signed.
    auto param = _X509_STORE_CTX_get0_param(verifyCtx.get());
    _X509_VERIFY_PARAM_set_flags(param, X509VerificationFlags::PARTIAL_CHAIN);

    try {
        _X509_verify_cert(verifyCtx.get());
    }
    catch (const OpenSSLException &error) {
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

uint64_t X509Certificate::getSerialNumber() const
{
    return _X509_get_serialNumber(const_cast<X509*>(internal()));
}


namespace util {

std::vector<X509Certificate> loadPEMChain(const std::string &pemChain)
{
    const auto beginMarker = "-----BEGIN CERTIFICATE-----"s;
    const auto endMarker = "-----END CERTIFICATE-----"s;

    std::string::size_type pos = 0;
    std::size_t index = 0;
    std::vector<X509Certificate> certChain;

    while (true) {
        auto nextBeginPos = pemChain.find(beginMarker, pos);
        if (nextBeginPos == std::string::npos) {
            return certChain;
        }
        if (nextBeginPos != pos) {
            // verify that only white spaces are in between. Otherwise the format is broken
            if (pemChain.substr(pos, nextBeginPos - pos).find_first_not_of(" \r\n\t") !=
                std::string::npos) {
                auto formatter =
                     boost::format("PEM Chain invalid. Invalid characters before certificate %d");
                formatter % index;
                throw MoCOCrWException(formatter.str());
            }
        }
        auto encodedPemBeginPos = pemChain.find_first_not_of(" \r\n\t",
                                                             nextBeginPos + beginMarker.size());

        auto nextEndPos = pemChain.find(endMarker, encodedPemBeginPos);
        if (nextEndPos == std::string::npos) {
            auto formatter = boost::format("PEM chain invalid. Certificate %d has no end marker");
            formatter % index;
            throw MoCOCrWException(formatter.str());
        }
        auto encodedPem = pemChain.substr(encodedPemBeginPos, nextEndPos - encodedPemBeginPos);
        auto lastNonWhitespace = encodedPem.find_last_not_of(" \r\n\t");
        if (lastNonWhitespace == std::string::npos) {
            auto formatter = boost::format("PEM chain invalid. Certificate %d appears to be empty");
            formatter % index;
            throw MoCOCrWException(formatter.str());
        }
        // remove trailing whitespaces from PEM content
        encodedPem.erase(lastNonWhitespace+1);
        // OpenSSL expects a newline after BEGIN CERTIFICATE and before END CERTIFICATE
        // so we make sure that there is one...
        auto certificatePem = boost::str(boost::format("%1%\n%2%\n%3%")
                                         % beginMarker
                                         % encodedPem
                                         % endMarker);

        certChain.emplace_back(X509Certificate::fromPEM(certificatePem));
        pos = nextEndPos + endMarker.size();
        index++;
    }
}


}

}  // ::mococrw
