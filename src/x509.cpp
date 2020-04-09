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

#include <fstream>
#include <boost/range/algorithm_ext/erase.hpp>
#include <boost/format.hpp>

#include "mococrw/x509.h"
#include "mococrw/bio.h"
#include "mococrw/error.h"
#include "mococrw/stack_utils.h"

#include "format_utils.h"

using namespace std::string_literals;

namespace {
/**
 * Helper function for reformatPEMCertificate:
 * Searches for the next occurence of the given marker in pem starting at start
 * @param pem String to search in
 * @param marker Marker to search
 * @param endPos Inidicates if start or end position of the marker shall be returned
 * @param start Position to start searching at
 * @return Start of next occurence of marker
 */
inline size_t findStartOfNextMarker(const std::string& pem, const std::string& marker, size_t start = 0)
{
    return pem.find(marker, start);
}

/**
 * Helper function for reformatPEMCertificate:
 * Searches for the next occurence of the given marker in pem starting at start
 * @param pem String to search in
 * @param marker Marker to search
 * @param endPos Inidicates if start or end position of the marker shall be returned
 * @param start Position to start searching at
 * @return End of next occurence of marker
 */
inline size_t findEndOfNextMarker(const std::string& pem, const std::string& marker, size_t start = 0)
{
    return findStartOfNextMarker(pem, marker, start) + marker.size();
}

/**
 * Reformats a PEM encoded certificate to contain only base64 encoded lines that consist
 * of 64 char at max. This had to be introduced to workaround a bug in OpenSSL that prevents
 * parsing of PEM certificates that contain the base64 encoded parts in only one line and
 * the length of the line is a multiple of 254.
 * Issue Ticket: https://github.com/openssl/openssl/issues/9187
 * This function only touches the base64 encoded parts between the begin- and end-marker
 * of the certificate and doesn't touch areas before the start marker or past the end marker.
 * However, please note that this function only reformats the first certificate found in pem.
 *
 * Note: to be removed as soon as the OpenSSL fix is integrated
 *
 * @param pem String containing the certificate to be reformatted
 * @returns Certificate with reformatted base64
 */
inline std::string reformatPEMCertificate(const std::string& pem) {
    // search for begin-marker
    std::string prevBase64;
    size_t endBeginMarker = findEndOfNextMarker(pem, "-----BEGIN CERTIFICATE-----");

    // In case of error let's try with the current certificate and let openssl fail
    // if necessary
    if (endBeginMarker == std::string::npos) {
        return pem;
    }

    // search for end-marker
    std::string postBase64;
    size_t startEndMarker = findStartOfNextMarker(pem, "-----END CERTIFICATE-----", endBeginMarker);

    // In case of error let's try with the current certificate and let openssl fail
    // if necessary
    if (startEndMarker == std::string::npos) {
        return pem;
    }

    // extract everything from beginning of the string until the begin-markers end
    prevBase64 = pem.substr(0, endBeginMarker);
    // extract everything from the beginning of the marker until end of the string
    postBase64 = pem.substr(startEndMarker);

    // extract base64 encoded content
    std::string base64 = pem.substr(endBeginMarker, startEndMarker - endBeginMarker - 1);
    boost::range::remove_erase_if(base64, [](char x) { return std::isspace(x); });

    // Insert newline after each 64 chars into base64 encoded content
    std::string splittedBase64;
    auto iter = base64.begin();
    for (; std::distance(iter, base64.end()) > 64; iter += 64) {
        std::copy_n(iter, 64, std::back_inserter(splittedBase64));
        splittedBase64 += "\n";
    }
    std::copy(iter, base64.end(), std::back_inserter(splittedBase64));

    // reassemble string
    return boost::str(boost::format("%1%\n%2%\n%3%") % prevBase64 % splittedBase64 % postBase64);
}

}

namespace mococrw
{
using namespace openssl;

X509Certificate X509Certificate::fromPEM(const std::string &pem)
{
    std::string formattedPem = reformatPEMCertificate(pem);
    BioObject bio{BioObject::Types::MEM};
    bio.write(formattedPem);
    auto cert = _PEM_read_bio_X509(bio.internal());
    return X509Certificate{std::move(cert)};
}

X509Certificate X509Certificate::fromPEMFile(const std::string &filename)
{
    // Change to be reverted to previous solution after OpenSSL parsing
    // bug for PEM certificates has been fixed.
    // https://github.com/openssl/openssl/issues/9187
    std::ifstream pemFile(filename);
    std::stringstream buffer;
    if (pemFile.is_open()) {
        buffer << pemFile.rdbuf();
        pemFile.close();
        if (!pemFile.fail()) {
            return fromPEM(buffer.str());
        }
    }

    // previous solutions
    // if reformatting fails, let openssl try (and fail if needed)
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

std::vector<uint8_t> X509Certificate::toDER() const
{
    BioObject bio{BioObject::Types::MEM};
    _i2d_X509_bio(bio.internal(), const_cast<X509*>(internal()));
    return bio.flushToVector();
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

X509Certificate::VerificationContext&
X509Certificate::VerificationContext::setVerificationCheckTime(Asn1Time checkTime)
{
    try {
        _verificationCheckTime = checkTime.toTimeT();
    } catch (const OpenSSLException& e) {
        throw MoCOCrWException(e.what());
    }
    return *this;
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

    if (ctx._verificationCheckTime) {
        flags |= X509VerificationFlags::USE_CHECK_TIME;
        _X509_STORE_CTX_set_time(verifyCtx.get(), ctx._verificationCheckTime.get());
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

bool X509Certificate::isCA() const
{
    return  _X509_check_ca(_x509.get());;
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
