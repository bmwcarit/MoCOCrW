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
#include "mococrw/crl.h"

#include "mococrw/bio.h"
#include "mococrw/error.h"
#include "mococrw/openssl_wrap.h"
#include "mococrw/x509.h"

#include "format_utils.h"

using namespace std::string_literals;

namespace mococrw
{
using namespace openssl;

DistinguishedName CertificateRevocationList::getIssuerName() const
{
    return DistinguishedName::fromX509Name(_X509_CRL_get_issuer(internal()));
}

Asn1Time CertificateRevocationList::getLastUpdateAsn1() const
{
    return Asn1Time(_X509_CRL_get_lastUpdate(internal()));
}

Asn1Time CertificateRevocationList::getNextUpdateAsn1() const
{
    return Asn1Time(_X509_CRL_get_nextUpdate(internal()));
}

void CertificateRevocationList::verify(const X509Certificate &signer) const
{
    // First compare DNs. If the DNs don't match, the user provided the wrong certificate.
    // This is checked by OpenSSL as well, but this way we get a clearer error report.
    if (getIssuerName() != signer.getSubjectDistinguishedName()) {
        throw MoCOCrWException("CRL issuer name doesn't match the provided certificate"s);
    }

    auto publicKey = signer.getPublicKey();
    try {
        _X509_CRL_verify(const_cast<X509_CRL *>(internal()), publicKey.internal());
    } catch (const openssl::OpenSSLException &e) {
        using namespace std::string_literals;
        throw MoCOCrWException("Error while verifying CRL signature: "s + e.what());
    }
}

std::string CertificateRevocationList::toPEM() const
{
    BioObject bio{BioObject::Types::MEM};
    _PEM_write_bio_X509_CRL(bio.internal(), const_cast<X509_CRL *>(internal()));
    return bio.flushToString();
}

CertificateRevocationList CertificateRevocationList::fromDER(const std::vector<uint8_t> &derData)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(derData);
    auto cert = _d2i_X509_CRL_bio(bio.internal());
    return CertificateRevocationList{std::move(cert)};
}

CertificateRevocationList CertificateRevocationList::fromDERFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::BINARY};
    auto cert = _d2i_X509_CRL_bio(bio.internal());
    return CertificateRevocationList{std::move(cert)};
}

CertificateRevocationList CertificateRevocationList::fromPEM(const std::string &pem)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(pem);
    auto cert = _PEM_read_bio_X509_CRL(bio.internal());
    return CertificateRevocationList{std::move(cert)};
}

CertificateRevocationList CertificateRevocationList::fromPEMFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::BINARY};
    auto cert = _PEM_read_bio_X509_CRL(bio.internal());
    return CertificateRevocationList{std::move(cert)};
}

X509_CRL *CertificateRevocationList::internal() { return _crl.get(); }

const X509_CRL *CertificateRevocationList::internal() const { return _crl.get(); }

namespace util
{
std::vector<CertificateRevocationList> loadCrlPEMChain(const std::string &pemChain)
{
    const auto beginMarker = "-----BEGIN X509 CRL-----"s;
    const auto endMarker = "-----END X509 CRL-----"s;

    auto pemList = splitPEMChain(pemChain, beginMarker, endMarker);

    std::vector<CertificateRevocationList> crlChain;
    std::transform(pemList.begin(),
                   pemList.end(),
                   std::back_inserter(crlChain),
                   CertificateRevocationList::fromPEM);

    return crlChain;
}

}  // namespace util

}  // namespace mococrw
