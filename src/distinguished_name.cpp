/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <tuple>

#include "mococrw/distinguished_name.h"
#include "mococrw/error.h"

namespace mococrw
{
using namespace openssl;

void _addString(SSL_X509_NAME_Ptr &x509Name, const std::string &str, ASN1_NID nid)
{
    if (!x509Name.get()) {
        throw std::runtime_error(ERROR_STRING("Received a nullptr as X509_NAME."));
    }
    if (str.empty()) {
        return;
    }
    auto vec = std::vector<unsigned char>{str.begin(), str.end()};
    _X509_NAME_add_entry_by_NID(x509Name.get(), nid, ASN1_Name_Entry_Type::ASCIIString, vec);
}

void DistinguishedName::populateX509Name(SSL_X509_NAME_Ptr &subject) const
{
    _addString(subject, commonName(), ASN1_NID::CommonName);
    _addString(subject, countryName(), ASN1_NID::CountryName);
    _addString(subject, localityName(), ASN1_NID::LocalityName);
    _addString(subject, stateOrProvinceName(), ASN1_NID::StateOrProvinceName);
    _addString(subject, organizationalUnitName(), ASN1_NID::OrganizationalUnitName);
    _addString(subject, organizationName(), ASN1_NID::OrganizationName);
    _addString(subject, pkcs9EmailAddress(), ASN1_NID::Pkcs9EmailAddress);
    _addString(subject, serialNumber(), ASN1_NID::SerialNumber);
}

std::string _getEntryByNIDAsString(X509_NAME *x509, ASN1_NID nid)
{
    if (!x509) {
        throw std::runtime_error(ERROR_STRING("nullptr"));
    }
    auto indices = _X509_NAME_get_index_by_NID(x509, nid);
    if (indices.size() == 0) {
        return "";
    }
    /* This should never have a size other than 1. We just pick the
     * first element, and don't worry about the size here (as long
     * as it's > 0).
     */
    auto entry = _X509_NAME_get_entry(x509, indices.at(0));
    return _X509_NAME_ENTRY_get_data(entry);
}

DistinguishedName DistinguishedName::fromX509Name(X509_NAME *x509)
{
    Builder builder{};
    builder.commonName(_getEntryByNIDAsString(x509, ASN1_NID::CommonName));
    builder.countryName(_getEntryByNIDAsString(x509, ASN1_NID::CountryName));
    builder.localityName(_getEntryByNIDAsString(x509, ASN1_NID::LocalityName));
    builder.stateOrProvinceName(_getEntryByNIDAsString(x509, ASN1_NID::StateOrProvinceName));
    builder.organizationalUnitName(_getEntryByNIDAsString(x509, ASN1_NID::OrganizationalUnitName));
    builder.organizationName(_getEntryByNIDAsString(x509, ASN1_NID::OrganizationName));
    builder.pkcs9EmailAddress(_getEntryByNIDAsString(x509, ASN1_NID::Pkcs9EmailAddress));
    builder.serialNumber(_getEntryByNIDAsString(x509, ASN1_NID::SerialNumber));
    return builder.build();
}

auto _createTuple(const DistinguishedName &dn)
{
    return std::tie(dn.commonName(),
                    dn.countryName(),
                    dn.localityName(),
                    dn.stateOrProvinceName(),
                    dn.organizationalUnitName(),
                    dn.organizationName(),
                    dn.pkcs9EmailAddress(),
                    dn.serialNumber());
}

bool DistinguishedName::operator==(const DistinguishedName &other) const
{
    return _createTuple(*this) == _createTuple(other);
}

}  //::mococrw
