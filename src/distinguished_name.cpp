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

#include "mococrw/distinguished_name.h"
#include "mococrw/error.h"

#include <tuple>

namespace mococrw
{
using namespace openssl;

void DistinguishedName::_addString(SSL_X509_NAME_Ptr &x509Name, const boost::optional<DistinguishedName::Attribute>& attribute) const
{
    if (!x509Name.get()) {
        throw std::runtime_error(ERROR_STRING("Received a nullptr as X509_NAME."));
    }

    if (!attribute || attribute->name.empty()) {
        return;
    }
    auto vec = std::vector<unsigned char>{attribute->name.begin(), attribute->name.end()};
    _X509_NAME_add_entry_by_NID(x509Name.get(), attribute->id, ASN1_Name_Entry_Type::ASCIIString, vec);
}

void DistinguishedName::populateX509Name(SSL_X509_NAME_Ptr &subject) const
{
    if (_customAttributeOrderFlag) {
        for (const auto& it : _attributes) {
            _addString(subject, it);
        }
    } else {
        _addString(subject, _getAttributeByNID(ASN1_NID::CommonName));
        _addString(subject, _getAttributeByNID(ASN1_NID::CountryName));
        _addString(subject, _getAttributeByNID(ASN1_NID::LocalityName));
        _addString(subject, _getAttributeByNID(ASN1_NID::StateOrProvinceName));
        _addString(subject, _getAttributeByNID(ASN1_NID::OrganizationalUnitName));
        _addString(subject, _getAttributeByNID(ASN1_NID::OrganizationName));
        _addString(subject, _getAttributeByNID(ASN1_NID::Pkcs9EmailAddress));
        _addString(subject, _getAttributeByNID(ASN1_NID::SerialNumber));
        _addString(subject, _getAttributeByNID(ASN1_NID::GivenName));
        _addString(subject, _getAttributeByNID(ASN1_NID::UserId));
    }
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
    builder.givenName(_getEntryByNIDAsString(x509, ASN1_NID::GivenName));
    builder.userId(_getEntryByNIDAsString(x509, ASN1_NID::UserId));
    return builder.build();
}

auto _createTuple(const DistinguishedName& dn)
{
    return std::make_tuple(dn.commonName(),
                    dn.countryName(),
                     dn.localityName(),
                     dn.stateOrProvinceName(),
                     dn.organizationalUnitName(),
                     dn.organizationName(),
                     dn.pkcs9EmailAddress(),
                     dn.serialNumber(),
                     dn.userId(),
                     dn.givenName());
}

bool DistinguishedName::operator==(const DistinguishedName &other) const
{
    if (_customAttributeOrderFlag && other._customAttributeOrderFlag) {
        // order matters now
        return std::equal(_attributes.begin(), _attributes.end(), other._attributes.begin(), other._attributes.end()
                          ,[](const auto& left, const auto& right){
            return left.id == right.id && left.name == right.name;
        });
    } else {
        // order independent to match old behavior
        return _createTuple(*this) == _createTuple(other);
    }
}

std::string DistinguishedName::_getAttributeByNIDAsString(const ASN1_NID id) const
{
    const auto attribute = _getAttributeByNID(id);
    if (attribute) {
        return attribute->name;
    }
    return "";
}

boost::optional<DistinguishedName::Attribute> DistinguishedName::_getAttributeByNID(const ASN1_NID id) const
{
    boost::optional<DistinguishedName::Attribute> ret;
    // returns the last occurence in case there is duplicates
    const auto it = std::find_if(_attributes.rbegin(), _attributes.rend(), [id] (const auto& attribute) { return attribute.id == id; } );
    if (it != _attributes.rend()) {
        ret = *it;
    };
    return ret;
}

}  //::mococrw
