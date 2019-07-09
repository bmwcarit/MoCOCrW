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
#pragma once

#include <string>
#include <vector>
#include <boost/optional.hpp>

#include "openssl_wrap.h"

namespace mococrw
{

/**
 * Represents a distinguished name.
 *
 * Holds all the data needed to for a ditinsguished name.
 * Instances must be created using an instance of the nested
 * Builder class:
 *
 *   auto builder = DistinguishedName::Builder();
 *   builder.commonName("some name"). .....
 *
 *
 */
class DistinguishedName
{
public:
    class Builder;
    class CustomOrderBuilder;
    /**
     * Get the various attributes in this distinguished name.
     *
     * If an attribute has not been set, the corresponding method will return an
     * empty string.
     */
    std::string commonName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::CommonName); }
    std::string countryName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::CountryName); }
    std::string localityName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::LocalityName); }
    std::string stateOrProvinceName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::StateOrProvinceName); }
    std::string organizationalUnitName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::OrganizationalUnitName); }
    std::string organizationName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::OrganizationName); }
    std::string pkcs9EmailAddress() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::Pkcs9EmailAddress); }
    std::string serialNumber() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::SerialNumber); }
    std::string givenName() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::GivenName); }
    std::string userId() const { return _getAttributeByNIDAsString(openssl::ASN1_NID::UserId); }

    /**
     * Populate an X509_NAME instance.
     *
     * Add the relevant parts of the DN to the X509_NAME
     * using the correct ASN1 node IDs (NIDs).
     *
     * If an attribute of the DN is empty (i.e. not set), this
     * method will ignore the corresponding component and not add
     * that to the NAME.
     *
     * @param subject Reference to a unique_ptr holding the X509_NAME.
     */
    void populateX509Name(openssl::SSL_X509_NAME_Ptr &subject) const;

    static DistinguishedName fromX509Name(X509_NAME *ptr);
    bool operator==(const DistinguishedName& other) const;
    bool operator!=(const DistinguishedName& other) const { return !(*this == other); }
private:    
    struct Attribute {
        openssl::ASN1_NID id;
        std::string       name;
    };
    std::string _getAttributeByNIDAsString(const openssl::ASN1_NID id) const;
    boost::optional<Attribute> _getAttributeByNID(const openssl::ASN1_NID id) const;
    void _addString(openssl::SSL_X509_NAME_Ptr &x509Name, const boost::optional<DistinguishedName::Attribute>& attribute) const;
    std::vector<Attribute> _attributes;
    bool _customAttributeOrderFlag{false};
};

class DistinguishedName::Builder
{
public:
    Builder() : _dn{} {}
    template <class T>
    Builder &commonName(T &&name);

    template <class T>
    Builder &countryName(T &&name);
    template <class T>
    Builder &localityName(T &&name);
    template <class T>
    Builder &stateOrProvinceName(T &&name);
    template <class T>
    Builder &organizationalUnitName(T &&name);
    template <class T>
    Builder &organizationName(T &&name);
    template <class T>
    Builder &pkcs9EmailAddress(T &&name);
    template <class T>
    Builder &serialNumber(T &&name);
    template <class T>
    Builder &givenName(T &&name);
    template <class T>
    Builder &userId(T &&name);

    inline DistinguishedName build() const { return _dn; }
protected:
    DistinguishedName _dn;
};

class DistinguishedName::CustomOrderBuilder: public DistinguishedName::Builder
{
public:
    CustomOrderBuilder(): Builder() { _dn._customAttributeOrderFlag = true; }
};

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::commonName(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::CommonName, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::countryName(T &&name)
{
    Attribute attribute{openssl::ASN1_NID::CountryName, std::forward<T>(name)};
    if (attribute.name.size() > 2) {
        throw std::runtime_error("The country name must not exceed two characters");
    }
    _dn._attributes.emplace_back(std::move(attribute));
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::localityName(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::LocalityName, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::stateOrProvinceName(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::StateOrProvinceName, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::organizationalUnitName(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::OrganizationalUnitName, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::organizationName(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::OrganizationName, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::pkcs9EmailAddress(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::Pkcs9EmailAddress, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::serialNumber(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::SerialNumber, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::givenName(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::GivenName, std::forward<T>(name)});
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::userId(T &&name)
{
    _dn._attributes.emplace_back(Attribute{openssl::ASN1_NID::UserId, std::forward<T>(name)});
    return *this;
}

} //::mococrw
