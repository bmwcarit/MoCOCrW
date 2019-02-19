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
    /**
     * Forward declaration of nested Builder class
     *
     * Definition is below.
     *
     */
    class Builder;

    /**
     * Get the various attributes in this distinguished name.
     *
     * If an attribute has not been set, the corresponding method will return an
     * empty string.
     */
    const std::string &commonName() const { return _commonName; }
    const std::string &countryName() const { return _countryName; }
    const std::string &localityName() const { return _localityName; }
    const std::string &stateOrProvinceName() const { return _stateOrProvinceName; }
    const std::string &organizationalUnitName() const { return _organizationalUnitName; }
    const std::string &organizationName() const { return _organizationName; }
    const std::string &pkcs9EmailAddress() const { return _pkcs9EmailAddress; }
    const std::string &serialNumber() const { return _serialNumber; }
    const std::string &givenName() const { return _givenName; }
    const std::string &userId() const { return _userId; }
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
    std::string _commonName;
    std::string _countryName;
    std::string _localityName;
    std::string _stateOrProvinceName;
    std::string _organizationalUnitName;
    std::string _organizationName;
    std::string _pkcs9EmailAddress;
    std::string _serialNumber;
    std::string _givenName;
    std::string _userId;
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

private:
    DistinguishedName _dn;
};

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::commonName(T &&name)
{
    _dn._commonName = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::countryName(T &&name)
{
    _dn._countryName = std::forward<T>(name);
    if (_dn._countryName.size() > 2) {
        _dn._countryName = "";
        throw std::runtime_error("The country name must not exceed two characters");
    }
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::localityName(T &&name)
{
    _dn._localityName = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::stateOrProvinceName(T &&name)
{
    _dn._stateOrProvinceName = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::organizationalUnitName(T &&name)
{
    _dn._organizationalUnitName = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::organizationName(T &&name)
{
    _dn._organizationName = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::pkcs9EmailAddress(T &&name)
{
    _dn._pkcs9EmailAddress = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::serialNumber(T &&name)
{
    _dn._serialNumber = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::givenName(T &&name)
{
    _dn._givenName = std::forward<T>(name);
    return *this;
}

template <class T>
DistinguishedName::Builder &DistinguishedName::Builder::userId(T &&name)
{
    _dn._userId = std::forward<T>(name);
    return *this;
}

} //::mococrw
