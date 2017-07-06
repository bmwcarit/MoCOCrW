/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include "extension.h"
#include "openssl_wrap.h"

namespace mococrw
{

class BasicConstraintsExtension final : public ExtensionBase
{
public:
    static constexpr openssl::X509Extension_NID NID = openssl::X509Extension_NID::BasicConstraints;

    BasicConstraintsExtension(bool ca, int pathlength)
        : _ca{ca}, _pathlength{pathlength} {}

    BasicConstraintsExtension()
        : _ca{false}, _pathlength{0} {}


    /**
     * @return true if the signed certificate may be used for signing other certificates.
     */
    bool isCA() const
    {
        return _ca;
    }

    /**
     * @return how many intermediate certificates may be between the signed certificates and
     * any end certificate. This is only useful in combination with #isCA.
     */
    int pathlength() const
    {
        return _pathlength;
    }

    openssl::X509Extension_NID getNid() const override
    {
        return NID;
    }

    bool operator==(const BasicConstraintsExtension &other) const
    {
        return _ca == other._ca && _pathlength == other._pathlength;
    }

    bool operator!=(const BasicConstraintsExtension &other) const
    {
        return !operator ==(other);
    }

    std::string getConfigurationString() const override
    {
        if (_ca) {
            return (boost::format("critical,CA:TRUE,pathlen:%i") % _pathlength).str();
        } else {
            return "critical, CA:FALSE";
        }
    }

private:
    const bool _ca;
    const int _pathlength;
};

} //::mococrw
