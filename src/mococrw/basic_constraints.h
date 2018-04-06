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
