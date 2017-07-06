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
/**
 * This extension contains a hash over the certificate's public key.
 */
class SubjectKeyIdentifierExtension final : public ExtensionBase
{
public:
    static constexpr openssl::X509Extension_NID NID
            = openssl::X509Extension_NID::SubjectKeyIdentifier;

    std::string getConfigurationString() const override
    {
        return "hash";
    }

    openssl::X509Extension_NID getNid() const override
    {
        return NID;
    }
};

} //::mococrw
