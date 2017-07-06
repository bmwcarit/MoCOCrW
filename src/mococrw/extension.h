/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include "openssl_wrap.h"

namespace mococrw
{

/**
 * @brief The ExtensionBase class is an abstract class
 * which needs to be implemented by all Extensions in this file
 */
class ExtensionBase
{
public:
    virtual ~ExtensionBase() = default;

    /**
     * @return The OpenSSL string representation of this extension.
     */
    virtual std::string getConfigurationString() const = 0;

    /**
     * @return The OpenSSL internal ID for this extension.
     */
    virtual openssl::X509Extension_NID getNid() const = 0;

    /**
     * @brief Builds the extension from toString() and getNid().
     * @return the resulting extension as pointer
     */
    openssl::SSL_X509_EXTENSION_Ptr buildExtension(X509V3_CTX *context) const
    {
        return openssl::_X509V3_EXT_conf_nid(static_cast<int>(getNid()),
                                             context,
                                             getConfigurationString());
    }
};

} //::mococrw
