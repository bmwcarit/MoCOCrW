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
