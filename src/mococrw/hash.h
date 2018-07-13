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

#include "mococrw/openssl_wrap.h"

#include <openssl/evp.h>

namespace mococrw
{

class Hash
{
public:
    Hash();
    static Hash sha256();
    void digest (unsigned char* outValue);
    void update (const std::string &chunk);
private:
    EVP_MD_CTX digestCtx;
    const EVP_MD *digestFn;
};

}