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
#include "mococrw/hash.h"

// @todo replace by openssl_wrap
#include <openssl/evp.h>

namespace mococrw
{
using namespace openssl;

Hash::Hash(void) {
    // @todo use get_digestbyname when further algorithms support is needed
    digestFn = EVP_sha256();

    EVP_MD_CTX_init(&digestCtx);
    EVP_DigestInit_ex(&digestCtx, digestFn, NULL);
}

Hash Hash::sha256 () {
    return Hash{};
}

void Hash::digest (unsigned char* outValue) {
    // @todo possibly take length or return it
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    EVP_DigestFinal_ex(&digestCtx, md_value, &md_len);
    EVP_MD_CTX_cleanup(&digestCtx);

    for(i = 0; i < md_len; i++) {
        outValue[i] = md_value[i];
    }
}

void Hash::update (const std::string &chunk) {
    const char *chunk_c = new char[chunk.length() + 1];
    chunk_c = chunk.c_str();
    EVP_DigestUpdate(&digestCtx, chunk_c, strlen(chunk_c));
}

}