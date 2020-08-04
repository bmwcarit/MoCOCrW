/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
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

#include <mococrw/hash.h>
#include <iostream>

using namespace mococrw;
void calculateHashSum(const DigestTypes digestType, const std::vector<uint8_t> &message)
{
    /* The streaming interface */
    auto hash = Hash::fromDigestType(digestType);

    /* OpenSSLException is thrown if an error in OpenSSL happens */
    hash.update(message);
    auto hashValue = hash.digest();

    std::cout << utility::toHex(hashValue) << std::endl << std::endl;
}

void oneShotSha512(const std::vector<uint8_t> &message)
{
    /* There are "one shot" functions for all supported digests */

    /* The interface for std::vectors (OpenSSLException is thrown if an error in OpenSSL happens) */
    std::cout << utility::toHex(sha512(message)) << std::endl << std ::endl;

    /* The interface for char arrays (OpenSSLException is thrown if an error in OpenSSL happens) */
    std::cout << utility::toHex(sha512(message.data(), message.size())) << std::endl << std::endl;;

    /* The interface for strings (OpenSSLException is thrown if an error in OpenSSL happens) */
    std::cout << utility::toHex(sha512("hello world")) << std::endl;
}

int main(void)
{
    const std::vector<uint8_t> message = utility::fromHex("deadbeef");
    calculateHashSum(DigestTypes::SHA512, message);
    oneShotSha512(message);
    return 0;
}
